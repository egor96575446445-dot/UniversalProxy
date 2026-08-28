#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Universal Proxy Ultimate — SOCKS5/HTTP прокси с ротацией, веб-интерфейсом и статистикой.
Исправленная версия — ошибка current_proxy исправлена, добавлен вызов первого прокси.
"""

import socketserver
import socket
import struct
import select
import sys
import logging
import time
import threading
import base64
import json
from datetime import datetime
from collections import defaultdict
import signal
import os

# ================== НАСТРОЙКИ ==================
PROXY_PORT = 1080
WEB_PORT = 5000
HOST = '0.0.0.0'
AUTH_REQUIRED = True
USERNAME = 'proxyuser'
PASSWORD = 'proxypass'
MAX_THREADS = 100
TIMEOUT = 60
LOG_FILE = 'proxy.log'
PROXY_LIST_FILE = 'prox.txt'
ROTATION_INTERVAL = 600

# =============================================

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE, encoding='utf-8'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger('UltimateProxy')

# ================== СТАТИСТИКА ==================
class Stats:
    def __init__(self):
        self.total_requests = 0
        self.total_bytes = 0
        self.active_connections = 0
        self.hosts = defaultdict(int)
        self.start_time = time.time()
        self.lock = threading.Lock()
        self._current_proxy = None

    def set_current_proxy(self, proxy):
        self._current_proxy = proxy

    def add_request(self, host, bytes_sent):
        with self.lock:
            self.total_requests += 1
            self.total_bytes += bytes_sent
            self.hosts[host] += 1

    def get_stats(self):
        with self.lock:
            return {
                'total_requests': self.total_requests,
                'total_bytes': self.total_bytes,
                'active_connections': self.active_connections,
                'top_hosts': sorted(self.hosts.items(), key=lambda x: x[1], reverse=True)[:10],
                'uptime': int(time.time() - self.start_time),
                'current_proxy': self._current_proxy if self._current_proxy else 'Direct'
            }

stats = Stats()

# ================== РОТАТОР ПРОКСИ ==================
class ProxyRotator:
    def __init__(self, filename):
        self.filename = filename
        self.proxies = []
        self.current_index = -1
        self.lock = threading.Lock()
        self.load_proxies()
        self.start_rotation()

    def load_proxies(self):
        try:
            with open(self.filename, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            new_proxies = []
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                parts = line.split()
                if len(parts) >= 2:
                    ip = parts[0].strip()
                    port = parts[1].strip()
                    if ip not in ['0.0.0.0', '127.0.0.7']:
                        new_proxies.append(f"{ip}:{port}")
            with self.lock:
                self.proxies = new_proxies
                self.current_index = -1
            logger.info(f"[+] Загружено {len(self.proxies)} прокси из {self.filename}")
        except Exception as e:
            logger.error(f"[!] Ошибка загрузки прокси: {e}")
            self.proxies = []

    def get_next(self):
        with self.lock:
            if not self.proxies:
                return None
            self.current_index = (self.current_index + 1) % len(self.proxies)
            proxy = self.proxies[self.current_index]
            logger.info(f"[*] Ротация: выбран прокси {proxy} (#{self.current_index+1}/{len(self.proxies)})")
            stats.set_current_proxy(proxy)
            return proxy

    def start_rotation(self):
        def rotate():
            while True:
                time.sleep(ROTATION_INTERVAL)
                self.load_proxies()
                self.get_next()
        thread = threading.Thread(target=rotate, daemon=True)
        thread.start()
        logger.info(f"[*] Ротация запущена: каждые {ROTATION_INTERVAL} секунд")

rotator = ProxyRotator(PROXY_LIST_FILE)

# ================== ОБРАБОТЧИК ПРОКСИ ==================
class Socks5Handler(socketserver.StreamRequestHandler):
    def handle(self):
        client_addr = self.client_address
        start_time = time.time()

        with stats.lock:
            stats.active_connections += 1

        logger.info(f"[+] Подключение от {client_addr[0]}:{client_addr[1]}")

        try:
            self.request.settimeout(TIMEOUT)
            first_byte = self._recv_exact(1)
            if not first_byte:
                return

            if first_byte == b'\x05':
                self._handle_socks5(client_addr)
            else:
                logger.warning(f"[-] Неизвестный протокол от {client_addr}: {first_byte}")
        except Exception as e:
            logger.error(f"[!] Ошибка: {e}")
        finally:
            self.request.close()
            with stats.lock:
                stats.active_connections -= 1
            logger.info(f"[-] Отключение {client_addr} (Время: {time.time()-start_time:.2f}с)")

    def _recv_exact(self, n):
        data = b''
        while len(data) < n:
            chunk = self.request.recv(n - len(data))
            if not chunk:
                return None
            data += chunk
        return data

    def _handle_socks5(self, client_addr):
        proxy_str = rotator.get_next()
        if not proxy_str:
            logger.warning("[-] Нет доступных прокси")
            return

        proxy_ip, proxy_port = proxy_str.split(':')
        proxy_port = int(proxy_port)

        remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        remote.settimeout(TIMEOUT)
        try:
            remote.connect((proxy_ip, proxy_port))
            logger.info(f"[*] Подключение к {proxy_ip}:{proxy_port}")

            remote.send(b'\x05\x01\x00')
            remote.recv(2)

            ver = self._recv_exact(1)
            if not ver or ver != b'\x05':
                return
            cmd = self._recv_exact(1)[0]
            self._recv_exact(1)
            atyp = self._recv_exact(1)[0]

            if atyp == 1:
                addr = socket.inet_ntoa(self._recv_exact(4))
            elif atyp == 3:
                length = self._recv_exact(1)[0]
                addr = self._recv_exact(length).decode('utf-8')
            else:
                return
            port = struct.unpack('>H', self._recv_exact(2))[0]

            req = b'\x05\x01\x00'
            if isinstance(addr, str):
                req += b'\x03' + len(addr).to_bytes(1, 'big') + addr.encode()
            else:
                req += b'\x01' + socket.inet_aton(addr)
            req += struct.pack('>H', port)
            remote.send(req)

            resp = remote.recv(10)
            if resp[1] != 0:
                logger.warning(f"[-] Ошибка подключения к {addr}:{port} через {proxy_str}")
                remote.close()
                return

            self.request.send(b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00')
            self._forward_data(self.request, remote, client_addr)
        except Exception as e:
            logger.error(f"[!] Ошибка через {proxy_str}: {e}")
        finally:
            remote.close()

    def _forward_data(self, client_sock, remote_sock, client_addr):
        try:
            while True:
                rlist, _, _ = select.select([client_sock, remote_sock], [], [], TIMEOUT)
                if not rlist:
                    continue

                if client_sock in rlist:
                    data = client_sock.recv(4096)
                    if not data:
                        break
                    remote_sock.sendall(data)

                if remote_sock in rlist:
                    data = remote_sock.recv(4096)
                    if not data:
                        break
                    client_sock.sendall(data)
        except Exception as e:
            logger.error(f"[!] Ошибка пересылки: {e}")

# ================== ВЕБ-ИНТЕРФЕЙС ==================
from flask import Flask, jsonify, render_template_string

app = Flask(__name__)

HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Universal Proxy Control</title>
    <style>
        body { font-family: Arial; margin: 20px; background: #f0f0f0; }
        .card { background: white; padding: 20px; margin: 10px 0; border-radius: 8px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        h2 { color: #333; }
        .stat { display: inline-block; margin: 10px 20px 10px 0; }
        .stat-value { font-size: 24px; font-weight: bold; color: #0066cc; }
        .stat-label { font-size: 14px; color: #666; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }
        pre { background: #1e1e1e; color: #d4d4d4; padding: 10px; border-radius: 4px; max-height: 300px; overflow: auto; }
    </style>
</head>
<body>
    <h1>🌐 Universal Proxy Control</h1>
    <div class="card">
        <h2>📊 Статистика</h2>
        <div class="stat"><div class="stat-value">{{ stats.total_requests }}</div><div class="stat-label">Запросов</div></div>
        <div class="stat"><div class="stat-value">{{ (stats.total_bytes // 1024) }} KB</div><div class="stat-label">Передано</div></div>
        <div class="stat"><div class="stat-value">{{ stats.active_connections }}</div><div class="stat-label">Активных</div></div>
        <div class="stat"><div class="stat-value">{{ (stats.uptime // 60) }} мин</div><div class="stat-label">Работает</div></div>
        <div class="stat"><div class="stat-value">{{ stats.current_proxy }}</div><div class="stat-label">Текущий прокси</div></div>
    </div>
    <div class="card">
        <h2>🔥 Топ сайтов</h2>
        <table>
            <tr><th>Сайт</th><th>Запросов</th></tr>
            {% for host, count in stats.top_hosts %}
            <tr><td>{{ host }}</td><td>{{ count }}</td></tr>
            {% endfor %}
        </table>
    </div>
    <div class="card">
        <h2>📋 Логи</h2>
        <pre>
{% for line in logs %}{{ line }}
{% endfor %}</pre>
    </div>
</body>
</html>
"""

@app.route('/')
def index():
    with open(LOG_FILE, 'r', encoding='utf-8') as f:
        logs = f.readlines()[-30:]
    return render_template_string(HTML, stats=stats.get_stats(), logs=logs)

@app.route('/api/stats')
def api_stats():
    return jsonify(stats.get_stats())

@app.route('/api/rotate')
def api_rotate():
    rotator.load_proxies()
    proxy = rotator.get_next()
    return jsonify({'status': 'ok', 'proxy': proxy})

# ================== ЗАПУСК ==================
if __name__ == "__main__":
    # Запускаем веб-интерфейс в отдельном потоке
    web_thread = threading.Thread(target=app.run, kwargs={'host': '0.0.0.0', 'port': WEB_PORT, 'debug': False, 'threaded': True}, daemon=True)
    web_thread.start()
    logger.info(f"[+] Веб-интерфейс: http://localhost:{WEB_PORT}")

    # ВЫБИРАЕМ ПЕРВЫЙ ПРОКСИ ПРИ СТАРТЕ
    rotator.get_next()

    # Запускаем прокси
    server = socketserver.ThreadingTCPServer((HOST, PROXY_PORT), Socks5Handler)
    logger.info(f"[+] Прокси запущен на порту {PROXY_PORT}")
    logger.info(f"[+] Ротация: {ROTATION_INTERVAL} секунд")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("[!] Остановка...")
        server.shutdown()