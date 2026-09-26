#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Universal Proxy Ultimate — SOCKS5/HTTP прокси с ротацией, веб-интерфейсом и статистикой.
Улучшенная версия: добавлена проверка аутентификации, поддержка HTTP CONNECT,
безопасные проверки входных данных и более чистая обработка ошибок.
"""

import base64
import logging
import select
import socket
import socketserver
import struct
import sys
import threading
import time
from collections import defaultdict

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


# ================== ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ==================
def parse_proxy_entry(line):
    if not line or not line.strip():
        return None

    parts = line.strip().split()
    if len(parts) < 2:
        return None

    ip = parts[0].strip()
    port_str = parts[1].strip()

    try:
        port = int(port_str)
    except ValueError:
        return None

    if not ip or ip in {'0.0.0.0', '127.0.0.7'}:
        return None

    if port <= 0 or port > 65535:
        return None

    return f"{ip}:{port}"


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
                proxy = parse_proxy_entry(line)
                if proxy:
                    new_proxies.append(proxy)

            with self.lock:
                self.proxies = new_proxies
                self.current_index = -1 if new_proxies else -1

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
            logger.info(f"[*] Ротация: выбран прокси {proxy} (#{self.current_index + 1}/{len(self.proxies)})")
            stats.set_current_proxy(proxy)
            return proxy

    def start_rotation(self):
        def rotate():
            while True:
                time.sleep(ROTATION_INTERVAL)
                self.load_proxies()
                if self.proxies:
                    self.get_next()

        thread = threading.Thread(target=rotate, daemon=True)
        thread.start()
        logger.info(f"[*] Ротация запущена: каждые {ROTATION_INTERVAL} секунд")


rotator = ProxyRotator(PROXY_LIST_FILE)


# ================== ОБРАБОТЧИКИ ПРОТОКОЛОВ ==================
def read_exact(sock, n):
    data = bytearray()
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            return None
        data.extend(chunk)
    return bytes(data)


class ProxyTunnel:
    @staticmethod
    def connect_upstream():
        proxy_str = rotator.get_next()
        if not proxy_str:
            raise RuntimeError('Нет доступных прокси в prox.txt')

        proxy_ip, proxy_port = proxy_str.split(':', 1)
        proxy_port = int(proxy_port)

        remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        remote.settimeout(TIMEOUT)
        remote.connect((proxy_ip, proxy_port))

        logger.info(f"[*] Подключение к upstream {proxy_ip}:{proxy_port}")

        remote.sendall(b'\x05\x01\x00')
        greeting = read_exact(remote, 2)
        if not greeting or greeting != b'\x05\x00':
            raise RuntimeError(f'Не удалось установить SOCKS5 handshake с upstream {proxy_str}')

        return remote, proxy_str

    @staticmethod
    def socks5_connect(remote, host, port):
        if isinstance(host, str):
            host_bytes = host.encode('utf-8')
            req = b'\x05\x01\x00\x03' + bytes([len(host_bytes)]) + host_bytes + struct.pack('>H', port)
        else:
            req = b'\x05\x01\x00\x01' + socket.inet_aton(host) + struct.pack('>H', port)

        remote.sendall(req)
        resp = read_exact(remote, 10)
        if not resp:
            raise RuntimeError('Нет ответа от upstream SOCKS5-сервера')

        if resp[1] != 0:
            raise RuntimeError(f'Upstream SOCKS5 вернул код ошибки: {resp[1]}')

        return True

    @staticmethod
    def forward_stream(client_sock, remote_sock, client_addr):
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


class Socks5Handler(socketserver.StreamRequestHandler):
    def handle(self):
        client_addr = self.client_address
        start_time = time.time()

        with stats.lock:
            stats.active_connections += 1

        logger.info(f"[+] Подключение от {client_addr[0]}:{client_addr[1]}")

        try:
            self.request.settimeout(TIMEOUT)
            probe = self.request.recv(1, socket.MSG_PEEK)

            if not probe:
                return

            if probe == b'\x05':
                self._handle_socks5(client_addr)
            else:
                self._handle_http(client_addr)

        except Exception as e:
            logger.error(f"[!] Ошибка: {e}")
        finally:
            self.request.close()
            with stats.lock:
                stats.active_connections -= 1
            logger.info(f"[-] Отключение {client_addr} (время: {time.time() - start_time:.2f}с)")

    def _handle_http(self, client_addr):
        request = self._read_http_request()
        if not request:
            return

        header_lines = request.split('\r\n')
        first_line = header_lines[0].strip() if header_lines else ''

        if first_line.upper().startswith('CONNECT '):
            target = first_line.split()[1]
            if ':' not in target:
                self.request.sendall(b'HTTP/1.1 400 Bad Request\r\n\r\n')
                return

            host, port_str = target.rsplit(':', 1)
            try:
                port = int(port_str)
            except ValueError:
                self.request.sendall(b'HTTP/1.1 400 Bad Request\r\n\r\n')
                return

            if AUTH_REQUIRED and not self._check_http_auth(header_lines):
                self.request.sendall(b'HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm="UniversalProxy"\r\n\r\n')
                return

            try:
                remote, proxy_str = ProxyTunnel.connect_upstream()
                ProxyTunnel.socks5_connect(remote, host, port)
                self.request.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n')
                ProxyTunnel.forward_stream(self.request, remote, client_addr)
            except Exception as e:
                logger.error(f"[!] HTTP CONNECT ошибка: {e}")
                self.request.sendall(b'HTTP/1.1 502 Bad Gateway\r\n\r\n')
            finally:
                try:
                    remote.close()
                except Exception:
                    pass
            return

        self.request.sendall(b'HTTP/1.1 405 Method Not Allowed\r\n\r\n')

    def _read_http_request(self):
        header = bytearray()
        while b'\r\n\r\n' not in header:
            chunk = self.request.recv(4096)
            if not chunk:
                return None
            header.extend(chunk)
            if len(header) > 65536:
                return None
        return header.decode('latin-1', errors='replace')

    def _check_http_auth(self, lines):
        for line in lines:
            if line.lower().startswith('proxy-authorization:'):
                auth_value = line.split(':', 1)[1].strip()
                if not auth_value:
                    return False
                try:
                    decoded = base64.b64decode(auth_value.split()[-1]).decode('utf-8')
                    username, password = decoded.split(':', 1)
                    return username == USERNAME and password == PASSWORD
                except Exception:
                    return False
        return False

    def _handle_socks5(self, client_addr):
        try:
            ver = read_exact(self.request, 1)
            if not ver or ver != b'\x05':
                return

            nmethods = read_exact(self.request, 1)
            if not nmethods:
                return

            methods = read_exact(self.request, nmethods[0])
            if not methods:
                return

            if AUTH_REQUIRED and 0x02 not in methods:
                self.request.sendall(b'\x05\xff')
                return

            if AUTH_REQUIRED:
                self.request.sendall(b'\x05\x02')
                ver_auth = read_exact(self.request, 1)
                if not ver_auth or ver_auth != b'\x01':
                    return

                username_len = read_exact(self.request, 1)
                if not username_len:
                    return
                username = read_exact(self.request, username_len[0]).decode('utf-8', errors='replace')
                password_len = read_exact(self.request, 1)
                if not password_len:
                    return
                password = read_exact(self.request, password_len[0]).decode('utf-8', errors='replace')

                if username != USERNAME or password != PASSWORD:
                    self.request.sendall(b'\x01\x01')
                    return

                self.request.sendall(b'\x01\x00')

            version = read_exact(self.request, 1)
            if not version or version != b'\x05':
                return

            cmd = read_exact(self.request, 1)
            if not cmd:
                return
            if cmd[0] != 0x01:
                self.request.sendall(b'\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00')
                return

            reserved = read_exact(self.request, 1)
            if not reserved or reserved != b'\x00':
                return

            atyp = read_exact(self.request, 1)
            if not atyp:
                return
            atyp = atyp[0]

            if atyp == 0x01:
                addr = socket.inet_ntoa(read_exact(self.request, 4))
                host = addr
            elif atyp == 0x03:
                length = read_exact(self.request, 1)
                if not length:
                    return
                host = read_exact(self.request, length[0]).decode('utf-8', errors='replace')
            elif atyp == 0x04:
                self.request.sendall(b'\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00')
                return
            else:
                self.request.sendall(b'\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00')
                return

            port = struct.unpack('>H', read_exact(self.request, 2))[0]

            remote, proxy_str = ProxyTunnel.connect_upstream()
            ProxyTunnel.socks5_connect(remote, host, port)

            self.request.sendall(b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00')
            ProxyTunnel.forward_stream(self.request, remote, client_addr)
        except Exception as e:
            logger.error(f"[!] SOCKS5 ошибка: {e}")
            try:
                self.request.sendall(b'\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00')
            except Exception:
                pass
        finally:
            try:
                remote.close()
            except Exception:
                pass


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
    web_thread = threading.Thread(
        target=app.run,
        kwargs={'host': '0.0.0.0', 'port': WEB_PORT, 'debug': False, 'threaded': True},
        daemon=True
    )
    web_thread.start()
    logger.info(f"[+] Веб-интерфейс: http://localhost:{WEB_PORT}")

    if rotator.proxies:
        rotator.get_next()

    server = socketserver.ThreadingTCPServer((HOST, PROXY_PORT), Socks5Handler)
    server.daemon_threads = True
    logger.info(f"[+] Прокси запущен на порту {PROXY_PORT}")
    logger.info(f"[+] Ротация: {ROTATION_INTERVAL} секунд")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("[!] Остановка...")
        server.shutdown()
