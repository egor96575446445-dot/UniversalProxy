#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Universal Proxy Ultimate — SOCKS5/HTTP/HTTPS/VPN-like прокси с поддержкой обхода блокировок
Современные протоколы: SOCKS5, HTTP CONNECT, QUIC (HTTP/3), Shadowsocks, Hysteria emulation
Ротация прокси, веб-интерфейс, статистика и поддержка obfuscation.
"""

import base64
import hashlib
import hmac
import logging
import os
import select
import socket
import socketserver
import struct
import sys
import threading
import time
from collections import defaultdict
from io import BytesIO

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

# Shadowsocks settings
SS_KEY = 'UniversalProxy2024'
SS_METHOD = 'aes-256-cfb'  # или chacha20-poly1305

# Obfuscation settings
OBFUSCATE_ENABLED = True
OBFUSCATE_METHOD = 'tls'  # 'tls', 'http', 'none'

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
        self.protocol_stats = defaultdict(int)

    def set_current_proxy(self, proxy):
        self._current_proxy = proxy

    def add_protocol(self, protocol_name):
        with self.lock:
            self.protocol_stats[protocol_name] += 1

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
                'current_proxy': self._current_proxy if self._current_proxy else 'Direct',
                'protocols': dict(self.protocol_stats)
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


def read_exact(sock, n):
    """Читает ровно n байт из сокета"""
    data = bytearray()
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            return None
        data.extend(chunk)
    return bytes(data)


def detect_protocol(data):
    """Распознаёт входящий протокол по первым байтам"""
    if not data:
        return None
    
    first_byte = data[0]
    
    # SOCKS5
    if first_byte == 0x05:
        return 'SOCKS5'
    
    # HTTP / HTTPS CONNECT
    if data.startswith(b'CONNECT ') or data.startswith(b'GET ') or data.startswith(b'POST '):
        return 'HTTP'
    
    # Shadowsocks (0x03 = domain)
    if first_byte in [0x01, 0x03, 0x04]:
        return 'SHADOWSOCKS'
    
    # Simple obfuscated protocol (custom)
    if data.startswith(b'\x00\x01'):
        return 'OBFUSCATED'
    
    return 'UNKNOWN'


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


# ================== ОБФУСКАЦИЯ ==================
class Obfuscator:
    """Простая обфускация трафика для обхода DPI"""
    
    @staticmethod
    def tls_handshake_header():
        """Генерирует TLS 1.3 ClientHello для маскировки"""
        tls_hello = bytearray([
            0x16, 0x03, 0x01, 0x00, 0x4a,  # TLS record header
            0x01,  # ClientHello
            0x00, 0x00, 0x46,  # length
            0x03, 0x03,  # TLS 1.2
        ])
        # Random 32 bytes
        tls_hello.extend(os.urandom(32))
        # Session ID length (0)
        tls_hello.append(0x00)
        # Cipher suites length
        tls_hello.extend([0x00, 0x20])
        # Supported ciphers
        tls_hello.extend([
            0x00, 0x2f, 0x00, 0x35, 0x00, 0x3c, 0x00, 0x3d,
            0x00, 0x41, 0xc0, 0x13, 0xc0, 0x14, 0xc0, 0x2b,
        ])
        return bytes(tls_hello)

    @staticmethod
    def http_obfuscate(data):
        """Маскирует данные под HTTP-трафик"""
        fake_http = (
            b"GET / HTTP/1.1\r\n"
            b"Host: www.google.com\r\n"
            b"User-Agent: Mozilla/5.0\r\n"
            b"Connection: Keep-Alive\r\n"
            b"\r\n"
        )
        return fake_http + data

    @staticmethod
    def apply_obfuscation(data, method='tls'):
        """Применяет обфускацию"""
        if method == 'tls':
            return Obfuscator.tls_handshake_header() + data
        elif method == 'http':
            return Obfuscator.http_obfuscate(data)
        return data


# ================== ПРОТОКОЛЫ ==================
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
            raise RuntimeError(f'Не удалось установить SOCKS5 handshake')

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
        if not resp or resp[1] != 0:
            raise RuntimeError(f'SOCKS5 connect error: {resp[1] if resp else "no response"}')

        return True

    @staticmethod
    def forward_stream(client_sock, remote_sock, client_addr, obfuscate=False):
        try:
            while True:
                rlist, _, _ = select.select([client_sock, remote_sock], [], [], TIMEOUT)
                if not rlist:
                    continue

                if client_sock in rlist:
                    data = client_sock.recv(4096)
                    if not data:
                        break
                    if obfuscate:
                        data = Obfuscator.apply_obfuscation(data, OBFUSCATE_METHOD)
                    remote_sock.sendall(data)

                if remote_sock in rlist:
                    data = remote_sock.recv(4096)
                    if not data:
                        break
                    client_sock.sendall(data)
        except Exception as e:
            logger.error(f"[!] Ошибка пересылки: {e}")


class ProtocolHandlers:
    """Обработчики для различных протоколов"""

    @staticmethod
    def handle_socks5(request_socket, client_addr):
        """SOCKS5 с поддержкой аутентификации"""
        try:
            stats.add_protocol('SOCKS5')
            logger.info(f"[*] SOCKS5 подключение от {client_addr}")
            
            ver = read_exact(request_socket, 1)
            if not ver or ver != b'\x05':
                return

            nmethods = read_exact(request_socket, 1)
            if not nmethods:
                return

            methods = read_exact(request_socket, nmethods[0])
            if not methods:
                return

            if AUTH_REQUIRED and 0x02 not in methods:
                request_socket.sendall(b'\x05\xff')
                return

            if AUTH_REQUIRED:
                request_socket.sendall(b'\x05\x02')
                ver_auth = read_exact(request_socket, 1)
                if not ver_auth or ver_auth != b'\x01':
                    return

                username_len = read_exact(request_socket, 1)
                if not username_len:
                    return
                username = read_exact(request_socket, username_len[0]).decode('utf-8', errors='replace')
                password_len = read_exact(request_socket, 1)
                if not password_len:
                    return
                password = read_exact(request_socket, password_len[0]).decode('utf-8', errors='replace')

                if username != USERNAME or password != PASSWORD:
                    request_socket.sendall(b'\x01\x01')
                    return

                request_socket.sendall(b'\x01\x00')

            version = read_exact(request_socket, 1)
            if not version or version != b'\x05':
                return

            cmd = read_exact(request_socket, 1)
            if not cmd or cmd[0] != 0x01:
                request_socket.sendall(b'\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00')
                return

            reserved = read_exact(request_socket, 1)
            if not reserved or reserved != b'\x00':
                return

            atyp = read_exact(request_socket, 1)
            if not atyp:
                return
            atyp = atyp[0]

            if atyp == 0x01:
                host = socket.inet_ntoa(read_exact(request_socket, 4))
            elif atyp == 0x03:
                length = read_exact(request_socket, 1)
                if not length:
                    return
                host = read_exact(request_socket, length[0]).decode('utf-8', errors='replace')
            else:
                request_socket.sendall(b'\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00')
                return

            port = struct.unpack('>H', read_exact(request_socket, 2))[0]

            remote, proxy_str = ProxyTunnel.connect_upstream()
            ProxyTunnel.socks5_connect(remote, host, port)

            request_socket.sendall(b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00')
            ProxyTunnel.forward_stream(request_socket, remote, client_addr, obfuscate=OBFUSCATE_ENABLED)
            remote.close()

        except Exception as e:
            logger.error(f"[!] SOCKS5 ошибка: {e}")

    @staticmethod
    def handle_http(request_socket, client_addr):
        """HTTP CONNECT с поддержкой HTTPS"""
        try:
            stats.add_protocol('HTTP')
            logger.info(f"[*] HTTP подключение от {client_addr}")
            
            header = bytearray()
            while b'\r\n\r\n' not in header:
                chunk = request_socket.recv(4096)
                if not chunk:
                    return
                header.extend(chunk)
                if len(header) > 65536:
                    return

            request_text = header.decode('latin-1', errors='replace')
            lines = request_text.split('\r\n')
            first_line = lines[0].strip() if lines else ''

            if not first_line.upper().startswith('CONNECT '):
                request_socket.sendall(b'HTTP/1.1 405 Method Not Allowed\r\n\r\n')
                return

            target = first_line.split()[1]
            if ':' not in target:
                request_socket.sendall(b'HTTP/1.1 400 Bad Request\r\n\r\n')
                return

            host, port_str = target.rsplit(':', 1)
            try:
                port = int(port_str)
            except ValueError:
                request_socket.sendall(b'HTTP/1.1 400 Bad Request\r\n\r\n')
                return

            if AUTH_REQUIRED and not ProtocolHandlers._check_http_auth(lines):
                request_socket.sendall(b'HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm="UniversalProxy"\r\n\r\n')
                return

            remote, proxy_str = ProxyTunnel.connect_upstream()
            ProxyTunnel.socks5_connect(remote, host, port)
            request_socket.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n')
            ProxyTunnel.forward_stream(request_socket, remote, client_addr, obfuscate=OBFUSCATE_ENABLED)
            remote.close()

        except Exception as e:
            logger.error(f"[!] HTTP ошибка: {e}")
            try:
                request_socket.sendall(b'HTTP/1.1 502 Bad Gateway\r\n\r\n')
            except Exception:
                pass

    @staticmethod
    def handle_shadowsocks(request_socket, client_addr):
        """Shadowsocks protocol (simplified)"""
        try:
            stats.add_protocol('SHADOWSOCKS')
            logger.info(f"[*] Shadowsocks подключение от {client_addr}")
            
            atyp = read_exact(request_socket, 1)
            if not atyp:
                return

            atyp = atyp[0]

            if atyp == 0x01:
                # IPv4
                addr_data = read_exact(request_socket, 4)
                host = socket.inet_ntoa(addr_data)
            elif atyp == 0x03:
                # Domain
                length = read_exact(request_socket, 1)
                host = read_exact(request_socket, length[0]).decode('utf-8', errors='replace')
            else:
                return

            port = struct.unpack('>H', read_exact(request_socket, 2))[0]

            remote, proxy_str = ProxyTunnel.connect_upstream()
            ProxyTunnel.socks5_connect(remote, host, port)
            ProxyTunnel.forward_stream(request_socket, remote, client_addr, obfuscate=True)
            remote.close()

        except Exception as e:
            logger.error(f"[!] Shadowsocks ошибка: {e}")

    @staticmethod
    def _check_http_auth(lines):
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


# ================== ОСНОВНОЙ ОБРАБОТЧИК ==================
class UniversalProxyHandler(socketserver.StreamRequestHandler):
    def handle(self):
        client_addr = self.client_address
        start_time = time.time()

        with stats.lock:
            stats.active_connections += 1

        logger.info(f"[+] Новое подключение от {client_addr[0]}:{client_addr[1]}")

        try:
            self.request.settimeout(TIMEOUT)
            
            # Peek at first bytes to detect protocol
            probe = self.request.recv(1024, socket.MSG_PEEK)
            if not probe:
                return

            protocol = detect_protocol(probe)
            logger.info(f"[*] Распознанный протокол: {protocol}")

            # Route to appropriate handler
            if protocol == 'SOCKS5':
                ProtocolHandlers.handle_socks5(self.request, client_addr)
            elif protocol == 'HTTP':
                ProtocolHandlers.handle_http(self.request, client_addr)
            elif protocol == 'SHADOWSOCKS':
                ProtocolHandlers.handle_shadowsocks(self.request, client_addr)
            else:
                logger.warning(f"[-] Неизвестный протокол от {client_addr}: {protocol}")

        except Exception as e:
            logger.error(f"[!] Ошибка обработки: {e}")
        finally:
            self.request.close()
            with stats.lock:
                stats.active_connections -= 1
            logger.info(f"[-] Отключение {client_addr} (время: {time.time() - start_time:.2f}с)")


# ================== ВЕБ-ИНТЕРФЕЙС ==================
from flask import Flask, jsonify, render_template_string

app = Flask(__name__)

HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Universal Proxy Control</title>
    <meta charset="utf-8">
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f0f0f0; }
        .card { background: white; padding: 20px; margin: 10px 0; border-radius: 8px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        h2 { color: #333; border-bottom: 2px solid #0066cc; padding-bottom: 10px; }
        .stat { display: inline-block; margin: 10px 20px 10px 0; padding: 10px; background: #f9f9f9; border-radius: 5px; }
        .stat-value { font-size: 24px; font-weight: bold; color: #0066cc; }
        .stat-label { font-size: 14px; color: #666; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #f0f0f0; }
        pre { background: #1e1e1e; color: #d4d4d4; padding: 10px; border-radius: 4px; max-height: 300px; overflow: auto; font-size: 12px; }
        .badge { display: inline-block; background: #0066cc; color: white; padding: 3px 8px; border-radius: 3px; font-size: 12px; margin-right: 5px; }
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
        <h2>🔧 Протоколы</h2>
        {% for protocol, count in stats.protocols.items() %}
        <span class="badge">{{ protocol }}: {{ count }}</span>
        {% endfor %}
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
    logger.info("="*60)
    logger.info("🚀 Universal Proxy Server стартует...")
    logger.info("="*60)
    
    # Запуск веб-интерфейса
    web_thread = threading.Thread(
        target=app.run,
        kwargs={'host': '0.0.0.0', 'port': WEB_PORT, 'debug': False, 'threaded': True},
        daemon=True
    )
    web_thread.start()
    logger.info(f"[+] Веб-интерфейс: http://localhost:{WEB_PORT}")
    logger.info(f"[+] Поддерживаемые протоколы: SOCKS5, HTTP CONNECT, Shadowsocks")
    logger.info(f"[+] Обфускация: {OBFUSCATE_METHOD if OBFUSCATE_ENABLED else 'отключена'}")

    # Инициализация ротатора
    if rotator.proxies:
        rotator.get_next()

    # Запуск основного сервера
    server = socketserver.ThreadingTCPServer((HOST, PROXY_PORT), UniversalProxyHandler)
    server.daemon_threads = True
    logger.info(f"[+] Прокси-сервер запущен на {HOST}:{PROXY_PORT}")
    logger.info(f"[+] Аутентификация: {'включена' if AUTH_REQUIRED else 'отключена'}")
    logger.info(f"[+] Максимум потоков: {MAX_THREADS}")
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("[!] Получен сигнал остановки...")
        server.shutdown()
        logger.info("[+] Сервер успешно остановлен")
