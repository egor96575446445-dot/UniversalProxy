#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Universal Proxy Server — Production-ready SOCKS5/HTTP CONNECT прокси
Надежная реализация: правильная обработка ошибок, безопасность, масштабируемость
Архитектура: модульная, тестируемая, документированная
"""

import base64
import logging
import logging.handlers
import os
import select
import socket
import socketserver
import struct
import sys
import threading
import time
from collections import defaultdict
from dataclasses import dataclass
from typing import Optional, Tuple, Dict, Any
from enum import Enum

# ================== КОНФИГУРАЦИЯ ==================
@dataclass
class ProxyConfig:
    """Конфигурация прокси-сервера"""
    proxy_port: int = 1080
    web_port: int = 5000
    bind_host: str = '0.0.0.0'
    auth_enabled: bool = True
    auth_username: str = 'proxyuser'
    auth_password: str = 'proxypass'
    max_threads: int = 100
    socket_timeout: int = 60
    log_file: str = 'proxy.log'
    log_level: int = logging.INFO
    proxy_list_file: str = 'prox.txt'
    rotation_interval: int = 600
    buffer_size: int = 4096
    max_connections: int = 1000


config = ProxyConfig()

# ================== ЛОГИРОВАНИЕ ==================
def setup_logging():
    """Инициализация логирования с ротацией"""
    logger = logging.getLogger('UniversalProxy')
    logger.setLevel(config.log_level)
    
    # Ротирующий обработчик файлов
    try:
        file_handler = logging.handlers.RotatingFileHandler(
            config.log_file,
            maxBytes=10 * 1024 * 1024,  # 10MB
            backupCount=5,
            encoding='utf-8'
        )
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        ))
        logger.addHandler(file_handler)
    except Exception as e:
        print(f"Ошибка инициализации логирования в файл: {e}")

    # Консольный вывод
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s'
    ))
    logger.addHandler(console_handler)

    return logger


logger = setup_logging()


# ================== ПЕРЕЧИСЛЕНИЯ И ТИПЫ ==================
class Protocol(Enum):
    """Поддерживаемые протоколы"""
    SOCKS5 = "SOCKS5"
    HTTP = "HTTP"
    UNKNOWN = "UNKNOWN"


class ConnectionState(Enum):
    """Состояние соединения"""
    GREETING = "greeting"
    AUTH = "auth"
    REQUEST = "request"
    TUNNEL = "tunnel"
    CLOSED = "closed"


# ================== СТАТИСТИКА ==================
class ProxyStatistics:
    """Thread-safe статистика прокси-сервера"""
    
    def __init__(self):
        self.lock = threading.RLock()
        self.start_time = time.time()
        
        # Счётчики
        self.total_requests = 0
        self.total_bytes_sent = 0
        self.total_bytes_received = 0
        self.active_connections = 0
        self.failed_connections = 0
        self.successful_connections = 0
        
        # По протоколам
        self.protocol_stats: Dict[str, int] = defaultdict(int)
        
        # По хостам
        self.hosts: Dict[str, int] = defaultdict(int)
        
        # Текущий прокси
        self._current_proxy: Optional[str] = None

    def increment_request(self, protocol: str, host: str, bytes_sent: int, bytes_received: int):
        with self.lock:
            self.total_requests += 1
            self.total_bytes_sent += bytes_sent
            self.total_bytes_received += bytes_received
            self.protocol_stats[protocol] += 1
            self.hosts[host] += 1

    def increment_active_connection(self):
        with self.lock:
            self.active_connections += 1

    def decrement_active_connection(self):
        with self.lock:
            self.active_connections = max(0, self.active_connections - 1)

    def increment_success(self):
        with self.lock:
            self.successful_connections += 1

    def increment_failure(self):
        with self.lock:
            self.failed_connections += 1

    def set_current_proxy(self, proxy: str):
        with self.lock:
            self._current_proxy = proxy

    def get_stats(self) -> Dict[str, Any]:
        with self.lock:
            uptime = int(time.time() - self.start_time)
            total_bytes = self.total_bytes_sent + self.total_bytes_received
            
            return {
                'uptime_seconds': uptime,
                'total_requests': self.total_requests,
                'total_bytes_mb': round(total_bytes / (1024 * 1024), 2),
                'active_connections': self.active_connections,
                'successful_connections': self.successful_connections,
                'failed_connections': self.failed_connections,
                'current_proxy': self._current_proxy or 'Direct',
                'protocols': dict(self.protocol_stats),
                'top_hosts': sorted(
                    self.hosts.items(),
                    key=lambda x: x[1],
                    reverse=True
                )[:10]
            }


stats = ProxyStatistics()


# ================== ПАРСИНГ ПРОКСИ ==================
class ProxyListLoader:
    """Загрузчик списка прокси с валидацией"""
    
    @staticmethod
    def parse_proxy_line(line: str) -> Optional[str]:
        """Парсит и валидирует строку прокси"""
        if not line or not line.strip():
            return None

        parts = line.strip().split()
        if len(parts) < 2:
            return None

        ip = parts[0].strip()
        port_str = parts[1].strip()

        # Валидация IP
        if not ProxyListLoader._is_valid_ip(ip):
            return None

        # Валидация порта
        try:
            port = int(port_str)
        except ValueError:
            return None

        if port <= 0 or port > 65535:
            return None

        # Исключение локальных адресов
        if ip in {'0.0.0.0', '127.0.0.1', '127.0.0.7', 'localhost'}:
            return None

        return f"{ip}:{port}"

    @staticmethod
    def _is_valid_ip(ip: str) -> bool:
        """Проверяет валидность IP адреса"""
        try:
            socket.inet_aton(ip)
            return True
        except socket.error:
            return False

    @staticmethod
    def load_proxies(filename: str) -> list:
        """Загружает прокси из файла"""
        proxies = []
        
        if not os.path.exists(filename):
            logger.warning(f"Файл прокси не найден: {filename}")
            return proxies

        try:
            with open(filename, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    proxy = ProxyListLoader.parse_proxy_line(line)
                    if proxy:
                        proxies.append(proxy)
                    elif line.strip():
                        logger.debug(f"Строка {line_num} не валидна: {line.strip()}")

            logger.info(f"Загружено {len(proxies)} валидных прокси из {filename}")
        except Exception as e:
            logger.error(f"Ошибка загрузки прокси: {e}")

        return proxies


# ================== РОТАТОР ПРОКСИ ==================
class ProxyRotator:
    """Управляет ротацией список прокси с периодическим обновлением"""
    
    def __init__(self, filename: str):
        self.filename = filename
        self.proxies = []
        self.current_index = -1
        self.lock = threading.RLock()
        self.loader = ProxyListLoader()
        
        self.load_proxies()
        self.start_rotation_thread()

    def load_proxies(self):
        """Перезагружает список прокси из файла"""
        new_proxies = self.loader.load_proxies(self.filename)
        
        with self.lock:
            self.proxies = new_proxies
            self.current_index = -1
            
            if not new_proxies:
                logger.warning("Список прокси пуст!")

    def get_next(self) -> Optional[str]:
        """Возвращает следующий прокси из списка"""
        with self.lock:
            if not self.proxies:
                return None

            self.current_index = (self.current_index + 1) % len(self.proxies)
            proxy = self.proxies[self.current_index]
            
            logger.debug(
                f"Выбран прокси: {proxy} "
                f"(#{self.current_index + 1}/{len(self.proxies)})"
            )
            stats.set_current_proxy(proxy)
            
            return proxy

    def start_rotation_thread(self):
        """Запускает фоновый поток для периодического обновления"""
        def rotate_worker():
            while True:
                try:
                    time.sleep(config.rotation_interval)
                    self.load_proxies()
                except Exception as e:
                    logger.error(f"Ошибка в потоке ротации: {e}")

        thread = threading.Thread(target=rotate_worker, daemon=True)
        thread.start()
        logger.info(f"Ротация прокси запущена (интервал: {config.rotation_interval}с)")


# ================== SOCKET UTILITIES ==================
def read_exact(sock: socket.socket, n: int) -> Optional[bytes]:
    """Читает ровно n байт из сокета"""
    if n <= 0:
        return b''

    data = bytearray()
    try:
        while len(data) < n:
            chunk = sock.recv(n - len(data))
            if not chunk:
                return None
            data.extend(chunk)
        return bytes(data)
    except socket.timeout:
        logger.debug("Таймаут при чтении из сокета")
        return None
    except Exception as e:
        logger.debug(f"Ошибка при чтении из сокета: {e}")
        return None


def detect_protocol(data: bytes) -> Protocol:
    """Распознаёт протокол по первым байтам"""
    if not data:
        return Protocol.UNKNOWN

    first_byte = data[0]

    # SOCKS5
    if first_byte == 0x05:
        return Protocol.SOCKS5

    # HTTP (GET, POST, CONNECT, PUT, DELETE и т.д.)
    if data.startswith(b'CONNECT ') or \
       data.startswith(b'GET ') or \
       data.startswith(b'POST ') or \
       data.startswith(b'PUT ') or \
       data.startswith(b'DELETE ') or \
       data.startswith(b'HEAD '):
        return Protocol.HTTP

    return Protocol.UNKNOWN


# ================== UPSTREAM TUNNEL ==================
class UpstreamTunnel:
    """Управление подключением к upstream-прокси"""
    
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.socket: Optional[socket.socket] = None
        self.bytes_sent = 0
        self.bytes_received = 0

    def connect(self) -> bool:
        """Подключается к upstream-прокси с SOCKS5 greeting"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(config.socket_timeout)
            self.socket.connect((self.host, self.port))

            logger.debug(f"Подключено к upstream {self.host}:{self.port}")

            # SOCKS5 greeting
            self.socket.sendall(b'\x05\x01\x00')
            greeting = read_exact(self.socket, 2)

            if greeting != b'\x05\x00':
                logger.warning(f"Неверный SOCKS5 greeting от {self.host}:{self.port}")
                self.close()
                return False

            return True

        except socket.timeout:
            logger.warning(f"Таймаут подключения к {self.host}:{self.port}")
            self.close()
            return False
        except Exception as e:
            logger.warning(f"Ошибка подключения к {self.host}:{self.port}: {e}")
            self.close()
            return False

    def connect_to_target(self, target_host: str, target_port: int) -> bool:
        """Устанавливает соединение с целевым хостом через upstream"""
        if not self.socket:
            return False

        try:
            # Построение SOCKS5 request
            if self._is_domain(target_host):
                # Доменное имя
                host_bytes = target_host.encode('utf-8')
                request = (
                    b'\x05\x01\x00\x03' +
                    bytes([len(host_bytes)]) +
                    host_bytes +
                    struct.pack('>H', target_port)
                )
            else:
                # IPv4 адрес
                request = (
                    b'\x05\x01\x00\x01' +
                    socket.inet_aton(target_host) +
                    struct.pack('>H', target_port)
                )

            self.socket.sendall(request)

            # Читаем ответ (min 10 байт)
            response = read_exact(self.socket, 10)
            if not response or response[1] != 0x00:
                error_code = response[1] if response else None
                logger.warning(
                    f"Ошибка SOCKS5 подключения к {target_host}:{target_port} "
                    f"(код: {error_code})"
                )
                return False

            logger.debug(f"Успешно подключено к {target_host}:{target_port}")
            return True

        except Exception as e:
            logger.warning(f"Ошибка при SOCKS5 connect: {e}")
            return False

    def relay_data(self, client_socket: socket.socket) -> Tuple[int, int]:
        """Пересылает данные между клиентом и upstream"""
        bytes_sent = 0
        bytes_received = 0

        try:
            while True:
                readable, _, _ = select.select(
                    [client_socket, self.socket],
                    [],
                    [],
                    config.socket_timeout
                )

                if not readable:
                    continue

                # Клиент -> Upstream
                if client_socket in readable:
                    data = client_socket.recv(config.buffer_size)
                    if not data:
                        break
                    self.socket.sendall(data)
                    bytes_sent += len(data)

                # Upstream -> Клиент
                if self.socket in readable:
                    data = self.socket.recv(config.buffer_size)
                    if not data:
                        break
                    client_socket.sendall(data)
                    bytes_received += len(data)

        except socket.timeout:
            logger.debug("Таймаут при пересылке данных")
        except Exception as e:
            logger.debug(f"Ошибка пересылки: {e}")

        self.bytes_sent = bytes_sent
        self.bytes_received = bytes_received
        return bytes_sent, bytes_received

    def close(self):
        """Закрывает соединение с upstream"""
        if self.socket:
            try:
                self.socket.close()
            except Exception:
                pass
            self.socket = None

    @staticmethod
    def _is_domain(host: str) -> bool:
        """Проверяет, является ли строка доменом или IP"""
        try:
            socket.inet_aton(host)
            return False
        except socket.error:
            return True


# ================== ПРОТОКОЛ ОБРАБОТЧИКИ ==================
class SOCKS5Handler:
    """Обработчик SOCKS5 протокола"""
    
    @staticmethod
    def handle(client_socket: socket.socket, client_addr: Tuple[str, int]) -> bool:
        """Обрабатывает SOCKS5 соединение"""
        try:
            # Greeting
            ver = read_exact(client_socket, 1)
            if ver != b'\x05':
                logger.warning(f"Неверная версия SOCKS от {client_addr[0]}")
                return False

            nmethods = read_exact(client_socket, 1)
            if not nmethods:
                return False

            methods = read_exact(client_socket, nmethods[0])
            if not methods:
                return False

            # Выбор метода аутентификации
            if config.auth_enabled:
                if 0x02 not in methods:
                    client_socket.sendall(b'\x05\xff')
                    logger.debug(f"Нет поддерживаемых методов auth от {client_addr[0]}")
                    return False
                
                # Требуем username/password auth (0x02)
                client_socket.sendall(b'\x05\x02')

                # Аутентификация
                if not SOCKS5Handler._authenticate(client_socket, client_addr):
                    return False
            else:
                # Без аутентификации (0x00)
                client_socket.sendall(b'\x05\x00')

            # Request
            ver = read_exact(client_socket, 1)
            if ver != b'\x05':
                return False

            cmd = read_exact(client_socket, 1)
            if not cmd or cmd[0] != 0x01:  # Только CONNECT
                client_socket.sendall(b'\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00')
                return False

            reserved = read_exact(client_socket, 1)
            if reserved != b'\x00':
                return False

            # Address Type
            atyp = read_exact(client_socket, 1)
            if not atyp:
                return False

            atyp = atyp[0]

            if atyp == 0x01:
                # IPv4
                addr_data = read_exact(client_socket, 4)
                if not addr_data:
                    return False
                target_host = socket.inet_ntoa(addr_data)
            elif atyp == 0x03:
                # Domain name
                length = read_exact(client_socket, 1)
                if not length:
                    return False
                domain_data = read_exact(client_socket, length[0])
                if not domain_data:
                    return False
                target_host = domain_data.decode('utf-8', errors='ignore')
            elif atyp == 0x04:
                # IPv6 (не поддерживается)
                client_socket.sendall(b'\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00')
                return False
            else:
                client_socket.sendall(b'\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00')
                return False

            # Port
            port_data = read_exact(client_socket, 2)
            if not port_data:
                return False

            target_port = struct.unpack('>H', port_data)[0]

            # Подключение к upstream
            proxy_rotator = rotator
            upstream_addr = proxy_rotator.get_next()

            if not upstream_addr:
                logger.warning("Нет доступных upstream прокси")
                client_socket.sendall(b'\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00')
                return False

            upstream_host, upstream_port = upstream_addr.split(':', 1)
            upstream_port = int(upstream_port)

            tunnel = UpstreamTunnel(upstream_host, upstream_port)
            if not tunnel.connect():
                client_socket.sendall(b'\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00')
                return False

            if not tunnel.connect_to_target(target_host, target_port):
                client_socket.sendall(b'\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00')
                tunnel.close()
                return False

            # Успех
            client_socket.sendall(b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00')

            # Пересылка данных
            sent, received = tunnel.relay_data(client_socket)
            stats.increment_request('SOCKS5', f"{target_host}:{target_port}", sent, received)
            stats.increment_success()

            tunnel.close()
            return True

        except Exception as e:
            logger.error(f"Ошибка SOCKS5: {e}")
            return False

    @staticmethod
    def _authenticate(client_socket: socket.socket, client_addr: Tuple[str, int]) -> bool:
        """Проверяет username/password аутентификацию"""
        try:
            ver = read_exact(client_socket, 1)
            if ver != b'\x01':
                return False

            username_len = read_exact(client_socket, 1)
            if not username_len:
                return False

            username = read_exact(client_socket, username_len[0])
            if not username:
                return False

            password_len = read_exact(client_socket, 1)
            if not password_len:
                return False

            password = read_exact(client_socket, password_len[0])
            if not password:
                return False

            username_str = username.decode('utf-8', errors='ignore')
            password_str = password.decode('utf-8', errors='ignore')

            if username_str != config.auth_username or password_str != config.auth_password:
                client_socket.sendall(b'\x01\x01')
                logger.warning(f"Неверные учётные данные от {client_addr[0]}")
                return False

            client_socket.sendall(b'\x01\x00')
            return True

        except Exception as e:
            logger.debug(f"Ошибка аутентификации: {e}")
            return False


class HTTPHandler:
    """Обработчик HTTP CONNECT протокола"""
    
    @staticmethod
    def handle(client_socket: socket.socket, client_addr: Tuple[str, int]) -> bool:
        """Обрабатывает HTTP CONNECT соединение"""
        try:
            # Читаем HTTP запрос
            request_data = HTTPHandler._read_http_header(client_socket)
            if not request_data:
                return False

            request_text = request_data.decode('latin-1', errors='ignore')
            lines = request_text.split('\r\n')

            if not lines:
                return False

            first_line = lines[0].strip()
            
            if not first_line.startswith('CONNECT '):
                client_socket.sendall(b'HTTP/1.1 405 Method Not Allowed\r\n\r\n')
                return False

            # Парсинг CONNECT
            parts = first_line.split()
            if len(parts) < 2:
                client_socket.sendall(b'HTTP/1.1 400 Bad Request\r\n\r\n')
                return False

            target = parts[1]
            if ':' not in target:
                client_socket.sendall(b'HTTP/1.1 400 Bad Request\r\n\r\n')
                return False

            target_host, target_port_str = target.rsplit(':', 1)

            try:
                target_port = int(target_port_str)
            except ValueError:
                client_socket.sendall(b'HTTP/1.1 400 Bad Request\r\n\r\n')
                return False

            # Проверка аутентификации
            if config.auth_enabled:
                if not HTTPHandler._check_auth(lines):
                    client_socket.sendall(
                        b'HTTP/1.1 407 Proxy Authentication Required\r\n'
                        b'Proxy-Authenticate: Basic realm="UniversalProxy"\r\n'
                        b'\r\n'
                    )
                    logger.warning(f"Неверная auth для HTTP от {client_addr[0]}")
                    return False

            # Подключение к upstream
            proxy_rotator = rotator
            upstream_addr = proxy_rotator.get_next()

            if not upstream_addr:
                logger.warning("Нет доступных upstream прокси")
                client_socket.sendall(b'HTTP/1.1 502 Bad Gateway\r\n\r\n')
                return False

            upstream_host, upstream_port = upstream_addr.split(':', 1)
            upstream_port = int(upstream_port)

            tunnel = UpstreamTunnel(upstream_host, upstream_port)
            if not tunnel.connect():
                client_socket.sendall(b'HTTP/1.1 502 Bad Gateway\r\n\r\n')
                return False

            if not tunnel.connect_to_target(target_host, target_port):
                client_socket.sendall(b'HTTP/1.1 502 Bad Gateway\r\n\r\n')
                tunnel.close()
                return False

            # Успех
            client_socket.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n')

            # Пересылка данных
            sent, received = tunnel.relay_data(client_socket)
            stats.increment_request('HTTP', f"{target_host}:{target_port}", sent, received)
            stats.increment_success()

            tunnel.close()
            return True

        except Exception as e:
            logger.error(f"Ошибка HTTP: {e}")
            return False

    @staticmethod
    def _read_http_header(sock: socket.socket) -> Optional[bytes]:
        """Читает HTTP заголовок до \r\n\r\n"""
        header = bytearray()
        max_size = 65536

        try:
            while b'\r\n\r\n' not in header:
                chunk = sock.recv(4096)
                if not chunk:
                    return None
                header.extend(chunk)

                if len(header) > max_size:
                    return None

            return bytes(header)
        except Exception as e:
            logger.debug(f"Ошибка чтения HTTP заголовка: {e}")
            return None

    @staticmethod
    def _check_auth(headers: list) -> bool:
        """Проверяет Proxy-Authorization заголовок"""
        for header in headers:
            if header.lower().startswith('proxy-authorization:'):
                auth_value = header.split(':', 1)[1].strip()

                try:
                    auth_method, auth_data = auth_value.split(' ', 1)
                    if auth_method.lower() != 'basic':
                        return False

                    decoded = base64.b64decode(auth_data).decode('utf-8')
                    username, password = decoded.split(':', 1)

                    return (username == config.auth_username and 
                            password == config.auth_password)

                except Exception:
                    return False

        return False


# ================== ГЛАВНЫЙ ОБРАБОТЧИК КЛИЕНТОВ ==================
class ProxyClientHandler(socketserver.StreamRequestHandler):
    """Главный обработчик входящих соединений"""
    
    def handle(self):
        client_addr = self.client_address
        start_time = time.time()

        stats.increment_active_connection()
        logger.info(f"[+] Новое соединение от {client_addr[0]}:{client_addr[1]}")

        try:
            self.request.settimeout(config.socket_timeout)

            # Определение протокола
            probe = self.request.recv(1024, socket.MSG_PEEK)
            if not probe:
                return

            protocol = detect_protocol(probe)
            logger.debug(f"Распознан протокол: {protocol.value}")

            # Маршрутизация по протоколу
            success = False
            if protocol == Protocol.SOCKS5:
                success = SOCKS5Handler.handle(self.request, client_addr)
            elif protocol == Protocol.HTTP:
                success = HTTPHandler.handle(self.request, client_addr)
            else:
                logger.warning(f"Неизвестный протокол от {client_addr[0]}")

            if success:
                pass  # Успех уже залогирован
            else:
                stats.increment_failure()

        except socket.timeout:
            logger.debug(f"Таймаут соединения от {client_addr[0]}")
            stats.increment_failure()
        except Exception as e:
            logger.error(f"Ошибка обработки соединения: {e}")
            stats.increment_failure()
        finally:
            self.request.close()
            stats.decrement_active_connection()
            
            elapsed = time.time() - start_time
            logger.info(f"[-] Отключение {client_addr[0]}:{client_addr[1]} (время: {elapsed:.2f}с)")


# ================== ВЕБ-ИНТЕРФЕЙС ==================
def create_web_app(stats_obj: ProxyStatistics):
    """Создаёт Flask приложение для веб-интерфейса"""
    from flask import Flask, jsonify, render_template_string

    app = Flask(__name__)

    HTML_TEMPLATE = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Universal Proxy — Control Panel</title>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                padding: 20px;
            }
            .container { max-width: 1200px; margin: 0 auto; }
            h1 {
                color: white;
                text-align: center;
                margin-bottom: 30px;
                font-size: 2.5em;
                text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
            }
            .grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
                gap: 20px;
                margin-bottom: 20px;
            }
            .card {
                background: white;
                border-radius: 10px;
                padding: 25px;
                box-shadow: 0 10px 30px rgba(0,0,0,0.2);
                transition: transform 0.3s;
            }
            .card:hover { transform: translateY(-5px); }
            .card h2 {
                color: #333;
                margin-bottom: 20px;
                font-size: 1.3em;
                border-bottom: 2px solid #667eea;
                padding-bottom: 10px;
            }
            .stat-group {
                display: flex;
                justify-content: space-around;
                flex-wrap: wrap;
                gap: 15px;
            }
            .stat-box {
                text-align: center;
                padding: 15px;
                background: #f8f9fa;
                border-radius: 8px;
                min-width: 120px;
            }
            .stat-value {
                font-size: 2em;
                font-weight: bold;
                color: #667eea;
            }
            .stat-label {
                font-size: 0.85em;
                color: #666;
                margin-top: 5px;
            }
            .badge {
                display: inline-block;
                background: #667eea;
                color: white;
                padding: 5px 12px;
                border-radius: 20px;
                font-size: 0.85em;
                margin: 5px;
            }
            table {
                width: 100%;
                border-collapse: collapse;
                margin-top: 15px;
            }
            th, td {
                padding: 12px;
                text-align: left;
                border-bottom: 1px solid #eee;
            }
            th {
                background: #f8f9fa;
                font-weight: 600;
                color: #333;
            }
            tr:hover { background: #f9f9f9; }
            pre {
                background: #1e1e1e;
                color: #d4d4d4;
                padding: 15px;
                border-radius: 8px;
                overflow-x: auto;
                max-height: 400px;
                overflow-y: auto;
                font-size: 0.85em;
                margin-top: 15px;
            }
            .footer {
                text-align: center;
                color: white;
                margin-top: 40px;
                font-size: 0.9em;
            }
        </style>
        <script>
            setInterval(function() {
                fetch('/api/stats')
                    .then(r => r.json())
                    .then(data => {
                        document.getElementById('uptime').textContent = 
                            Math.floor(data.uptime_seconds / 60) + ' мин';
                        document.getElementById('requests').textContent = 
                            data.total_requests;
                        document.getElementById('bytes').textContent = 
                            data.total_bytes_mb + ' MB';
                        document.getElementById('active').textContent = 
                            data.active_connections;
                        document.getElementById('success').textContent = 
                            data.successful_connections;
                        document.getElementById('proxy').textContent = 
                            data.current_proxy;
                    });
            }, 5000);
        </script>
    </head>
    <body>
        <div class="container">
            <h1>🌐 Universal Proxy</h1>
            
            <div class="grid">
                <div class="card">
                    <h2>📊 Статистика</h2>
                    <div class="stat-group">
                        <div class="stat-box">
                            <div class="stat-value" id="uptime">{{ stats.uptime_seconds // 60 }} мин</div>
                            <div class="stat-label">Работает</div>
                        </div>
                        <div class="stat-box">
                            <div class="stat-value" id="requests">{{ stats.total_requests }}</div>
                            <div class="stat-label">Запросов</div>
                        </div>
                        <div class="stat-box">
                            <div class="stat-value" id="bytes">{{ stats.total_bytes_mb }} MB</div>
                            <div class="stat-label">Данных</div>
                        </div>
                        <div class="stat-box">
                            <div class="stat-value" id="active">{{ stats.active_connections }}</div>
                            <div class="stat-label">Активных</div>
                        </div>
                    </div>
                </div>

                <div class="card">
                    <h2>🔧 Протоколы</h2>
                    <div>
                        {% for proto, count in stats.protocols.items() %}
                        <span class="badge">{{ proto }}: {{ count }}</span>
                        {% endfor %}
                    </div>
                    <div style="margin-top: 15px; font-size: 0.9em; color: #666;">
                        <p>✅ SOCKS5: полная поддержка</p>
                        <p>✅ HTTP CONNECT: полная поддержка</p>
                        <p id="success">✅ Успешно: {{ stats.successful_connections }}</p>
                    </div>
                </div>

                <div class="card">
                    <h2>🔌 Текущий прокси</h2>
                    <div style="font-size: 1.3em; color: #667eea; font-weight: bold;" id="proxy">
                        {{ stats.current_proxy }}
                    </div>
                    <div style="margin-top: 15px; font-size: 0.9em; color: #666;">
                        Upstream: автоматическая ротация<br>
                        Статус: ✅ Активен
                    </div>
                </div>
            </div>

            <div class="card">
                <h2>🔥 Топ хосты</h2>
                <table>
                    <tr><th>Хост</th><th>Запросов</th></tr>
                    {% for host, count in stats.top_hosts %}
                    <tr><td>{{ host }}</td><td>{{ count }}</td></tr>
                    {% endfor %}
                </table>
            </div>

            <div class="footer">
                <p>Universal Proxy Server v2.0 — Production-ready SOCKS5/HTTP proxy</p>
                <p>🔒 Аутентификация: {% if auth_enabled %}Включена{% else %}Отключена{% endif %}</p>
            </div>
        </div>
    </body>
    </html>
    """

    @app.route('/')
    def index():
        stats_data = stats_obj.get_stats()
        return render_template_string(
            HTML_TEMPLATE,
            stats=stats_data,
            auth_enabled=config.auth_enabled
        )

    @app.route('/api/stats')
    def api_stats():
        return jsonify(stats_obj.get_stats())

    return app


# ================== ГЛАВНАЯ ТОЧКА ВХОДА ==================
def main():
    """Запуск прокси-сервера"""
    global rotator

    logger.info("=" * 70)
    logger.info("🚀 Universal Proxy Server v2.0 — Production Ready")
    logger.info("=" * 70)
    logger.info(f"Конфигурация:")
    logger.info(f"  • Прокси порт: {config.proxy_port}")
    logger.info(f"  • Веб-интерфейс: {config.web_port}")
    logger.info(f"  • Привязка: {config.bind_host}")
    logger.info(f"  • Аутентификация: {'Включена' if config.auth_enabled else 'Отключена'}")
    logger.info(f"  • Таймаут: {config.socket_timeout}s")
    logger.info(f"  • Список прокси: {config.proxy_list_file}")
    logger.info("=" * 70)

    # Инициализация ротатора
    rotator = ProxyRotator(config.proxy_list_file)

    # Запуск веб-интерфейса
    try:
        web_app = create_web_app(stats)
        web_thread = threading.Thread(
            target=lambda: web_app.run(
                host=config.bind_host,
                port=config.web_port,
                debug=False,
                threaded=True
            ),
            daemon=True
        )
        web_thread.start()
        logger.info(f"[+] Веб-интерфейс запущен: http://localhost:{config.web_port}")
    except Exception as e:
        logger.error(f"Ошибка запуска веб-интерфейса: {e}")

    # Запуск основного сервера
    try:
        server = socketserver.ThreadingTCPServer(
            (config.bind_host, config.proxy_port),
            ProxyClientHandler
        )
        server.daemon_threads = True
        
        logger.info(f"[+] Прокси-сервер запущен на {config.bind_host}:{config.proxy_port}")
        logger.info("[+] Поддерживаемые протоколы: SOCKS5, HTTP CONNECT")
        logger.info("[+] Нажми Ctrl+C для остановки")
        logger.info("=" * 70)

        server.serve_forever()

    except KeyboardInterrupt:
        logger.info("\n[!] Получен сигнал остановки...")
        logger.info("[!] Закрытие соединений...")
        try:
            server.shutdown()
        except Exception:
            pass
        logger.info("[+] Сервер успешно остановлен")
        logger.info("=" * 70)

    except Exception as e:
        logger.error(f"Критическая ошибка: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
