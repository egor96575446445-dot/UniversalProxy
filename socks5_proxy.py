#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Универсальный прокси-сервер для Windows.
Поддерживает SOCKS5 и HTTP (CONNECT) с аутентификацией.
Оптимизирован для работы с Яндекс.Браузером, Chrome, Firefox и любыми программами,
поддерживающими HTTP/SOCKS5 прокси.

Версия: 2.0 (финальная)
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
from datetime import datetime
import signal
import os

# ================== НАСТРОЙКИ ПОЛЬЗОВАТЕЛЯ ==================
PORT = 1080                 # Порт, на котором будет слушать прокси
HOST = '0.0.0.0'            # Слушать все интерфейсы (0.0.0.0) или только локальный (127.0.0.1)
AUTH_REQUIRED = True        # Требовать логин и пароль
USERNAME = 'proxyuser'      # Логин
PASSWORD = 'proxypass'      # Пароль
MAX_THREADS = 100           # Максимальное количество одновременных подключений
TIMEOUT = 60                # Таймаут для соединений (секунды)
LOG_LEVEL = 'INFO'          # Уровень логирования: DEBUG, INFO, WARNING, ERROR
LOG_FILE = 'proxy.log'      # Файл для логов (оставьте пустым, чтобы писать только в консоль)
# =========================================================

# Настройка логирования
log_handlers = [logging.StreamHandler(sys.stdout)]
if LOG_FILE:
    log_handlers.append(logging.FileHandler(LOG_FILE, encoding='utf-8'))

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL.upper()),
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=log_handlers
)
logger = logging.getLogger('UniversalProxy')

# Счетчик активных соединений
active_connections = 0
connections_lock = threading.Lock()

# =========================================================
# КЛАСС ДЛЯ РАБОТЫ С SOCKS5
# =========================================================

class Socks5Handler(socketserver.StreamRequestHandler):
    """Обработчик SOCKS5-запросов с поддержкой аутентификации"""

    def handle(self):
        global active_connections
        client_addr = self.client_address
        start_time = time.time()

        with connections_lock:
            active_connections += 1
            current_active = active_connections

        logger.info(f"[+] Подключение от {client_addr[0]}:{client_addr[1]} (Активно: {current_active})")

        try:
            self.request.settimeout(TIMEOUT)

            # ---------- 1. Чтение первого байта для определения типа ----------
            first_byte = self._recv_exact(1)
            if not first_byte:
                logger.warning(f"[-] Пустой запрос от {client_addr}")
                return

            # ---------- 2. Определение протокола (SOCKS5 или HTTP) ----------
            if first_byte == b'\x05':
                # SOCKS5
                self._handle_socks5(client_addr)
            elif first_byte in (b'C', b'G', b'P', b'H', b'D', b'O'):
                # HTTP-запрос (CONNECT, GET, POST, HEAD, DELETE, OPTIONS)
                # Читаем остаток строки, чтобы получить полный запрос
                rest = self.request.recv(1024).decode('utf-8', errors='ignore')
                full_request = (first_byte.decode('utf-8', errors='ignore') + rest).strip()
                self._handle_http_connect(full_request, client_addr)
            else:
                logger.warning(f"[-] Неизвестный протокол от {client_addr}: {first_byte}")
                return

        except socket.timeout:
            logger.warning(f"[-] Таймаут от {client_addr}")
        except ConnectionResetError:
            logger.warning(f"[-] Сброс соединения от {client_addr}")
        except BrokenPipeError:
            logger.warning(f"[-] Разрыв соединения от {client_addr}")
        except Exception as e:
            logger.error(f"[!] Ошибка от {client_addr}: {e.__class__.__name__}: {e}")
            import traceback
            traceback.print_exc()
        finally:
            self.request.close()
            elapsed = time.time() - start_time
            with connections_lock:
                active_connections -= 1
            logger.info(f"[-] Отключение {client_addr} (Время: {elapsed:.2f}с, Активно: {active_connections})")

    def _recv_exact(self, n):
        """Принять ровно n байт или вернуть None"""
        data = b''
        while len(data) < n:
            chunk = self.request.recv(n - len(data))
            if not chunk:
                return None
            data += chunk
        return data

    # ---------- SOCKS5 ----------
    def _handle_socks5(self, client_addr):
        """Обработка SOCKS5-протокола"""
        # Чтение методов
        nmethods = self._recv_exact(1)[0]
        methods = self._recv_exact(nmethods)

        # Выбор метода аутентификации
        if AUTH_REQUIRED and b'\x02' in methods:
            self.request.send(b'\x05\x02')  # Запрос логина/пароля
            logger.debug(f"[*] SOCKS5: запрошена аутентификация от {client_addr}")
        else:
            self.request.send(b'\x05\x00')  # Без аутентификации
            logger.debug(f"[*] SOCKS5: аутентификация не требуется от {client_addr}")

        # Аутентификация (если требуется)
        if AUTH_REQUIRED:
            ver = self._recv_exact(1)
            if not ver or ver != b'\x01':
                logger.warning(f"[-] SOCKS5: неверный запрос аутентификации от {client_addr}")
                return
            ulen = self._recv_exact(1)[0]
            username = self._recv_exact(ulen).decode('utf-8', errors='ignore')
            plen = self._recv_exact(1)[0]
            password = self._recv_exact(plen).decode('utf-8', errors='ignore')

            if username == USERNAME and password == PASSWORD:
                self.request.send(b'\x01\x00')
                logger.info(f"[+] SOCKS5: аутентификация прошла: {username} от {client_addr}")
            else:
                self.request.send(b'\x01\x01')
                logger.warning(f"[-] SOCKS5: неудачная аутентификация от {client_addr}")
                return

        # Чтение запроса
        ver = self._recv_exact(1)
        if not ver or ver != b'\x05':
            return
        cmd = self._recv_exact(1)[0]
        self._recv_exact(1)  # rsv
        atyp = self._recv_exact(1)[0]

        # Парсинг адреса
        if atyp == 1:  # IPv4
            addr = socket.inet_ntoa(self._recv_exact(4))
        elif atyp == 3:  # Доменное имя
            length = self._recv_exact(1)[0]
            addr = self._recv_exact(length).decode('utf-8')
        elif atyp == 4:  # IPv6
            addr = socket.inet_ntop(socket.AF_INET6, self._recv_exact(16))
        else:
            logger.warning(f"[-] SOCKS5: неподдерживаемый тип адреса {atyp} от {client_addr}")
            return
        port = struct.unpack('>H', self._recv_exact(2))[0]

        logger.info(f"[*] SOCKS5: запрос к {addr}:{port} от {client_addr}")

        if cmd == 1:  # CONNECT
            self._forward_to_target(addr, port, client_addr)
        else:
            logger.warning(f"[-] SOCKS5: команда {cmd} не поддерживается от {client_addr}")
            self.request.send(b'\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00')

    # ---------- HTTP CONNECT ----------
    def _handle_http_connect(self, raw_request, client_addr):
        """Обработка HTTP-запроса (CONNECT, GET, POST) — превращаем в SOCKS5-туннель"""
        lines = raw_request.split('\r\n')
        if not lines:
            return

        first_line = lines[0].strip()
        parts = first_line.split(' ')
        if len(parts) < 2:
            logger.warning(f"[-] HTTP: неверный запрос от {client_addr}: {first_line}")
            self.request.send(b'HTTP/1.1 400 Bad Request\r\n\r\n')
            return

        method = parts[0].upper()
        target = parts[1]

        # Проверка аутентификации (Proxy-Authorization)
        if AUTH_REQUIRED:
            auth_header = None
            for line in lines:
                if line.lower().startswith('proxy-authorization:'):
                    auth_header = line.split(':', 1)[1].strip()
                    break
            if not auth_header:
                logger.warning(f"[-] HTTP: отсутствует аутентификация от {client_addr}")
                self.request.send(b'HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm="Proxy"\r\n\r\n')
                return

            # Проверка логина/пароля (Basic Auth)
            if auth_header.startswith('Basic '):
                try:
                    decoded = base64.b64decode(auth_header[6:]).decode('utf-8')
                    user, pwd = decoded.split(':', 1)
                except:
                    user, pwd = '', ''
                if user != USERNAME or pwd != PASSWORD:
                    logger.warning(f"[-] HTTP: неверный логин/пароль от {client_addr}")
                    self.request.send(b'HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm="Proxy"\r\n\r\n')
                    return
            else:
                logger.warning(f"[-] HTTP: неподдерживаемый метод аутентификации от {client_addr}")
                self.request.send(b'HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm="Proxy"\r\n\r\n')
                return

        # Обработка CONNECT
        if method == 'CONNECT':
            # target = "host:port"
            if ':' in target:
                host, port_str = target.rsplit(':', 1)
                try:
                    port = int(port_str)
                except:
                    logger.warning(f"[-] HTTP: неверный порт от {client_addr}: {target}")
                    self.request.send(b'HTTP/1.1 400 Bad Request\r\n\r\n')
                    return
                logger.info(f"[*] HTTP CONNECT: {host}:{port} от {client_addr}")

                # Подключаемся к цели
                remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                remote.settimeout(TIMEOUT)
                try:
                    remote.connect((host, port))
                except Exception as e:
                    logger.warning(f"[-] HTTP: не удалось подключиться к {host}:{port} от {client_addr}: {e}")
                    self.request.send(b'HTTP/1.1 502 Bad Gateway\r\n\r\n')
                    remote.close()
                    return

                # Отправляем успешный ответ (туннель установлен)
                self.request.send(b'HTTP/1.1 200 Connection Established\r\nProxy-Agent: UniversalProxy/2.0\r\n\r\n')
                logger.info(f"[*] HTTP CONNECT: туннель к {host}:{port} установлен для {client_addr}")

                # Пересылка данных
                self._forward_data(self.request, remote, client_addr)

        else:
            # GET, POST, HEAD — обрабатываем как обычный HTTP-запрос через прокси
            logger.info(f"[*] HTTP {method}: {target} от {client_addr}")
            self._forward_http_request(raw_request, target, client_addr)

    # ---------- Пересылка данных ----------
    def _forward_to_target(self, addr, port, client_addr):
        """Установка туннеля к целевой машине и пересылка данных"""
        remote = None
        try:
            remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote.settimeout(TIMEOUT)
            remote.connect((addr, port))
            logger.info(f"[*] Подключение к {addr}:{port} установлено для {client_addr}")

            # Ответ об успехе
            self.request.send(b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00')
            self._forward_data(self.request, remote, client_addr)

        except socket.timeout:
            logger.warning(f"[-] Таймаут подключения к {addr}:{port} от {client_addr}")
            self.request.send(b'\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00')
        except ConnectionRefusedError:
            logger.warning(f"[-] Отказ в соединении с {addr}:{port} от {client_addr}")
            self.request.send(b'\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00')
        except Exception as e:
            logger.error(f"[!] Ошибка подключения к {addr}:{port} от {client_addr}: {e}")
            self.request.send(b'\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00')
        finally:
            if remote:
                remote.close()

    def _forward_http_request(self, raw_request, target, client_addr):
        """Пересылка HTTP-запроса (GET, POST, HEAD) через прокси"""
        # Извлекаем хост и порт из target
        if '://' in target:
            target = target.split('://', 1)[1]
        if '/' in target:
            host_port, path = target.split('/', 1)
            path = '/' + path
        else:
            host_port = target
            path = '/'

        if ':' in host_port:
            host, port_str = host_port.rsplit(':', 1)
            try:
                port = int(port_str)
            except:
                port = 80
        else:
            host = host_port
            port = 80

        try:
            remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote.settimeout(TIMEOUT)
            remote.connect((host, port))

            # Пересылаем запрос (исправляем заголовки, добавляем Host если нужно)
            lines = raw_request.split('\r\n')
            new_first_line = f"{lines[0].split(' ')[0]} {path} HTTP/1.1"
            new_lines = [new_first_line]
            has_host = False
            for line in lines[1:]:
                if line.lower().startswith('host:'):
                    has_host = True
                new_lines.append(line)
            if not has_host:
                new_lines.append(f"Host: {host}")
            new_request = '\r\n'.join(new_lines) + '\r\n\r\n'

            remote.send(new_request.encode('utf-8'))
            self._forward_data(self.request, remote, client_addr)

        except Exception as e:
            logger.error(f"[!] Ошибка HTTP-запроса к {host}:{port} от {client_addr}: {e}")
            try:
                self.request.send(b'HTTP/1.1 502 Bad Gateway\r\n\r\n')
            except:
                pass
        finally:
            remote.close()

    def _forward_data(self, client_sock, remote_sock, client_addr):
        """Двусторонняя пересылка данных между клиентом и удалённым сервером"""
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

        except socket.timeout:
            logger.warning(f"[-] Таймаут пересылки данных для {client_addr}")
        except Exception as e:
            logger.error(f"[!] Ошибка пересылки данных для {client_addr}: {e}")


# =========================================================
# ЗАПУСК СЕРВЕРА
# =========================================================

class ThreadedTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True

    def __init__(self, server_address, RequestHandlerClass, bind_and_activate=True):
        super().__init__(server_address, RequestHandlerClass, bind_and_activate)
        self.active_threads = 0
        self.threads_lock = threading.Lock()

    def process_request(self, request, client_address):
        with self.threads_lock:
            if self.active_threads >= MAX_THREADS:
                logger.warning(f"[-] Достигнут лимит потоков ({MAX_THREADS}), соединение отклонено")
                request.close()
                return
            self.active_threads += 1

        try:
            super().process_request(request, client_address)
        finally:
            with self.threads_lock:
                self.active_threads -= 1


def signal_handler(sig, frame):
    logger.info("\n[!] Получен сигнал остановки. Завершаем работу...")
    sys.exit(0)


if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    server = ThreadedTCPServer((HOST, PORT), Socks5Handler)

    logger.info("="*60)
    logger.info(f"[+] УНИВЕРСАЛЬНЫЙ ПРОКСИ-СЕРВЕР ЗАПУЩЕН")
    logger.info(f"[+] Хост: {HOST}")
    logger.info(f"[+] Порт: {PORT}")
    logger.info(f"[+] Аутентификация: {'ВКЛЮЧЕНА' if AUTH_REQUIRED else 'ВЫКЛЮЧЕНА'}")
    if AUTH_REQUIRED:
        logger.info(f"[+] Логин: {USERNAME}")
        logger.info(f"[+] Пароль: {PASSWORD}")
    logger.info(f"[+] Максимум потоков: {MAX_THREADS}")
    logger.info(f"[+] Лог-файл: {LOG_FILE if LOG_FILE else 'Только консоль'}")
    logger.info("="*60)
    logger.info("[*] Нажмите Ctrl+C для остановки")
    logger.info("[*] Поддерживаются: SOCKS5, HTTP CONNECT, HTTP GET/POST")
    logger.info("[*] Браузеры: Яндекс, Chrome, Firefox, Edge")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("\n[!] Остановка сервера...")
        server.shutdown()
        server.server_close()
        logger.info("[+] Сервер остановлен")