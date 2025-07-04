import socket
import sys
import argparse
import threading
from concurrent.futures import ThreadPoolExecutor
import time
import ssl
import struct

# Блокировка для синхронизации вывода
print_lock = threading.Lock()

def resolve_hostname(hostname):
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        with print_lock:
            print(f"[-] Не удалось определить имя хоста: {hostname}")
        sys.exit(1)

def detect_smtp(host, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            sock.connect((host, port))
            sock.sendall(b'EHLO test\r\n')
            response = sock.recv(1024)
            if b'220' in response or b'250' in response:
                return 'SMTP'
    except Exception:
        pass
    return ''

def detect_http(host, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            sock.connect((host, port))
            sock.sendall(b'GET / HTTP/1.1\r\nHost: test\r\n\r\n')
            response = sock.recv(1024)
            if b'HTTP' in response:
                return 'HTTP'
    except Exception:
        pass
    return ''

def detect_pop3(host, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            sock.connect((host, port))
            response = sock.recv(1024)
            if b'+OK' in response:
                return 'POP3'
    except Exception:
        pass
    return ''

def detect_imap(host, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            sock.connect((host, port))
            response = sock.recv(1024)
            if b'* OK' in response:
                return 'IMAP'
    except Exception:
        pass
    return ''

def detect_dns_tcp(host, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(2)
            sock.connect((host, port))
            query = (
                b'\xaa\xbb'  # ID: произвольный (0xAABB)
                b'\x01\x00'  # Flags: стандартный запрос с рекурсией
                b'\x00\x01'  # Questions: 1
                b'\x00\x00'  # Answer RRs: 0
                b'\x00\x00'  # Authority RRs: 0
                b'\x00\x00'  # Additional RRs: 0
                b'\x06google\x03com\x00'  # google.com (QNAME)
                b'\x00\x01'  # Type: A
                b'\x00\x01'  # Class: IN
            )
            dns_packet = struct.pack('!H', len(query)) + query
            sock.sendall(dns_packet)
            response = sock.recv(1024)
            if len(response) >= 12 and (response[2] & 0x80) == 0x80:
                return 'DNS'
    except Exception:
        pass
    return ''

def detect_https(host, port):
    try:
        context = ssl.create_default_context()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                ssock.settimeout(1)
                ssock.connect((host, port))
                return 'HTTPS'
    except Exception:
        pass
    return ''

def detect_dns(host, port, data):
    try:
        if data and len(data) >= 12 and data[2] == 1:
            return 'DNS'
    except Exception:
        pass
    return ''

def detect_ntp(host, port, data):
    try:
        if data and len(data) == 48 and data[0] == 0x1c:
            return 'NTP'
    except Exception:
        pass
    return ''

def detect_protocol_tcp(host, port):
    protocols = [
        detect_smtp(host, port),
        detect_http(host, port),
        detect_pop3(host, port),
        detect_imap(host, port),
        detect_dns_tcp(host, port),
        detect_https(host, port)
    ]
    for protocol in protocols:
        if protocol:
            return protocol
    return 'Unknown'

def detect_protocol_udp(host, port, data):
    protocols = [
        detect_dns(host, port, data),
        detect_ntp(host, port, data)
    ]
    for protocol in protocols:
        if protocol:
            return protocol
    return 'Unknown'

def tcp_scan_port(ip, port):
    """Проверяет TCP порт и возвращает порт и протокол, если порт открыт."""
    try:
        tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp.settimeout(0.5)
        result = tcp.connect_ex((ip, port))
        if result == 0:
            try:
                protocol = detect_protocol_tcp(ip, port)
                with print_lock:
                    print(f"TCP {port: <5} - {protocol}")
                tcp.close()
                return port, protocol
            #сравниваем строковое представление ошибки
            except ConnectionResetError as e:
                if str(e) == '[WinError 10054] Удаленный хост принудительно разорвал существующее подключение':
                    with print_lock:
                        print(f"TCP {port: <5} - Unknown ([WinError 10054] Удаленный хост принудительно разорвал соединение)")
                else:
                    with print_lock:
                        print(f"TCP {port: <5} - Unknown (разорвано удалённым хостом: {e})")
                tcp.close()
                return port, 'Unknown (ConnectionReset)'
        tcp.close()
    except ConnectionResetError as e:
        if str(e) == '[WinError 10054] Удаленный хост принудительно разорвал подключение':
            with print_lock:
                print(f"TCP {port: <5} - Unknown ([WinError 10054] Удаленный хост принудительно разорвал соединение)")
        else:
            with print_lock:
                print(f"[-] Ошибка на порту {port}: {e}")
        return None, None
    except Exception as e:
        with print_lock:
            print(f"[-] Ошибка на порту {port}: {e}")
    return None, None

def udp_scan_port(ip, port):
    """Проверяет UDP порт и возвращает порт и протокол, если порт открыт или фильтруется."""
    try:
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp.settimeout(2)
        udp.sendto(b'test', (ip, port))
        try:
            data, _ = udp.recvfrom(1024)
            try:
                protocol = detect_protocol_udp(ip, port, data)
                with print_lock:
                    print(f"UDP {port: <5} - {protocol} (получен ответ)")
                udp.close()
                return port, protocol
            except ConnectionResetError as e:
                if str(e) == '[WinError 10054] Удаленный хост принудительно разорвал существующее подключение':
                    with print_lock:
                        print(f"UDP {port: <5} - Unknown ([WinError 10054] Удаленный хост принудительно разорвал соединение, возможно SNTP-сервер)")
                else:
                    with print_lock:
                        print(f"UDP {port: <5} - Unknown (разорвано удалённым хостом: {e})")
                udp.close()
                return port, 'Unknown (ConnectionReset)'
        except socket.timeout:
            protocol = detect_protocol_udp(ip, port, None)
            with print_lock:
                print(f"UDP {port: <5} - {protocol} (открыт или фильтруется)")
            udp.close()
            return port, protocol
    except ConnectionResetError as e:
        if str(e) == '[WinError 10054] Удаленный хост принудительно разорвал существующее подключение':
            with print_lock:
                print(f"UDP {port: <5} - Unknown")
        else:
            with print_lock:
                print(f"UDP {port: <5} - Unknown (разорвано удалённым хостом: {e})")
        return port, 'Unknown (ConnectionReset)'
    except Exception as e:
        with print_lock:
            print(f"[-] Ошибка на порту {port}: {e}")
    finally:
        if 'udp' in locals():
            udp.close()
    return None, None

def tcp_scan(ip, start_port, end_port, max_workers=10):
    """Сканирует TCP порты параллельно."""
    open_ports = []
    print(f"[*] Начинаем TCP сканирование на {ip}")
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(tcp_scan_port, ip, port): port for port in range(start_port, end_port + 1)}
        for future in futures:
            port, protocol = future.result()
            if port:
                open_ports.append((port, protocol))
    return open_ports

def udp_scan(ip, start_port, end_port, max_workers=10):
    """Сканирует UDP порты параллельно."""
    open_ports = []
    print(f"[*] Начинаем UDP сканирование на {ip}")
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(udp_scan_port, ip, port): port for port in range(start_port, end_port + 1)}
        for future in futures:
            port, protocol = future.result()
            if port:
                open_ports.append((port, protocol))
    return open_ports

def scan_host(host, start_port, end_port, scan_tcp=True, scan_udp=False, max_workers=10):
    ip = resolve_hostname(host)
    print(f"[*] Сканируемый хост: {host} ({ip})")
    print(f"[*] Диапазон портов: {start_port}-{end_port}")
    print("\nРезультаты:")
    start_time = time.time()
    try:
        if scan_tcp:
            tcp_ports = tcp_scan(ip, start_port, end_port, max_workers)
            if not tcp_ports:
                print("[*] Открытых TCP портов не найдено")
        if scan_udp:
            udp_ports = udp_scan(ip, start_port, end_port, max_workers)
            if not udp_ports:
                print("[*] Открытых UDP портов не найдено")
        elapsed_time = time.time() - start_time
        print(f"[+] Сканирование завершено за {elapsed_time:.2f} секунд")
    except KeyboardInterrupt:
        print("\n[!] Сканирование прервано пользователем")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="Сканер портов с определением протоколов")
    parser.add_argument("host", help="Целевой хост")
    parser.add_argument("-t", "--tcp", action="store_true", help="Сканировать TCP")
    parser.add_argument("-u", "--udp", action="store_true", help="Сканировать UDP")
    parser.add_argument("-p", "--ports", nargs=2, type=int, required=True, help="Диапазон портов", metavar=('НАЧАЛО', 'КОНЕЦ'))
    parser.add_argument("-w", "--workers", type=int, default=10, help="Количество потоков")
    args = parser.parse_args()

    if args.ports[0] < 1 or args.ports[1] > 65535 or args.ports[0] > args.ports[1]:
        print("[-] Недопустимый диапазон портов")
        sys.exit(1)
    if not (args.tcp or args.udp):
        print("[-] Укажите протокол (-t или -u)")
        sys.exit(1)

    scan_host(args.host, args.ports[0], args.ports[1], args.tcp, args.udp, args.workers)

if __name__ == "__main__":
    main()