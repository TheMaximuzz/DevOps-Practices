
import socket
import sys
import argparse
import signal


def resolve_hostname(hostname):
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        print(f"[-] Не удалось определить имя хоста: {hostname}")
        sys.exit(1)


def tcp_scan(ip, start_port, end_port):
    open_ports = []
    print(f"[*] Начинаем TCP cканирование на {ip}")
    for port in range(start_port, end_port + 1):
        try:
            tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            tcp.settimeout(0.5)
            result = tcp.connect_ex((ip, port)) #Делаем соединение по порту
            if result == 0:
                print(f"TCP {port: <5}")
                open_ports.append(port)
            tcp.close()
            if port % 100 == 0:
                print(f"[*] Прогресс: Просканировано до порта {port}")
        except Exception as e:
            print(f"[-] Ошибка на порту {port}: {e}")
            continue
    return open_ports


def udp_scan(ip, start_port, end_port):
    open_ports = []
    print(f"[*] Начинаем UDP сканирование на {ip}")
    for port in range(start_port, end_port + 1):
        try:
            udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp.settimeout(2)
            udp.sendto(b"test", (ip, port)) # отправка UDP-пакета

            try:
                data, _ = udp.recvfrom(1024)
                print(f"UDP {port: <5} открыт (получен ответ)")
                open_ports.append(port)
            except socket.timeout:
                print(f"UDP {port: <5} открыт или фильтруется (нет отклика)")
                open_ports.append(port)
            except socket.error:
                print(f"UDP {port: <5} закрыт (ICMP пакет с ошибкой)")

            udp.close()

            if port % 100 == 0:
                print(f"[*] Прогресс: Просканировано до порта {port}")

        except Exception as e:
            print(f"[-] Ошибка на порту {port}: {e}")
            continue
    return open_ports


def scan_host(host, start_port, end_port, scan_tcp=True, scan_udp=False):
    ip = resolve_hostname(host)
    print(f"[*] Сканируемый хост: {host} ({ip})")
    print(f"[*] Диапазон портов: {start_port}-{end_port}")

    try:
        if scan_tcp:
            tcp_ports = tcp_scan(ip, start_port, end_port)
            if not tcp_ports:
                print("[*] Открытых TCP портов не найдено")

        if scan_udp:
            udp_ports = udp_scan(ip, start_port, end_port)
            if not udp_ports:
                print("[*] Открытых UDP портов не найдено")

        print(f"[+] Сканирование завершено")
    except KeyboardInterrupt:
        print("\n[!] Сканирование прервано пользователем")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description="Сканер портов")
    parser.add_argument("host", help="Целевой хост (IP или имя хоста)")
    parser.add_argument("-t", "--tcp", action="store_true", help="Сканировать TCP порты")
    parser.add_argument("-u", "--udp", action="store_true", help="Сканировать UDP порты")
    parser.add_argument("-p", "--ports", nargs=2, type=int, required=True,
                        help="Диапазон портов (начало конец)", metavar=('НАЧАЛО', 'КОНЕЦ'))

    args = parser.parse_args()

    if args.ports[0] < 1 or args.ports[1] > 65535 or args.ports[0] > args.ports[1]:
        print("[-] Недопустимый диапазон портов. Порты должны быть в пределах 1-65535 и начало <= конец")
        sys.exit(1)

    if not (args.tcp or args.udp):
        print("[-] Укажите хотя бы один протокол (-t или -u)")
        sys.exit(1)

    signal.signal(signal.SIGINT, lambda sig, frame: sys.exit(1))

    scan_host(args.host, args.ports[0], args.ports[1], args.tcp, args.udp)


if __name__ == "__main__":
    main()