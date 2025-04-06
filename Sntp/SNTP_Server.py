import socket
import struct
import threading
import argparse
import subprocess
from datetime import datetime, timedelta, timezone

EXTERNAL_NTP_SERVERS = ['time.google.com', 'pool.ntp.org']
EXTERNAL_NTP_PORT = 123
NTP_EPOCH = 2208988800  # Разница между 1900 и 1970 гг.


def check_port_availability(port):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as test_socket:
        try:
            test_socket.bind(("0.0.0.0", port))
            return True
        except OSError:
            return False


def disable_windows_time_service():
    try:
        subprocess.run(["net", "stop", "w32time"], check=True, shell=True)
        print("Служба времени остановлена")
    except subprocess.CalledProcessError:
        print("Не удалось остановить службу времени")


def get_external_ntp_time():
    """ Получает текущее NTP-время от одного из внешних серверов """
    for ntp_server in EXTERNAL_NTP_SERVERS:
        try:
            client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            client.settimeout(5)
            request = b'\x1b' + 47 * b'\0'
            addr_info = socket.getaddrinfo(ntp_server, EXTERNAL_NTP_PORT, socket.AF_INET, socket.SOCK_DGRAM)
            if not addr_info:
                continue
            server_address = addr_info[0][4]
            client.sendto(request, server_address)
            data, _ = client.recvfrom(1024)
            unpacked = struct.unpack('!12I', data)
            return unpacked[10] - NTP_EPOCH + unpacked[11] / 2 ** 32
        except (socket.gaierror, socket.timeout):
            continue
        except Exception as e:
            print(f"[ERROR] Ошибка при получении NTP времени: {e}")
    raise ValueError("Не удалось получить время с внешнего NTP сервера")


def get_shifted_time(offset_seconds):
    """ Возвращает сдвинутое время с учётом NTP """
    try:
        external_time = get_external_ntp_time()
        shifted_time = external_time + offset_seconds
        print(f"[INFO] Время NTP: {external_time}, сдвинутое: {shifted_time}")
        return datetime.fromtimestamp(shifted_time, tz=timezone.utc)
    except (OSError, ValueError):
        print("[ERROR] Ошибка преобразования времени, используем текущее UTC")
        return datetime.utcnow().replace(tzinfo=timezone.utc)


def to_ntp_time(dt):
    return (dt - datetime(1900, 1, 1, tzinfo=timezone.utc)).total_seconds()


def create_ntp_packet(offset_seconds):
    """ Формирует NTP-пакет с учетом смещения """
    shifted_time = get_shifted_time(offset_seconds)
    ntp_time = to_ntp_time(shifted_time)

    integer_part = int(ntp_time)
    fractional_part = int((ntp_time - integer_part) * (2 ** 32))

    if integer_part < 0 or integer_part > 0xFFFFFFFF:
        raise ValueError(f"Invalid integer_part: {integer_part}")

    packet = bytearray(48)
    packet[0] = 0x1C  # LI=0, VN=3, Mode=4 (server)
    packet[1] = 1  # Stratum
    packet[2] = 0  # Poll
    packet[3] = 0  # Precision
    packet[12:16] = b'LOCL'

    packet[16:20] = struct.pack('!I', integer_part)
    packet[20:24] = struct.pack('!I', fractional_part)
    packet[24:28] = struct.pack('!I', integer_part)
    packet[28:32] = struct.pack('!I', fractional_part)
    packet[32:36] = struct.pack('!I', integer_part)
    packet[36:40] = struct.pack('!I', fractional_part)
    packet[40:44] = struct.pack('!I', integer_part)
    packet[44:48] = struct.pack('!I', fractional_part)

    return packet


def handle_client(data, address, server_socket, offset_seconds):
    print(f"[INFO] Получен запрос от {address[0]}")
    try:
        response_packet = create_ntp_packet(offset_seconds)
        server_socket.sendto(response_packet, address)
        print(f"[INFO] Отправлено сдвинутое время клиенту {address[0]}")
    except Exception as e:
        print(f"[ERROR] Ошибка при отправке ответа: {e}")


def start_sntp_server(host, port, offset_seconds):
    """ Запускает SNTP-сервер """
    if not check_port_availability(port):
        print(f"[WARNING] Порт {port} уже занят! Попытка отключить системную службу времени...")
        disable_windows_time_service()
        if not check_port_availability(port):
            print(f"[ERROR] Порт {port} по-прежнему занят, сервер не может быть запущен!")
            return

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server_socket:
        server_socket.bind((host, port))
        print(f"[INFO] SNTP сервер запущен на {host}:{port} с задержкой {offset_seconds} секунд")

        while True:
            data, address = server_socket.recvfrom(1024)
            client_thread = threading.Thread(target=handle_client, args=(data, address, server_socket, offset_seconds))
            client_thread.start()


def main():
    parser = argparse.ArgumentParser(description="SNTP сервер с настройкой смещения времени")
    parser.add_argument('-d', '--delay', type=int, default=0, help="Смещение времени в секундах")
    parser.add_argument('-p', '--port', type=int, default=123, help="Порт (должен быть 123)")
    args = parser.parse_args()

    if args.port != 123:
        print("[WARNING] Для работы SNTP должен использоваться порт 123!")

    start_sntp_server('0.0.0.0', args.port, args.delay)


if __name__ == "__main__":
    main()
