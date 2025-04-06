import socket
import struct
from datetime import datetime

def get_ntp_time():
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(30)

        # Инициализируем 48-байтовый пакет NTP-запроса
        packet = bytearray(48)
        packet[0] = 0x1B  # LI=0, VN=3, Mode=3 (клиент)

        server_address = ("10.249.18.180", 123)
        sock.sendto(packet, server_address)

        data, addr = sock.recvfrom(1024)
        # Извлекаем transmit timestamp из ответа (байты 40-47)
        unpacked = struct.unpack('!12I', data)
        transmit = (unpacked[10] - 2208988800) + (unpacked[11] / 2**32)
        precise_time_str = datetime.fromtimestamp(transmit).strftime('%H:%M:%S %d.%m.%Y')

        return precise_time_str

    except Exception as e:
        return f"Ошибка: {e}"

if __name__ == "__main__":
    current_time = get_ntp_time()
    print(current_time)
