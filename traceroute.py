#!/usr/bin/env python3

import sys
import socket
import ipaddress
import subprocess
import re


def is_local_ip(ip):
    """Проверка, является ли IP локальным"""
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private
    except ValueError:
        return False


def get_whois_info(ip):
    """Получение информации через WHOIS вручную"""
    try:
        # Создаем сокет и подключаемся к whois.ripe.net
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect(("whois.ripe.net", 43))

        # Отправляем запрос
        s.send(f"{ip}\r\n".encode('utf-8'))

        # Получаем ответ
        response = ""
        while True:
            data = s.recv(4096).decode('utf-8', errors='ignore')
            if not data:
                break
            response += data
        s.close()

        # Парсинг ответа
        netname = ""
        asn = ""
        country = ""

        for line in response.split('\n'):
            if line.startswith('netname:'):
                netname = line.split(':', 1)[1].strip()
            elif line.startswith('origin:') or line.startswith('AS:'):
                asn = line.split(':', 1)[1].strip().replace('AS', '')
            elif line.startswith('country:'):
                country = line.split(':', 1)[1].strip()
                if country == 'EU':  # EU не считается страной
                    country = ""

        return netname, asn, country
    except Exception:
        return "", "", ""


def traceroute(target):
    """Выполнение трассировки с использованием системной команды"""
    try:
        # Преобразование имени в IP, если это DNS
        try:
            target_ip = socket.gethostbyname(target)
        except socket.gaierror:
            print(f"{target} is invalid")
            return

        # Проверка прав доступа
        if sys.platform != 'win32':
            try:
                socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            except PermissionError:
                print("Sorry, this operation requires elevated privileges")
                return

        # Используем системную команду traceroute/tracert
        cmd = ['tracert' if sys.platform == 'win32' else 'traceroute', '-m', '30', target]
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, _ = process.communicate()

        output = output.decode('utf-8', errors='ignore')
        hop_num = 1

        # Парсинг вывода
        if sys.platform == 'win32':
            lines = output.split('\n')[4:]  # Пропускаем заголовок в Windows
            ip_pattern = r'(\d+\.\d+\.\d+\.\d+)'
        else:
            lines = output.split('\n')[1:]  # Пропускаем первую строку в Unix
            ip_pattern = r'(\d+\.\d+\.\d+\.\d+)'

        for line in lines:
            if not line.strip():
                continue

            ip_match = re.search(ip_pattern, line)
            if ip_match:
                ip = ip_match.group(1)
                print(f"{hop_num}. {ip}")

                if is_local_ip(ip):
                    print("local")
                else:
                    netname, asn, country = get_whois_info(ip)
                    info_parts = []
                    if netname:
                        info_parts.append(netname)
                    if asn:
                        info_parts.append(asn)
                    if country:
                        info_parts.append(country)
                    if info_parts:
                        print(", ".join(info_parts))
                print("")
                hop_num += 1
            elif '*' in line or 'timeout' in line.lower():
                print(f"{hop_num}. *")
                print("")
                hop_num += 1

    except Exception as e:
        print(f"An error occurred: {str(e)}")


def main():
    if len(sys.argv) != 2:
        print("Usage: script.py <IP or hostname>")
        return

    target = sys.argv[1]

    # Проверка валидности адреса
    try:
        ipaddress.ip_address(target)
    except ValueError:
        # Если не IP, проверяем как hostname
        if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9-.]*$', target):
            print(f"{target} is invalid")
            return

    traceroute(target)


if __name__ == "__main__":
    main()