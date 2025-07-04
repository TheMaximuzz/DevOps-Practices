import os
import sys
import argparse
import socket
import ssl
import base64
import imghdr
from getpass import getpass
from typing import List

# Словарь для сопоставления типов imghdr с MIME-типами
MIME_TYPE_MAP = {
    'jpeg': 'jpeg',
    'png': 'png',
    'gif': 'gif',
    'bmp': 'bmp',
    'tiff': 'tiff',
    'webp': 'webp',
    'rgb': 'x-rgb',
    'pbm': 'x-portable-bitmap',
    'pgm': 'x-portable-graymap',
    'ppm': 'x-portable-pixmap',
    'rast': 'x-cmu-raster',
    'xbm': 'x-xbitmap',
    'exif': 'jpeg'  # EXIF обрабатывается как JPEG
}

def validate_image_file(full_path: str) -> bool:
    """
    Проверяет, является ли файл изображением, используя imghdr и дополнительные проверки.
    """
    # Проверка размера файла (слишком маленькие файлы вряд ли изображения)
    if os.path.getsize(full_path) < 100:  # Минимум 100 байт
        return False

    # Проверка начальных байт для исключения MP3
    try:
        with open(full_path, 'rb') as file:
            header = file.read(4)
            # MP3 часто начинается с ID3 или FF FB/FF F3 (MPEG frame)
            if header.startswith(b'ID3') or header[:2] == b'\xFF\xFB' or header[:2] == b'\xFF\xF3':
                return False
    except IOError:
        return False

    # Проверка с помощью imghdr
    image_type = imghdr.what(full_path)
    return image_type in MIME_TYPE_MAP

def find_images_in_directory(directory_path: str):
    """
    Находит все изображения в указанной директории с улучшенной проверкой типа.
    """
    if not os.path.isdir(directory_path):
        print(f"Ошибка: директория '{directory_path}' не существует", file=sys.stderr)
        sys.exit(1)

    found_images = []
    for item in os.listdir(directory_path):
        full_path = os.path.join(directory_path, item)
        if os.path.isfile(full_path) and validate_image_file(full_path):
            found_images.append(full_path)

    if not found_images:
        print(f"Ошибка: в директории '{directory_path}' нет изображений, поддерживаемых imghdr", file=sys.stderr)
        sys.exit(1)

    return found_images

def compose_email(from_address: str, to_address: str, email_subject: str, image_files: List[str]):
    """
    Формирует email-сообщение с вложениями изображений.
    """
    boundary = "BOUNDARY_" + base64.urlsafe_b64encode(os.urandom(12)).decode('ascii')

    email_headers = [
        f"From: {from_address}",
        f"To: {to_address}",
        f"Subject: {email_subject}",
        "MIME-Version: 1.0",
        f'Content-Type: multipart/mixed; boundary="{boundary}"',
        ""
    ]

    email_body = [
        f"--{boundary}",
        'Content-Type: text/plain; charset="utf-8"',
        "Content-Transfer-Encoding: 7bit",
        "",
        "Апчихба!",
        ""
    ]

    for image in image_files:
        try:
            with open(image, "rb") as file:
                image_data = file.read()

            # Определяем тип изображения с помощью imghdr
            image_type = imghdr.what(None, image_data)
            if not image_type or image_type not in MIME_TYPE_MAP:
                # Fallback на JPEG, если тип не распознан
                image_type = 'jpeg'
            # Получаем MIME-тип из словаря
            mime_type = MIME_TYPE_MAP.get(image_type, 'jpeg')

            image_filename = os.path.basename(image)
            encoded_data = base64.b64encode(image_data).decode('ascii')

            attachment_part = [
                f"--{boundary}",
                f'Content-Type: image/{mime_type}; name="{image_filename}"',
                "Content-Transfer-Encoding: base64",
                f'Content-Disposition: attachment; filename="{image_filename}"',
                ""
            ]

            attachment_part.extend(
                encoded_data[i:i + 76]
                for i in range(0, len(encoded_data), 76)
            )

            email_body.extend(attachment_part)
        except IOError as error:
            print(f"Ошибка: не удалось прочитать файл {image}: {error}", file=sys.stderr)
            sys.exit(1)

    email_body.append(f"--{boundary}--")
    return "\r\n".join(email_headers + email_body).encode("utf-8")

def receive_smtp_response(sock: socket.socket, verbose: bool = False) -> str:
    """Получает ответ от SMTP-сервера."""
    response_data = []
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        response_data.append(chunk)
        if b"\r\n" in chunk:
            break

    response = b"".join(response_data).decode('ascii', errors='replace')
    if verbose:
        for line in response.splitlines():
            print(line)
    return response

def send_smtp_command(sock: socket.socket, command: str, verbose: bool = False):
    """Отправляет команду SMTP-серверу и получает ответ."""
    if verbose:
        print(command)
    sock.sendall((command + "\r\n").encode('ascii'))
    return receive_smtp_response(sock, verbose)

def connect_to_smtp_server(host: str, port: int, verbose: bool = False):
    """Устанавливает соединение с SMTP-сервером."""
    try:
        sock = socket.create_connection((host, port), timeout=10)
        response = receive_smtp_response(sock, verbose)

        if not response.startswith("220"):
            print(f"Ошибка: некорректное приветствие сервера: {response.strip()}", file=sys.stderr)
            sock.close()
            sys.exit(1)

        return sock
    except (socket.timeout, socket.error) as error:
        print(f"Ошибка: не удалось подключиться к серверу: {error}", file=sys.stderr)
        sys.exit(1)

def send_hello(sock: socket.socket, verbose: bool = False) -> set:
    """Отправляет команду EHLO и возвращает поддерживаемые функции."""
    response = send_smtp_command(sock, f"EHLO {socket.gethostname()}", verbose)
    features = set()
    for line in response.splitlines():
        if len(line) >= 4 and line[:3].isdigit():
            feature = line[4:].strip().split()[0].upper()
            features.add(feature)
    return features

def start_tls_connection(sock: socket.socket, host: str, verbose: bool = False) -> socket.socket:
    """Инициирует TLS-соединение."""
    send_smtp_command(sock, "STARTTLS", verbose)
    context = ssl.create_default_context()
    secure_sock = context.wrap_socket(sock, server_hostname=host)
    return secure_sock

def send_email(sock: socket.socket, from_address: str, to_address: str, email_data: bytes,
               features: set, verbose: bool = False, auth: bool = False):
    """Отправляет email через SMTP с улучшенной обработкой ошибок и логированием."""
    # Очистка и валидация адреса получателя
    to_address = to_address.strip()
    if not to_address or '@' not in to_address and to_address != to_address.lower().replace(' ', ''):
        print(f"Ошибка: некорректный адрес получателя: {to_address}", file=sys.stderr)
        sys.exit(1)

    def attempt_send():
        mail_command = f"MAIL FROM:<{from_address}>"
        if any(f.startswith("SIZE") for f in features):
            mail_command += f" SIZE={len(email_data)}"

        response = send_smtp_command(sock, mail_command, verbose)
        if not response.startswith("2"):
            print(f"Ошибка в MAIL FROM: {response.strip()}", file=sys.stderr)
            return response

        if verbose:
            print(f"Отправка RCPT TO с адресом: {to_address}")
        response = send_smtp_command(sock, f"RCPT TO:<{to_address}>", verbose)
        if not response.startswith("2"):
            print(f"Ошибка в RCPT TO: {response.strip()}", file=sys.stderr)
            return response

        response = send_smtp_command(sock, "DATA", verbose)
        if not response.startswith("3"):
            print(f"Ошибка в DATA: {response.strip()}", file=sys.stderr)
            return response

        return response

    response = attempt_send()

    if auth and (response.startswith("530") or response.startswith("535")):
        authenticate_smtp(sock, verbose)
        response = attempt_send()

    if not response.startswith("2") and not response.startswith("3"):
        print(f"Прерывание отправки из-за ошибки: {response.strip()}", file=sys.stderr)
        sys.exit(1)

    safe_email_data = email_data.replace(b"\r\n.", b"\r\n..")
    sock.sendall(safe_email_data + b"\r\n.\r\n")

    final_response = receive_smtp_response(sock, verbose)
    if not final_response.startswith("2"):
        print(f"Ошибка при отправке письма: {final_response.strip()}", file=sys.stderr)
        sys.exit(1)

def parse_arguments():
    """Парсит аргументы командной строки."""
    parser = argparse.ArgumentParser(description="Отправка изображений по email через SMTP")
    parser.add_argument('--ssl', action='store_true', help="Использовать SSL/STARTTLS")
    parser.add_argument('-s', '--server', required=True, help="SMTP сервер (host[:port])")
    parser.add_argument('-t', '--to', required=True, help="Email получателя")
    parser.add_argument('-f', '--from', dest='from_address', default="<>", help="Email отправителя")
    parser.add_argument('--subject', default="Happy pictures", help="Тема письма")
    parser.add_argument('--auth', action='store_true', help="Требовать аутентификацию")
    parser.add_argument('-v', '--verbose', action='store_true', help="Подробный вывод")
    parser.add_argument('-d', '--directory', default='.', help="Директория с изображениями")
    return parser.parse_args()

def authenticate_smtp(sock: socket.socket, verbose: bool = False) -> str:
    """Выполняет аутентификацию на SMTP-сервере."""
    arg = parse_arguments()
    email = arg.from_address
    password = getpass("Введите пароль приложения: ").strip()

    send_smtp_command(sock, "AUTH LOGIN", verbose)
    send_smtp_command(sock, base64.b64encode(email.encode()).decode(), verbose)
    auth_response = send_smtp_command(sock, base64.b64encode(password.encode()).decode(), verbose)

    if not auth_response.startswith("235"):
        print(f"Ошибка аутентификации: {auth_response.strip()}", file=sys.stderr)
        sys.exit(1)

    return email

def main():
    """Основная функция для отправки письма."""
    args = parse_arguments()
    host, port = args.server.split(':')[0], int(args.server.split(':')[1]) if ':' in args.server else 25

    images = find_images_in_directory(args.directory)
    sock = connect_to_smtp_server(host, port, args.verbose)

    try:
        features = send_hello(sock, args.verbose)

        if args.ssl:
            if port == 465:
                context = ssl.create_default_context()
                sock = context.wrap_socket(sock, server_hostname=host)
                features = send_hello(sock, args.verbose)
            elif "STARTTLS" in features:
                sock = start_tls_connection(sock, host, args.verbose)
                features = send_hello(sock, args.verbose)
            else:
                print("Предупреждение: сервер не поддерживает STARTTLS", file=sys.stderr)

        email_data = compose_email(args.from_address, args.to, args.subject, images)
        send_email(sock, args.from_address, args.to, email_data, features, args.verbose, auth=args.auth)

        send_smtp_command(sock, "QUIT", args.verbose)
        print("Письмо успешно отправлено!")
    finally:
        sock.close()

if __name__ == "__main__":
    main()