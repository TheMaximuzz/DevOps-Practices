import socket
import time
import argparse
import struct

# Класс для кэширования записей
class DNSCache:
    def __init__(self):
        self.cache = {}  # Формат: {ключ: (ответ, время_добавления, ttl)}

    def get(self, key):
        if key in self.cache:
            entry, timestamp, ttl = self.cache[key]
            current_time = time.time()
            # Проверяем, не устарела ли запись (700 секунд прошло, TTL < 650)
            if (current_time - timestamp > 700) and (ttl < 650):
                del self.cache[key]
                return None
            return entry
        return None

    def put(self, key, value, ttl):
        self.cache[key] = (value, time.time(), ttl)

# Функция для извлечения имени домена из запроса
def parse_dns_name(data, offset):
    labels = []
    while True:
        length = data[offset]
        if length == 0:
            offset += 1
            break
        labels.append(data[offset + 1:offset + 1 + length].decode('utf-8'))
        offset += length + 1
    return '.'.join(labels), offset

# Функция для извлечения типа запроса (QTYPE)
def parse_qtype(data, offset):
    qtype = struct.unpack('!H', data[offset:offset + 2])[0]
    return qtype, offset + 4  # Пропускаем QTYPE и QCLASS (2 байта + 2 байта)

# Функция для создания DNS-ответа (простой случай)
def create_dns_response(query_data, answer_ip=None):
    # Извлекаем ID запроса
    dns_id = query_data[:2]
    # Формируем заголовок ответа
    flags = 0x8180  # Ответ, рекурсия доступна, нет ошибок
    qdcount = 1  # 1 вопрос
    ancount = 1 if answer_ip else 0  # 1 ответ, если есть IP
    nscount = 0
    arcount = 0
    header = struct.pack('!HHHHHH', struct.unpack('!H', dns_id)[0], flags, qdcount, ancount, nscount, arcount)

    # Копируем вопрос из запроса
    question = query_data[12:]  # Пропускаем заголовок (12 байт)

    if not answer_ip:
        return header + question  # Пустой ответ (SERVFAIL)

    # Формируем ответ (простой A-запись)
    name = b'\xc0\x0c'  # Указатель на имя из вопроса (сжатие)
    type_a = 1  # Тип A
    class_in = 1  # Класс IN
    ttl = 600  # TTL
    rdlength = 4  # Длина данных (IPv4 - 4 байта)
    rdata = socket.inet_aton(answer_ip)  # IP-адрес
    answer = name + struct.pack('!HHIH', type_a, class_in, ttl, rdlength) + rdata

    return header + question + answer

# Функция для отправки запроса форвардеру
def query_forwarder(forwarder, port, query):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)
    try:
        sock.sendto(query, (forwarder, port))
        data, _ = sock.recvfrom(1024)
        return data
    except socket.timeout:
        return None
    finally:
        sock.close()

# Основная функция сервера
def run_dns_server(port, forwarder, forwarder_port):
    cache = DNSCache()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('0.0.0.0', port))
    print(f"DNS сервер запущен на порту {port}, форвардер: {forwarder}:{forwarder_port}")

    while True:
        try:
            data, addr = sock.recvfrom(1024)
            # Парсим запрос
            offset = 12  # Пропускаем заголовок
            qname, offset = parse_dns_name(data, offset)
            qtype, offset = parse_qtype(data, offset)

            # Определяем тип запроса
            qtype_str = {1: 'A', 15: 'MX', 2: 'NS'}.get(qtype, 'UNKNOWN')
            cache_key = (qname, qtype)

            # Проверяем кэш
            cached_response = cache.get(cache_key)
            source = "cache"

            if cached_response is None:
                # Если в кэше нет, отправляем запрос форвардеру
                response = query_forwarder(forwarder, forwarder_port, data)
                if response is None:
                    # Если форвардер не ответил, отправляем пустой ответ
                    response = create_dns_response(data)
                    source = "forwarder"
                else:
                    # Сохраняем в кэш с TTL (для простоты фиксируем TTL)
                    ttl = 600  # Извлечение реального TTL требует полного парсинга ответа
                    cache.put(cache_key, response, ttl)
                    source = "forwarder"
            else:
                response = cached_response

            # Логируем запрос
            print(f"{addr[0]}, {qtype_str}, {qname}, {source}")

            # Отправляем ответ клиенту
            sock.sendto(response, addr)

        except Exception as e:
            print(f"Ошибка: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', type=int, default=53, help='Порт для сервера')
    parser.add_argument('-f', type=str, default='8.8.8.8', help='IP форвардера')
    args = parser.parse_args()

    forwarder_port = 53  # Порт форвардера по умолчанию
    run_dns_server(args.p, args.f, forwarder_port)