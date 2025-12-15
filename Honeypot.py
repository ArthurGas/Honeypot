import socket
import threading
import logging
from datetime import datetime

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(message)s',
    handlers=[
        logging.FileHandler("honeypot.log"),
        logging.StreamHandler()
    ]
)

# Конфигурация фейковых сервисов
HONEYPOT_CONFIG = {
    21: "220 ProFTPD 1.3.5 Server (Honeypot) [127.0.0.1]\r\n",
    22: "SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u7\r\n",
    23: "Ubuntu 18.04.1 LTS\r\nLogin: ",
    25: "220 mail.corp.local ESMTP Postfix (Ubuntu)\r\n",
    80: "HTTP/1.1 200 OK\r\nServer: Apache/2.4.25 (Debian)\r\nContent-Type: text/html\r\n\r\n<html><body><h1>System Online</h1></body></html>"
}

HOST = '0.0.0.0'  # Слушаем на всех интерфейсах

#обработка подключений
def handle_client(client_socket, address, port):
    try:
        logging.info(f"[!] Попытка сканирования: IP {address[0]} на порт {port}")
        # Получаем немного данных (если сканер что-то шлет)
        client_socket.settimeout(5)
        try:
            data = client_socket.recv(1024)
            if data:
                logging.info(f"    -> Полученные данные: {data.decode('utf-8', errors='ignore').strip()}")
        except socket.timeout:
            pass # Сканер просто подключился и ждет (TCP Connect)

        # Отправляем фейковый баннер
        if port in HONEYPOT_CONFIG:
            banner = HONEYPOT_CONFIG[port]
            client_socket.send(banner.encode())
            

    except Exception as e:
        logging.error(f"Ошибка при обработке соединения: {e}")
    finally:
        client_socket.close()
#запуск псевдослужб на портах
def start_honeypot_service(port):
    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Опция, чтобы можно было перезапускать скрипт без ожидания освобождения порта
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((HOST, port))
        server.listen(5)
        logging.info(f"[*] Honeypot запущен на порту {port}...")

        while True:
            client_socket, address = server.accept()
            # Запускаем обработку в отдельном потоке, чтобы не блокировать другие подключения
            client_handler = threading.Thread(
                target=handle_client,
                args=(client_socket, address, port)
            )
            client_handler.start()
            
    except PermissionError:
        logging.error(f"[X] Ошибка: Недостаточно прав")
    except Exception as e:
        logging.error(f"[X] Ошибка на порту {port}: {e}")

if __name__ == "__main__":
    logging.info("=== Приманка активна ===")
    
    threads = []
    # запуск прослушивания для каждого порта из конфигурации
    for port in HONEYPOT_CONFIG.keys():
        thread = threading.Thread(target=start_honeypot_service, args=(port,))
        thread.start()
        threads.append(thread)

    # бесконечный цикл работы
    for thread in threads:
        thread.join()
