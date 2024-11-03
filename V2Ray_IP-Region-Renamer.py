# Системные библиотеки
import base64  # для кодирования и декодирования VMESS профилей в base64
import os  # для работы с файловой системой, например, проверки существования файлов
import socket  # для разрешения доменных имен в IP
import sys  # для управления завершением программы и работы с аргументами командной строки
import time  # для работы с задержками и замером времени
from datetime import datetime, timedelta  # для работы с датами и временем, например, проверки последней проверки времени

# Сетевые библиотеки и HTTP-запросы
import requests  # для выполнения HTTP-запросов к API для получения данных о местоположении IP

# Обработка данных
import json  # для работы с JSON-данными
import re  # для использования регулярных выражений

# Интерфейс и улучшение взаимодействия с пользователем
import colorama  # для вывода цветного текста в консоли для улучшения читаемости и удобства
from colorama import Fore, Style
import pyperclip  # для копирования текста в буфер обмена

colorama.init(autoreset=True)

API_URL = "http://ip-api.com/json/"
MAX_REQUESTS_PER_MINUTE = 45
TIME_DELAY = 60  # Задержка между проверками
TIME_FILE = "last_check_time.txt"  # Файл для хранения времени последней проверки
CACHE_FILE = "processed_profiles.txt"  # Кеш-файл для сохранения обработанных профилей

def extract_profiles(file_path):
    """Извлекает профили из файла."""
    with open(file_path, 'r', encoding='utf-8') as f:
        return f.readlines()

def decode_vmess(vmess_profile):
    """Расшифровывает VMESS профиль из base64."""
    try:
        decoded = base64.b64decode(vmess_profile[8:]).decode('utf-8')
        return json.loads(decoded)
    except Exception as e:
        print(f"{Fore.RED}❌ Ошибка при расшифровке VMESS профиля: {e}")
        return None

def encode_vmess(vmess_data):
    """Кодирует VMESS профиль обратно в base64."""
    try:
        json_str = json.dumps(vmess_data, ensure_ascii=False)
        encoded = base64.b64encode(json_str.encode('utf-8')).decode('utf-8')
        return f"vmess://{encoded}"
    except Exception as e:
        print(f"{Fore.RED}❌ Ошибка при кодировании VMESS профиля: {e}")
        return None

def extract_ip_from_profile(profile):
    """Извлекает IP-адрес или домен из профиля."""
    if profile.startswith("vmess://"):
        vmess_data = decode_vmess(profile)
        if vmess_data and "add" in vmess_data:
            return vmess_data["add"]
    else:
        ip_or_domain_match = re.search(r'((?:\d{1,3}\.){3}\d{1,3}|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', profile)
        if ip_or_domain_match:
            return ip_or_domain_match.group(0)
    return None

def resolve_domain_to_ip(domain):
    """Разрешает доменное имя в IP-адрес."""
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        print(f"{Fore.RED}❌ Не удалось разрешить домен: {domain}")
        return None

def get_location(ip):
    """Получает местоположение IP через API."""
    url = f"{API_URL}{ip}"
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            if data.get("status") == "success":
                return f"{data['country']}, {data['regionName']}, {data['city']}"
            elif data.get("status") == "fail" and data.get("message") == "quota":
                # Превышен лимит запросов
                return "RATE_LIMIT_EXCEEDED"
            else:
                return "Unknown, Unknown, Unknown"
        else:
            return "Unknown, Unknown, Unknown"
    except Exception as e:
        print(f"{Fore.RED}❌ Ошибка соединения: {e}")
        return "Unknown, Unknown, Unknown"

def cooldown(seconds):
    """Отсчитывает время задержки, позволяет прервать ожидание при нажатии 'P'."""
    print(f"{Fore.YELLOW}⏳ Ожидание {seconds} секунд перед следующей отправкой...")
    print("Если вы сменили IP и хотите пропустить ожидание, нажмите 'P'.")
    start_time = time.time()
    try:
        if os.name == 'nt':
            import msvcrt
            while True:
                remaining = int(seconds - (time.time() - start_time))
                if remaining <= 0:
                    break
                print(f"{remaining}/{seconds} секунд", end='\r')
                time.sleep(1)
                if msvcrt.kbhit():
                    key = msvcrt.getch()
                    if key.lower() == b'p':
                        print(f"{Fore.GREEN}✅ Ожидание пропущено по запросу пользователя.")
                        break
        else:
            import select
            import sys
            while True:
                remaining = int(seconds - (time.time() - start_time))
                if remaining <= 0:
                    break
                print(f"{remaining}/{seconds} секунд", end='\r')
                time.sleep(1)
                dr, dw, de = select.select([sys.stdin], [], [], 0)
                if dr:
                    user_input = sys.stdin.readline().strip()
                    if user_input.lower() == 'p':
                        print(f"{Fore.GREEN}✅ Ожидание пропущено по запросу пользователя.")
                        break
    except ImportError:
        # Если не удалось импортировать необходимые модули
        for remaining in range(seconds, 0, -1):
            print(f"{remaining}/{seconds} секунд", end='\r')
            time.sleep(1)
    print()

def check_last_request_time():
    """Проверяет, прошло ли 60 секунд с последней проверки."""
    if os.path.exists(TIME_FILE):
        with open(TIME_FILE, 'r') as f:
            last_check_str = f.read().strip()
        try:
            last_check_time = datetime.strptime(last_check_str, "%Y-%m-%d %H:%M:%S")
            current_time = datetime.now()
            time_difference = current_time - last_check_time
            if time_difference < timedelta(seconds=TIME_DELAY):
                remaining_time = TIME_DELAY - time_difference.seconds
                print(f"{Fore.YELLOW}⏳ Подождите, перед следующей проверкой должно пройти {remaining_time} секунд.")
                sys.exit(1)
        except ValueError:
            print(f"{Fore.RED}⚠️ Ошибка в формате времени в файле last_check_time.txt. Продолжаем без проверки...")
    else:
        print(f"{Fore.YELLOW}⚠️ Файл last_check_time.txt не найден. Продолжаем проверку...")

def update_last_request_time():
    """Обновляет файл с временем последней проверки."""
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(TIME_FILE, 'w') as f:
        f.write(current_time)

def process_profiles(profiles):
    """Проверяет IP и сохраняет информацию о местоположении."""
    total_profiles = len(profiles)
    processed_profiles = []
    batch = []

    # Загрузка ранее обработанных профилей
    processed_ips = set()
    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE, 'r', encoding='utf-8') as f:
            processed_profiles = f.read().splitlines()
            for profile in processed_profiles:
                ip = extract_ip_from_profile(profile)
                if ip:
                    processed_ips.add(ip)

    check_last_request_time()

    for index, profile in enumerate(profiles):
        ip_or_domain = extract_ip_from_profile(profile)
        if not ip_or_domain:
            print(f"{Fore.RED}❌ IP или домен не найден в строке {index + 1}, пропуск...")
            continue

        # Если это домен, пытаемся его разрешить в IP
        if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip_or_domain):
            print(f"{Fore.YELLOW}🌐 Попытка разрешить домен: {ip_or_domain}")
            ip_or_domain_resolved = resolve_domain_to_ip(ip_or_domain)
            if not ip_or_domain_resolved:
                print(f"{Fore.RED}❌ Не удалось разрешить домен в строке {index + 1}, пропуск...")
                continue
            ip_or_domain = ip_or_domain_resolved

        # Проверяем, был ли этот IP уже обработан
        if ip_or_domain in processed_ips:
            print(f"{Fore.CYAN}ℹ️ IP {ip_or_domain} уже обработан ранее, пропуск...")
            continue

        print(f"Проверка IP: {ip_or_domain} (строка {index + 1}/{total_profiles})")
        batch.append({'ip': ip_or_domain, 'profile': profile.strip()})

        if len(batch) == MAX_REQUESTS_PER_MINUTE:
            print(f"{Fore.YELLOW}🚀 Отправка пакета из {MAX_REQUESTS_PER_MINUTE} запросов...")
            process_batch(batch, processed_profiles, processed_ips)
            batch.clear()
            cooldown(TIME_DELAY)

    if batch:
        print(f"{Fore.YELLOW}🚀 Отправка последнего пакета из {len(batch)} запросов...")
        process_batch(batch, processed_profiles, processed_ips)

    # Сохраняем обновлённые профили в кеш-файл
    with open(CACHE_FILE, 'w', encoding='utf-8') as f:
        f.write('\n'.join(processed_profiles))

    print(f"{Fore.GREEN}✅ Проверка завершена. Информация сохранена в '{CACHE_FILE}'.")
    update_last_request_time()
    return processed_profiles

def process_batch(batch, processed_profiles, processed_ips):
    """Обрабатывает пакет из профилей."""
    ips_in_batch = [item['ip'] for item in batch]
    batch_results = process_ip_batch(ips_in_batch)
    for item in batch:
        ip = item['ip']
        location = batch_results[ip]
        new_name = f"{location}, {ip}"

        profile = item['profile']

        if profile.startswith("vmess://"):
            vmess_data = decode_vmess(profile)
            if vmess_data:
                vmess_data["ps"] = new_name
                updated_profile = encode_vmess(vmess_data)
            else:
                updated_profile = profile
        else:
            updated_profile = re.sub(r'#.*$', f'#{new_name}', profile)

        processed_profiles.append(updated_profile)
        processed_ips.add(ip)

def process_ip_batch(ips):
    """Обрабатывает пакет из IP-адресов."""
    results = {}
    while True:
        rate_limit_exceeded = False
        for ip in ips:
            location = get_location(ip)
            if location == "RATE_LIMIT_EXCEEDED":
                rate_limit_exceeded = True
                break
            results[ip] = location
        if rate_limit_exceeded:
            print(f"{Fore.RED}⚠️ Превышен лимит запросов к API. Ожидание 60 секунд...")
            cooldown(TIME_DELAY)
            update_last_request_time()
            continue  # Повторяем пакет после ожидания
        else:
            break  # Пакет обработан успешно
    return results

def update_profiles(processed_profiles):
    """Сохраняет обновлённые профили."""
    with open('updated_profiles.txt', 'w', encoding='utf-8') as f:
        f.write('\n'.join(processed_profiles))

    print(f"{Fore.GREEN}✅ Обновлённые профили сохранены в 'updated_profiles.txt'.")

    # Предлагаем скопировать в буфер обмена
    print("\nХотите скопировать обновленные профили в буфер обмена?")
    print("1. Да")
    print("2. Нет")
    copy_choice = input("Введите номер действия (1 или 2): ").strip()
    if copy_choice == '1':
        pyperclip.copy('\n'.join(processed_profiles))
        print(f"{Fore.GREEN}✅ Обновленные профили скопированы в буфер обмена.")
    else:
        print(f"{Fore.YELLOW}⚠️ Профили не скопированы в буфер обмена.")

def main():
    print(f"{Fore.CYAN}🚀 Запуск программы обновления профилей V2Ray...")
    profiles_path = "profiles.txt"

    if not os.path.isfile(profiles_path):
        print(f"{Fore.RED}❌ Ошибка: Файл '{profiles_path}' не найден.")
        sys.exit(1)

    profiles = extract_profiles(profiles_path)
    processed_profiles = process_profiles(profiles)

    # После обработки сразу обновляем профили
    update_profiles(processed_profiles)

if __name__ == "__main__":
    main()