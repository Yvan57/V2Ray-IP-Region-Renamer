# Системные библиотеки
import base64  # для кодирования и декодирования профилей
import os  # для работы с файловой системой
import socket  # для разрешения доменных имен в IP
import sys  # для управления завершением программы
import time  # для работы с задержками и замером времени
from datetime import datetime, timedelta  # для работы с датами и временем

# Сетевые библиотеки и HTTP-запросы
import requests  # для выполнения HTTP-запросов к API

# Обработка данных
import json  # для работы с JSON-данными
import re  # для использования регулярных выражений
from urllib.parse import urlparse, unquote, parse_qs  # для разбора URI

# Интерфейс и улучшение взаимодействия с пользователем
import colorama  # для вывода цветного текста в консоли
from colorama import Fore, Style
import pyperclip  # для копирования текста в буфер обмена

colorama.init(autoreset=True)

API_URL = "http://ip-api.com/json/"
MAX_REQUESTS_PER_MINUTE = 45
TIME_DELAY = 60  # Задержка между проверками
TIME_FILE = "LastCheck.txt"  # Файл для хранения времени последней проверки
CACHE_FILE = "ProfilesTemp.txt"  # Кеш-файл для сохранения обработанных профилей
LOG_FILE = "LogCMD.txt"  # Файл для сохранения логов
PROFILES_INPUT_FILE = "ImportProfiles.txt"  # Файл с исходными профилями
PROFILES_OUTPUT_FILE = "ProfilesUpdated.txt"  # Файл для сохранения обновлённых профилей

def log(message):
    print(message)
    with open(LOG_FILE, 'a', encoding='utf-8') as log_file:
        log_file.write(message + '\n')

def get_public_ip():
    """Получает публичный IP-адрес пользователя."""
    try:
        response = requests.get('https://api.ipify.org', timeout=10)
        if response.status_code == 200:
            return response.text.strip()
        else:
            return 'Не удалось получить IP-адрес'
    except Exception as e:
        return f'Ошибка получения IP-адреса: {e}'

def extract_profiles(file_path):
    """Извлекает профили из файла."""
    with open(file_path, 'r', encoding='utf-8') as f:
        return [line.strip() for line in f if line.strip()]

def decode_vmess(vmess_profile):
    """Расшифровывает VMESS профиль из base64."""
    try:
        decoded = base64.b64decode(vmess_profile[8:] + '===').decode('utf-8')
        return json.loads(decoded)
    except Exception as e:
        log(f"{Fore.RED}❌ Ошибка при расшифровке VMESS профиля: {e}")
        return None

def encode_vmess(vmess_data):
    """Кодирует VMESS профиль обратно в base64."""
    try:
        json_str = json.dumps(vmess_data, ensure_ascii=False)
        encoded = base64.b64encode(json_str.encode('utf-8')).decode('utf-8')
        return f"vmess://{encoded}"
    except Exception as e:
        log(f"{Fore.RED}❌ Ошибка при кодировании VMESS профиля: {e}")
        return None

def extract_ip_and_port_from_profile(profile):
    """Извлекает IP-адрес или домен и порт из профиля."""
    ip_or_domain = None
    port = None

    # Отсекаем часть после '#' если она есть
    if '#' in profile:
        profile, _ = profile.split('#', 1)

    if profile.startswith("vmess://"):
        vmess_data = decode_vmess(profile)
        if vmess_data:
            ip_or_domain = vmess_data.get("add")
            port = vmess_data.get("port")
    elif profile.startswith("ss://"):
        # Shadowsocks может иметь часть URI в base64
        try:
            ss_info = profile[5:]
            if '@' in ss_info:
                # URI-формат
                user_info, server_info = ss_info.rsplit('@', 1)
                if ':' in server_info:
                    ip_or_domain, port = server_info.split(':', 1)
                else:
                    ip_or_domain = server_info
                    port = 'default'
            else:
                # SIP002 URI-формат
                # Отсекаем часть после '#' если она есть
                if '#' in ss_info:
                    ss_info, _ = ss_info.split('#', 1)
                decoded_ss_info = base64.urlsafe_b64decode(ss_info + '===').decode('utf-8')
                method_password, server_info = decoded_ss_info.rsplit('@', 1)
                if ':' in server_info:
                    ip_or_domain, port = server_info.split(':', 1)
                else:
                    ip_or_domain = server_info
                    port = 'default'
        except Exception as e:
            log(f"{Fore.RED}❌ Ошибка при разборе Shadowsocks профиля: {e}")
            return None, None
    elif profile.startswith("trojan://") or profile.startswith("vless://"):
        try:
            parsed_url = urlparse(profile)
            ip_or_domain = parsed_url.hostname
            port = parsed_url.port or 'default'
        except Exception as e:
            log(f"{Fore.RED}❌ Ошибка при разборе профиля: {e}")
            return None, None
    else:
        # Попытка извлечь IP/домен и порт из URI
        try:
            parsed_url = urlparse(profile)
            if parsed_url.hostname:
                ip_or_domain = parsed_url.hostname
                port = parsed_url.port or 'default'
            else:
                # Если не удалось распарсить, ищем IP/домен в тексте
                ip_match = re.search(r'((?:\d{1,3}\.){3}\d{1,3}|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', profile)
                if ip_match:
                    ip_or_domain = ip_match.group(0)
                    port = 'default'
        except Exception as e:
            log(f"{Fore.RED}❌ Ошибка при извлечении IP/домена: {e}")
            return None, None
    return ip_or_domain, str(port) if port else 'default'

def resolve_domain_to_ip(domain):
    """Разрешает доменное имя в IP-адрес."""
    try:
        return socket.gethostbyname(domain)
    except Exception as e:
        log(f"{Fore.RED}❌ Не удалось разрешить домен '{domain}': {e}")
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
        log(f"{Fore.RED}❌ Ошибка соединения: {e}")
        return "Unknown, Unknown, Unknown"

def cooldown(seconds, previous_ip, processed_profiles):
    """Отсчитывает время задержки, позволяет прервать ожидание при нажатии 'P'."""
    log(f"{Fore.YELLOW}⏳ Ожидание {seconds} секунд перед следующей отправкой...")
    log("Если вы сменили IP и хотите пропустить ожидание, нажмите 'P'.")
    start_time = time.time()
    ip_changed = False
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
                        new_ip = get_public_ip()
                        log(f"Ваш новый IP-адрес: {new_ip}")
                        if new_ip == previous_ip:
                            log(f"{Fore.RED}❌ IP-адрес не изменился. Ожидание продолжается.")
                            continue
                        else:
                            log(f"{Fore.GREEN}✅ IP-адрес изменился. Ожидание пропущено по запросу пользователя.")
                            ip_changed = True
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
                        new_ip = get_public_ip()
                        log(f"Ваш новый IP-адрес: {new_ip}")
                        if new_ip == previous_ip:
                            log(f"{Fore.RED}❌ IP-адрес не изменился. Ожидание продолжается.")
                            continue
                        else:
                            log(f"{Fore.GREEN}✅ IP-адрес изменился. Ожидание пропущено по запросу пользователя.")
                            ip_changed = True
                            break
    except ImportError:
        # Если не удалось импортировать необходимые модули
        for remaining in range(seconds, 0, -1):
            print(f"{remaining}/{seconds} секунд", end='\r')
            time.sleep(1)
    print()
    # Сохраняем промежуточные результаты при нажатии 'P'
    with open(CACHE_FILE, 'w', encoding='utf-8') as f:
        f.write('\n'.join(processed_profiles))
    return ip_changed

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
                log(f"{Fore.YELLOW}⏳ Подождите, перед следующей проверкой должно пройти {remaining_time} секунд.")
                sys.exit(1)
        except ValueError:
            log(f"{Fore.RED}⚠️ Ошибка в формате времени в файле {TIME_FILE}. Продолжаем без проверки...")
    else:
        log(f"{Fore.YELLOW}⚠️ Файл {TIME_FILE} не найден. Продолжаем проверку...")

def update_last_request_time():
    """Обновляет файл с временем последней проверки."""
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(TIME_FILE, 'w') as f:
        f.write(current_time)

def process_profiles(profiles):
    """Проверяет IP и сохраняет информацию о местоположении."""
    total_profiles = len(profiles)
    processed_profiles = []
    processed_ips = set()
    skipped_profiles = []
    batch = []

    # Очищаем кеш-файл с обработанными профилями
    with open(CACHE_FILE, 'w', encoding='utf-8') as f:
        f.write('')

    # Очищаем лог-файл
    with open(LOG_FILE, 'w', encoding='utf-8') as log_file:
        log_file.write('')

    check_last_request_time()

    # Получаем текущий IP-адрес пользователя
    previous_ip = get_public_ip()
    log(f"Ваш текущий IP-адрес: {previous_ip}")

    # Кеш для хранения местоположений IP
    ip_location_cache = {}

    for index, profile in enumerate(profiles):
        ip_or_domain, port = extract_ip_and_port_from_profile(profile)
        if not ip_or_domain:
            log(f"{Fore.RED}❌ IP или домен не найден в строке {index + 1}, пропуск...")
            continue

        # Если это домен, пытаемся его разрешить в IP
        if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip_or_domain):
            log(f"{Fore.YELLOW}🌐 Попытка разрешить домен: {ip_or_domain}")
            ip_or_domain_resolved = resolve_domain_to_ip(ip_or_domain)
            if not ip_or_domain_resolved:
                log(f"{Fore.RED}❌ Не удалось разрешить домен в строке {index + 1}, пропуск...")
                continue
            ip_or_domain = ip_or_domain_resolved

        # Проверяем, был ли этот IP уже обработан в текущей сессии
        if ip_or_domain in processed_ips:
            log(f"{Fore.CYAN}ℹ️ IP {ip_or_domain} уже обработан, пропуск...")
            skipped_profiles.append(profile.strip())
            continue

        log(f"Проверка IP: {ip_or_domain}:{port} (строка {index + 1}/{total_profiles})")
        batch.append({'ip': ip_or_domain, 'port': port, 'profile': profile.strip()})

        if len(batch) == MAX_REQUESTS_PER_MINUTE:
            log(f"{Fore.YELLOW}🚀 Отправка пакета из {MAX_REQUESTS_PER_MINUTE} запросов...")
            current_ip = get_public_ip()
            log(f"Ваш текущий IP-адрес: {current_ip}")
            process_batch(batch, processed_profiles, processed_ips, ip_location_cache)
            batch.clear()
            # Сохраняем результаты в кеш-файл
            with open(CACHE_FILE, 'w', encoding='utf-8') as f:
                f.write('\n'.join(processed_profiles))
            ip_changed = cooldown(TIME_DELAY, previous_ip, processed_profiles)
            if ip_changed:
                # Обновляем previous_ip
                previous_ip = get_public_ip()
            else:
                # Если ожидание не было пропущено, обновляем время последней проверки
                update_last_request_time()

    if batch:
        log(f"{Fore.YELLOW}🚀 Отправка последнего пакета из {len(batch)} запросов...")
        current_ip = get_public_ip()
        log(f"Ваш текущий IP-адрес: {current_ip}")
        process_batch(batch, processed_profiles, processed_ips, ip_location_cache)

    # Сохраняем обновлённые профили в кеш-файл
    with open(CACHE_FILE, 'w', encoding='utf-8') as f:
        f.write('\n'.join(processed_profiles))

    log(f"{Fore.GREEN}✅ Проверка завершена. Информация сохранена в '{CACHE_FILE}'.")
    update_last_request_time()
    return processed_profiles, skipped_profiles

def process_batch(batch, processed_profiles, processed_ips, ip_location_cache):
    """Обрабатывает пакет из профилей."""
    ips_in_batch = [item['ip'] for item in batch if item['ip'] not in ip_location_cache]
    batch_results = {}

    if ips_in_batch:
        batch_results = process_ip_batch(ips_in_batch)

    for item in batch:
        ip = item['ip']
        port = item['port']
        profile = item['profile']

        # Получаем местоположение из кеша или результатов текущего пакета
        if ip in ip_location_cache:
            location = ip_location_cache[ip]
        else:
            location = batch_results.get(ip, "Unknown, Unknown, Unknown")
            ip_location_cache[ip] = location

        new_name = f"{location}, {ip}"

        if profile.startswith("vmess://"):
            vmess_data = decode_vmess(profile)
            if vmess_data:
                vmess_data["ps"] = new_name
                updated_profile = encode_vmess(vmess_data)
            else:
                updated_profile = profile
        else:
            # Для других типов профилей обновляем имя сервера в конце URI после '#'
            if '#' in profile:
                updated_profile = re.sub(r'#.*', f'#{new_name}', profile)
            else:
                updated_profile = f"{profile}#{new_name}"

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
            log(f"{Fore.RED}⚠️ Превышен лимит запросов к API. Ожидание 60 секунд...")
            cooldown(TIME_DELAY, get_public_ip(), [])
            update_last_request_time()
            continue  # Повторяем пакет после ожидания
        else:
            break  # Пакет обработан успешно
    return results

def update_profiles(processed_profiles, skipped_profiles):
    """Сохраняет обновлённые профили."""
    with open(PROFILES_OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write('\n'.join(processed_profiles))

    log(f"{Fore.GREEN}✅ Обновлённые профили сохранены в '{PROFILES_OUTPUT_FILE}'.")

    # Предлагаем скопировать в буфер обмена
    log("\nХотите скопировать обновленные профили в буфер обмена?")
    log("1. Да")
    log("2. Нет")
    copy_choice = input("Введите номер действия (1 или 2): ").strip()
    if copy_choice == '1':
        pyperclip.copy('\n'.join(processed_profiles))
        log(f"{Fore.GREEN}✅ Обновленные профили скопированы в буфер обмена.")
    else:
        log(f"{Fore.YELLOW}⚠️ Профили не скопированы в буфер обмена.")

    # Вывод пропущенных профилей
    if skipped_profiles:
        log("\nПрофили, которые были пропущены из-за того, что IP уже был обработан:")
        for profile in skipped_profiles:
            log(profile)
    else:
        log("\nНе было пропущенных профилей из-за повторного IP.")

def main():
    log(f"{Fore.CYAN}🚀 Запуск программы обновления профилей V2Ray...")
    profiles_path = PROFILES_INPUT_FILE

    if not os.path.isfile(profiles_path):
        log(f"{Fore.RED}❌ Ошибка: Файл '{profiles_path}' не найден.")
        sys.exit(1)

    profiles = extract_profiles(profiles_path)
    processed_profiles, skipped_profiles = process_profiles(profiles)

    # После обработки сразу обновляем профили
    update_profiles(processed_profiles, skipped_profiles)

if __name__ == "__main__":
    main()