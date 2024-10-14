import re
import requests
import json
import time
import os
import sys
import base64

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
        print(f"Ошибка при расшифровке VMESS профиля: {e}")
        return None

def encode_vmess(vmess_data):
    """Кодирует VMESS профиль обратно в base64."""
    try:
        json_str = json.dumps(vmess_data, ensure_ascii=False)
        encoded = base64.b64encode(json_str.encode('utf-8')).decode('utf-8')
        return f"vmess://{encoded}"
    except Exception as e:
        print(f"Ошибка при кодировании VMESS профиля: {e}")
        return None

def extract_ip_from_profile(profile):
    """Извлекает IP-адрес из профиля."""
    if profile.startswith("vmess://"):
        vmess_data = decode_vmess(profile)
        if vmess_data and "add" in vmess_data:
            return vmess_data["add"]
    else:
        ip_match = re.search(r'((?:\d{1,3}\.){3}\d{1,3})', profile)
        if ip_match:
            return ip_match.group(0)
    return None

def get_location(ip, cache):
    """Получает местоположение IP через API с использованием кэша."""
    if ip in cache:
        print(f"Используем кэш для IP: {ip}")
        return cache[ip]

    url = f"http://ip-api.com/json/{ip}"
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            if data.get("status") == "success":
                result = f"{data['country']}, {data['regionName']}, {data['city']}"
            else:
                result = "Unknown, Unknown, Unknown"
        else:
            result = "Unknown, Unknown, Unknown"
    except Exception as e:
        print(f"Ошибка соединения: {e}")
        result = "Unknown, Unknown, Unknown"

    cache[ip] = result
    return result

def cooldown(seconds):
    """Отсчитывает время задержки."""
    print("Достигнут лимит в 45 запросов, пауза на 60 секунд...")
    for remaining in range(seconds, 0, -1):
        print(f"Ожидание {remaining} секунд...", end='\r')
        time.sleep(1)
    print()

def process_profiles(profiles):
    """Проверяет IP и сохраняет информацию о местоположении."""
    total_profiles = len(profiles)
    cache = {}
    results = []
    request_count = 0

    for index, profile in enumerate(profiles):
        ip = extract_ip_from_profile(profile)
        if not ip:
            print(f"IP не найден в строке {index + 1}, пропуск...")
            continue

        print(f"Проверка IP: {ip} (строка {index + 1}/{total_profiles})")

        location = get_location(ip, cache)
        results.append({
            "ip": ip,
            "location": f"{location}, {ip}",
            "profile": profile.strip()
        })

        request_count += 1

        if request_count % 45 == 0:
            cooldown(60)

    with open('ip_info.json', 'w', encoding='utf-8') as f:
        json.dump(results, f, ensure_ascii=False, indent=2)

    print("Проверка завершена. Информация сохранена в 'ip_info.json'.")
    return results

def update_profiles(results):
    """Обновляет названия профилей, включая VMESS."""
    updated_profiles = []

    for result in results:
        profile = result["profile"]
        new_name = result["location"]

        if profile.startswith("vmess://"):
            vmess_data = decode_vmess(profile)
            if vmess_data:
                vmess_data["ps"] = new_name
                updated_profile = encode_vmess(vmess_data)
            else:
                updated_profile = profile
        else:
            updated_profile = re.sub(r'#.*$', f'#{new_name}', profile)

        updated_profiles.append(updated_profile)

    with open('updated_profiles.txt', 'w', encoding='utf-8') as f:
        f.write('\n'.join(updated_profiles))

    print("Обновлённые профили сохранены в 'updated_profiles.txt'.")

def wait_for_choice():
    """Ожидает правильного выбора от пользователя бесконечно."""
    while True:
        print("\nВыберите действие:")
        print("1. Обновить названия профилей")
        print("2. Завершить и сохранить только файл 'ip_info.json'")

        choice = input("Введите номер действия (1 или 2): ").strip()

        if choice == "1":
            return 1
        elif choice == "2":
            return 2
        else:
            print("Неверный выбор. Пожалуйста, введите 1 или 2.")

def main():
    profiles_path = "profiles.txt"

    if not os.path.isfile(profiles_path):
        print(f"Ошибка: Файл '{profiles_path}' не найден.")
        sys.exit(1)

    profiles = extract_profiles(profiles_path)
    results = process_profiles(profiles)

    choice = wait_for_choice()

    if choice == 1:
        update_profiles(results)
    elif choice == 2:
        print("Работа завершена. Файл 'ip_info.json' сохранён.")

if __name__ == "__main__":
    main()