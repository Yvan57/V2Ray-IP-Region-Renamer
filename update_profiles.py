import re
import requests
import json
import time
import os
import sys

def extract_profiles(file_path):
    """Извлекает IP и строку профиля из файла."""
    with open(file_path, 'r', encoding='utf-8') as f:
        profiles = f.readlines()

    profile_data = []
    ip_pattern = r"((?:\d{1,3}\.){3}\d{1,3})"

    for index, profile in enumerate(profiles):
        match = re.search(ip_pattern, profile)
        if match:
            ip = match.group(0)
            profile_data.append((ip, profile.strip(), index + 1))

    return profile_data

def get_location(ip, cache):
    """Получает информацию о местоположении IP через API с использованием кэша."""
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

def process_profiles(file_path):
    """Обрабатывает переданный файл профилей."""
    profiles = extract_profiles(file_path)
    total_profiles = len(profiles)
    cache = {}
    results = []

    request_count = 0

    for index, (ip, profile, line_number) in enumerate(profiles):
        print(f"Проверка IP: {ip} (строка {line_number}/{total_profiles})")

        location = get_location(ip, cache)
        results.append({
            "ip": ip,
            "country, region, ip": f"{location}, {ip}"
        })

        request_count += 1

        if request_count % 45 == 0:
            cooldown(60)

    with open('ip_info.json', 'w', encoding='utf-8') as f:
        json.dump(results, f, ensure_ascii=False, indent=2)

    print("Информация о IP успешно сохранена в 'ip_info.json'.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Ошибка: Не указан файл профилей.")
        sys.exit(1)

    file_path = sys.argv[1]
    if not os.path.isfile(file_path):
        print(f"Ошибка: Файл '{file_path}' не найден.")
        sys.exit(1)

    process_profiles(file_path)