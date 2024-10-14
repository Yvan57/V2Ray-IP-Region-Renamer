import json
import base64
import re

def load_profiles(file_path):
    """Загружает профили из файла."""
    with open(file_path, 'r', encoding='utf-8') as f:
        return f.readlines()

def load_ip_info(ip_info_path):
    """Загружает данные из ip_info.json."""
    with open(ip_info_path, 'r', encoding='utf-8') as f:
        return json.load(f)

def update_name_in_vmess(profile, new_name):
    """Обновляет имя профиля для Vmess."""
    decoded = base64.b64decode(profile[8:]).decode('utf-8')  # Декодируем base64
    updated = re.sub(r'"ps":\s*".*?",', f'"ps": "{new_name}",', decoded)  # Обновляем поле "ps"
    encoded = base64.b64encode(updated.encode('utf-8')).decode('utf-8')  # Кодируем обратно в base64
    return f"vmess://{encoded}"

def update_profiles(profiles, ip_info):
    """Обновляет названия профилей на основании данных ip_info.json."""
    updated_profiles = []

    for profile in profiles:
        # Извлечение IP из профиля
        ip_match = re.search(r'((?:\d{1,3}\.){3}\d{1,3})', profile)
        if not ip_match:
            updated_profiles.append(profile)  # Пропустить, если IP не найден
            continue

        ip = ip_match.group(0)

        # Поиск соответствующего IP в ip_info.json
        matching_info = next((info for info in ip_info if info["ip"] == ip), None)
        if not matching_info:
            updated_profiles.append(profile)  # Пропустить, если IP не найден в ip_info.json
            continue

        # Формируем новое имя профиля
        new_name = matching_info["country, region, ip"]

        # Обновляем профиль в зависимости от его типа
        if profile.startswith("vmess://"):
            updated_profile = update_name_in_vmess(profile, new_name)
        else:
            # Обновляем имя для других типов протоколов (после символа '#')
            updated_profile = re.sub(r'#.*$', f'#{new_name}', profile)

        updated_profiles.append(updated_profile)

    return updated_profiles

def save_profiles(file_path, profiles):
    """Сохраняет обновлённые профили в файл."""
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(profiles))

if __name__ == "__main__":
    # Пути к файлам
    profiles_path = "profiles.txt"
    ip_info_path = "ip_info.json"
    output_path = "updated_profiles.txt"

    # Загрузка данных
    profiles = load_profiles(profiles_path)
    ip_info = load_ip_info(ip_info_path)

    # Обновление профилей
    updated_profiles = update_profiles(profiles, ip_info)

    # Сохранение обновлённых профилей
    save_profiles(output_path, updated_profiles)

    print("Обновление профилей завершено. Результаты сохранены в 'updated_profiles.txt'.")