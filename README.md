# V2ray-checker-region-IP-VLESS-VMESS-SS-Trojan
Автоматическое обновление профилей V2Ray с информацией о местоположении IP

# 🌐 V2Ray Profile Updater

Добро пожаловать в **V2Ray Profile Updater** — инструмент для автоматической проверки и обновления названий профилей V2Ray на основании данных о местоположении IP-адресов! 🛠

## 📋 Описание

Проект состоит из двух основных скриптов:

1. **`update_profiles.py`** — проверяет IP-адреса из файла `profiles.txt` через API [ip-api.com](http://ip-api.com/json) и сохраняет информацию о местоположении в `ip_info.json`.
2. **`update_v2ray_profiles.py`** — обновляет названия профилей V2Ray в зависимости от данных о местоположении IP-адресов из файла `ip_info.json`.

## 🚀 Как использовать


### Шаг 1: Установка Python

Убедитесь, что Python установлен на вашем компьютере. Для проверки введите команду в терминале:


```
python --version
```


Если Python не установлен, скачайте его с официального сайта python.org.


### Шаг 2: Скачивание и установка проекта
Клонируйте репозиторий с GitHub:

```
git clone https://github.com/ВАШ_ЮЗЕРНЕЙМ/v2ray-profile-updater.git
```

Перейдите в директорию проекта:

```
cd v2ray-profile-updater
```


### Шаг 3: Использование скрипта для проверки IP
Отредактируйте файл profiles.txt, добавив в него ваши профили V2Ray.

Запустите проверку IP-адресов:

Для Windows используйте Drag-and-Drop:

Перетащите файл update_profiles.py на Start.bat.
Для Linux/MacOS запустите скрипт командой:


```
python update_profiles.py
```


После выполнения в файле ip_info.json будут сохранены результаты проверки.



### Шаг 4: Обновление названий профилей
Запустите скрипт для обновления названий профилей:
bash
Копировать код
python update_v2ray_profiles.py
Обновлённые профили будут сохранены в файл updated_profiles.txt.
📄 Пример профиля


```
ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTphOGJ0OWZZMFFzTFM2ZUxuWFVlMFlt@193.29.139.215:8080#Germany, Berlin, 193.29.139.215
```


🛠 Файлы проекта
profiles.txt — исходные профили V2Ray.
ip_info.json — результаты проверки IP-адресов.
updated_profiles.txt — обновлённые профили с новыми именами.
update_profiles.py — скрипт для проверки IP.
update_v2ray_profiles.py — скрипт для обновления названий профилей.
📢 Контакт
Если у вас есть вопросы, не стесняйтесь обращаться! 🤝
