# 🌐 V2Ray IP-Region Renamer

**V2Ray IP-Region Renamer** — это инструмент, который автоматически обновляет названия ваших профилей V2Ray на основе местоположения IP-адресов серверов. 📍

## 📋 Что это и зачем нужно?

Когда вы используете клиент V2Ray, у вас может быть множество профилей серверов, и часто бывает сложно понять, где именно находится тот или иной сервер. Этот инструмент решает эту проблему, автоматически добавляя информацию о стране, регионе и городе в название каждого профиля. Это позволяет легко выбрать нужный сервер из списка в вашем клиенте V2Ray.

## 🛠 Что вам понадобится?

- **Компьютер с Windows** (инструкция ниже ориентирована на Windows).
- **Установленный Python** (версия 3.x).
- **Интернет-соединение**.

## 🚀 Как установить и настроить?

### Шаг 1: Проверьте, установлен ли Python

1. **Откройте командную строку (CMD)**:
   - Нажмите комбинацию клавиш `Win + R`.
   - Введите `cmd` и нажмите **Enter**.

2. **Проверьте версию Python**:
   - В командной строке введите:
     ```
     python --version
     ```
   - Если вы увидите версию Python (например, `Python 3.9.7`), значит, Python уже установлен.
   - Если появится сообщение об ошибке или команда не найдена, перейдите к следующему шагу.

### Шаг 2: Установите Python (если не установлен)

1. **Скачайте Python**:
   - Перейдите на официальный сайт: https://www.python.org/downloads/windows/
   - Нажмите на кнопку **Download Python 3.x.x** (где `3.x.x` — последняя версия).

2. **Установите Python**:
   - Запустите скачанный установочный файл.
   - Обязательно поставьте галочку **"Add Python to PATH"** (Добавить Python в PATH).
   - Следуйте инструкциям установщика.

### Шаг 3: Скачайте V2Ray IP-Region Renamer

1. **Скачайте проект**:
   - На странице репозитория нажмите на зелёную кнопку **"Code"**.
   - В выпадающем меню выберите **"Download ZIP"**.

2. **Распакуйте архив**:
   - Найдите скачанный ZIP-файл на вашем компьютере (обычно в папке "Загрузки").
   - Щёлкните по нему правой кнопкой мыши и выберите **"Извлечь всё..."** или **"Extract All..."**.
   - Выберите удобное для вас место для распаковки (например, на рабочем столе).

### Шаг 4: Установите необходимые компоненты

1. **Откройте папку проекта**:
   - Перейдите в папку, куда вы распаковали проект. Вы должны увидеть файлы, такие как `V2Ray_IP-Region-Renamer.py` и `requirements.txt`.

2. **Откройте командную строку в этой папке**:
   - В адресной строке проводника (где отображается путь к папке) щёлкните левой кнопкой мыши.
   - Введите `cmd` и нажмите **Enter**. Откроется командная строка, уже настроенная на эту папку.

3. **Установите зависимости**:
   - В командной строке введите следующую команду и нажмите **Enter**:
     ```
     pip install -r requirements.txt
     ```
   - Подождите, пока все необходимые модули будут установлены.

### Шаг 5: Подготовьте файл с вашими профилями

1. **Создайте файл `profiles.txt`**:
   - В папке проекта щёлкните правой кнопкой мыши по пустому месту.
   - Выберите **"Создать"** > **"Текстовый документ"**.
   - Назовите файл `profiles.txt` (убедитесь, что расширение `.txt` присутствует).

2. **Добавьте ваши профили V2Ray**:
   - Откройте файл `profiles.txt` двойным щелчком левой кнопки мыши.
   - Вставьте туда ваши профили (VMESS, VLESS, Trojan, Shadowsocks), каждый профиль с новой строки.
   - Сохраните файл и закройте его.

## 📝 Как использовать инструмент?

### Шаг 1: Запустите скрипт

1. **В командной строке** (которая уже открыта в папке проекта) введите:
   ```
   python V2Ray_IP-Region-Renamer.py
   ```
   - Нажмите **Enter**.

### Шаг 2: Дождитесь обработки профилей

- Скрипт начнёт обработку ваших профилей:
  - Он будет проверять каждый профиль, извлекать IP-адрес или доменное имя сервера.
  - Определять местоположение сервера (страну, регион, город).
  - Обновлять название профиля, добавляя эту информацию.

- **Примечание**: Сервис, который используется для определения местоположения IP, имеет ограничение — не более 45 запросов в минуту. Поэтому после каждого пакета из 45 профилей скрипт будет ждать 60 секунд.

- **Важно**: Если вы хотите пропустить ожидание (например, если вы сменили свой IP-адрес), вы можете нажать клавишу `P` во время ожидания.

### Шаг 3: Выберите дальнейшее действие

- После завершения обработки скрипт предложит вам выбрать, что делать дальше:

  ```
  Хотите скопировать обновленные профили в буфер обмена?
  1. Да
  2. Нет
  Введите номер действия (1 или 2):
  ```

- **Введите `1`**, чтобы сохранить обновлённые названия профилей в буфер обмена
- **Введите `2`**, чтобы завершить работу и использовать файл с обработанными профилями без копирования в буфер обмена.

### Шаг 4: Получите обновлённые профили

- Если вы выбрали **1**:
  - Обработанные профили будут скопированы в буфер обмена для удобного импорта в ваш клиент V2Ray.
  - В папке проекта появится файл `updated_profiles.txt` - он содержит профили с обновлёнными названиями, включая информацию о местоположении серверов.

- Если вы выбрали **2**:
  - Вы можете использовать файл `updated_profiles.txt`, который содержит обработанные профили в нужном формате.

## 📂 Какие файлы у вас теперь есть?

- **`V2Ray_IP-Region-Renamer.py`** — основной скрипт для обновления профилей.
- **`profiles.txt`** — ваш файл с исходными профилями (вы его создали).
- **`updated_profiles.txt`** — файл с обновлёнными названиями профилей (если вы выбрали обновление).
- **`processed_profiles.txt`** — файл с обработанными профилями (кеш-файл).
- **`requirements.txt`** — файл со списком необходимых компонентов для установки.

## ❓ Часто задаваемые вопросы

### 1. **У меня возникла ошибка при запуске скрипта. Что делать?**

- Убедитесь, что вы правильно установили все необходимые компоненты (см. шаг 4).
- Проверьте, что вы запустили командную строку из папки проекта.
- Убедитесь, что вы используете команду `python V2Ray_IP-Region-Renamer.py`, а не какую-либо другую.

### 2. **Скрипт сообщает об ошибке с сетью или API.**

- Убедитесь, что у вас есть стабильное интернет-соединение.
- Возможно, сервис определения местоположения временно недоступен. Попробуйте запустить скрипт позже.

### 3. **Как импортировать обновлённые профили в клиент V2Ray?**

- Откройте файл `updated_profiles.txt`.
- Скопируйте содержимое файла.
- Вставьте скопированные профили в ваш клиент V2Ray, следуя его инструкциям по импорту.

## ⚠️ Важные заметки

- **Ограничение по количеству запросов**: Сервис для определения местоположения IP имеет ограничение — не более 45 запросов в минуту с одного IP-адреса. Скрипт учитывает это и автоматически ждёт 60 секунд после каждого пакета из 45 запросов. Вы можете пропустить ожидание, если смените свой IP (например, подключитесь к другому Wi-Fi или используйте VPN).

- **Кеширование результатов**: Чтобы сэкономить время и ресурсы, скрипт сохраняет результаты предыдущих проверок в файл `processed_profiles.txt`. При повторном запуске он не будет повторно проверять уже обработанные профили.

## 🤝 Благодарности

Большое спасибо сервису [ip-api.com](http://ip-api.com/json) за предоставление бесплатного API для определения геолокации IP-адресов.
Код проекта был написан благодаря AI ChatBot **ChatGPT 4o** и AI ChatBot **ChatGPT o1-preview** от OpenAI.

---

✨ **Наслаждайтесь удобным обновлением профилей V2Ray! Если у вас есть вопросы или предложения, создавайте обращения в разделе Issues данного репозитория.** ✨

