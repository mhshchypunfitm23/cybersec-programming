# ЛР №6. Розробка безпечного клієнт-серверного застосунку з використанням SSL/TLS

## 1. Архітектура та криптографічні параметри
* **Сервер (`server.py`):** асинхронний TCP/TLS-сервер (`asyncio` + `ssl`) на `127.0.0.1:8443`, мінімальна версія протоколу `TLSv1.2` (активний шифр `TLSv1.3 / TLS_AES_256_GCM_SHA384`).
* **Інфраструктура відкритих ключів (PKI):** локальний кореневий центр сертифікації (`Lab6-Root-CA`) та підписаний сертифікат сервера X.509 v3 (`CN=localhost`, `SAN=DNS:localhost, IP:127.0.0.1`).
* **Автентифікація та контроль цілісності:** перевірка облікових даних за допомогою `bcrypt`, видача сесійного токена (`secrets.token_hex(16)`) та підпис кожного повідомлення прикладного рівня кодом автентифікації **HMAC-SHA256**.
* **Журналювання та аудит (`analyze_logs.py`, `logs/server.jsonl`):** реєстрація всіх TLS-рукостискань, успішних і невдалих спроб входу, перевірок HMAC та помилок з'єднання у форматі JSON Lines.

## 2. Запуск
```bash
python3 server.py --host 127.0.0.1 --port 8443 --cert certs/server.crt --key certs/server.key --ca certs/ca.crt
python3 client.py --host 127.0.0.1 --port 8443 --ca certs/ca.crt --user alice --password secret --msg "hello TLS"
python3 analyze_logs.py logs/server.jsonl
```
