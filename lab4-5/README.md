# ЛР №4-5. Реалізація симетричного шифрування з використанням AES

## 1. Архітектура та криптографічні механізми
* **Управління ключами (`key_manager.py`):** генерація похідних ключів за допомогою **PBKDF2-HMAC-SHA256** (310 000 ітерацій) із використанням криптографічно випадкової солі (`salt`), контролем довжини ключа (128/192/256 біт) та відстеженням ідентифікаторів (`key-id`) для запобігання повторному використанню.
* **Режими шифрування (`crypto_aes.py`):** реалізовано **AES-GCM** (автентифіковане шифрування AEAD із генерацією унікального 96-бітного `nonce` і 128-бітного тегу цілісності) та **AES-CBC + HMAC-SHA256** (із PKCS#7 паддингом та перевіркою MAC за схемою Encrypt-then-MAC).
* **Захист від модифікації (`tamper_demo.py`):** імітація зміни байтів шифртексту або тегу автентифікації підтвердила, що під час спроби розшифрування бібліотека миттєво виявляє порушення цілісності (`InvalidTag`) та блокує виведення пошкоджених даних.
* **Журналювання (`logger_setup.py`, `logs/aes.jsonl`):** реєстрація всіх криптографічних операцій, генерації ключів та помилок автентифікації у форматі JSON.

## 2. Запуск
```bash
python3 aes_cli.py key new --label default --password strongpass
python3 aes_cli.py enc --in data/sample.txt --out outputs/sample.enc --mode gcm --label default --password strongpass
python3 aes_cli.py dec --in outputs/sample.enc --out outputs/sample.dec --mode gcm --label default --password strongpass
python3 aes_cli.py bench --sizes 1MB 5MB --modes cbc gcm --repeat 3 --label default --password strongpass
python3 tamper_demo.py --file outputs/sample.enc
```
