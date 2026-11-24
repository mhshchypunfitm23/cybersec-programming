# Оцінка ризиків безпеки (CVSS v3.1 + DREAD)

**Об'єкт аналізу:** Демонстраційний стенд вебпорталу університету (`Nginx + FastAPI + PostgreSQL`)

## 1. Оцінка за методикою CVSS v3.1

| Threat | Vector | Base Score | Notes |
| :--- | :--- | :---: | :--- |
| SQL Injection (/items?q=) | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | **9.8** | Tampering / Info Disclosure (CWE-89 / CVE-2023-38545) |
| Unencrypted HTTP Traffic | `AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N` | **7.5** | Information Disclosure (CWE-319 / CVE-2022-3602) |
| Unencrypted PostgreSQL DB | `AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N` | **7.1** | Information Disclosure (CWE-311 / CVE-2023-2454) |
| Broken Auth / JWT Spoofing | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` | **9.1** | Spoofing / Elevation (CWE-287 / CVE-2023-29409) |

## 2. Оцінка за методикою DREAD (0–10)

| Threat | D | R | E | A | D | Avg | Level |
| :--- | :-: | :-: | :-: | :-: | :-: | :-: | :--- |
| SQL Injection (/items?q=) | 9 | 9 | 9 | 8 | 8 | **8.6** | Critical |
| Unencrypted HTTP Traffic | 8 | 7 | 6 | 9 | 7 | **7.4** | High |
| Unencrypted PostgreSQL DB | 8 | 6 | 5 | 9 | 6 | **6.8** | High |
| Broken Auth / JWT Spoofing | 9 | 8 | 8 | 8 | 8 | **8.2** | Critical |

## 3. Порівняння До / Після впровадження захисту (Mitigation Impact)

| Threat | Before (CVSS/DREAD) | After (CVSS/DREAD) | Mitigations |
| :--- | :---: | :---: | :--- |
| SQL Injection (/items?q=) | 9.8 / 8.6 | 2.4 / 2.8 | Параметризовані запити (ORM/SQLAlchemy) та Pydantic-валідація параметра q |
| Unencrypted HTTP Traffic | 7.5 / 7.4 | 1.8 / 2.2 | Налаштування TLS 1.3 (HTTPS) на Nginx та внутрішнього шифрування |
| Unencrypted PostgreSQL DB | 7.1 / 6.8 | 2.0 / 2.4 | Шифрування тому бази даних, обмеження доступу через pg_hba.conf та складні паролі |
| Broken Auth / JWT Spoofing | 9.1 / 8.2 | 2.1 / 2.5 | Використання алгоритмів RS256, короткий час життя токенів (15 хв) та MFA |

## 4. Висновки щодо критичних зон безпеки та рекомендації
1. **Критичні зони:** найбільший ризик компрометації несуть публічний API-ендпоінт пошуку (`/items?q=`) через можливі SQL-ін'єкції (CVSS 9.8, DREAD 8.6) та механізм автентифікації (CVSS 9.1).
2. **Рекомендації щодо пом'якшення ризиків:**
   * Використання суворої типізації та параметризованих запитів у FastAPI для повного блокування SQL-ін'єкцій.
   * Переведення зовнішнього трафіку Nginx на HTTPS (TLS 1.3) та обмеження доступу до порту PostgreSQL (`5432`) виключно всередині приватної Docker-мережі.
   * Увімкнення шифрування даних на рівні сховища та впровадження моніторингу аномальних запитів (WAF / Rate Limiting).
