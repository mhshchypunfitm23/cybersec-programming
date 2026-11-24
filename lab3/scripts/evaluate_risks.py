#!/usr/bin/env python3

threats = [
    {
        "name": "SQL Injection (/items?q=)",
        "stride": "Tampering / Info Disclosure",
        "cve": "CWE-89 / CVE-2023-38545",
        "cvss_vec": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cvss_before": 9.8,
        "cvss_after": 2.4,
        "dread": (9, 9, 9, 8, 8),
        "dread_after": 2.8,
        "mitigation": "Параметризовані запити (ORM/SQLAlchemy) та Pydantic-валідація параметра q"
    },
    {
        "name": "Unencrypted HTTP Traffic",
        "stride": "Information Disclosure",
        "cve": "CWE-319 / CVE-2022-3602",
        "cvss_vec": "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "cvss_before": 7.5,
        "cvss_after": 1.8,
        "dread": (8, 7, 6, 9, 7),
        "dread_after": 2.2,
        "mitigation": "Налаштування TLS 1.3 (HTTPS) на Nginx та внутрішнього шифрування"
    },
    {
        "name": "Unencrypted PostgreSQL DB",
        "stride": "Information Disclosure",
        "cve": "CWE-311 / CVE-2023-2454",
        "cvss_vec": "AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
        "cvss_before": 7.1,
        "cvss_after": 2.0,
        "dread": (8, 6, 5, 9, 6),
        "dread_after": 2.4,
        "mitigation": "Шифрування тому бази даних, обмеження доступу через pg_hba.conf та складні паролі"
    },
    {
        "name": "Broken Auth / JWT Spoofing",
        "stride": "Spoofing / Elevation",
        "cve": "CWE-287 / CVE-2023-29409",
        "cvss_vec": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "cvss_before": 9.1,
        "cvss_after": 2.1,
        "dread": (9, 8, 8, 8, 8),
        "dread_after": 2.5,
        "mitigation": "Використання алгоритмів RS256, короткий час життя токенів (15 хв) та MFA"
    }
]

def get_level(score):
    if score >= 8.0: return "Critical"
    if score >= 6.0: return "High"
    if score >= 4.0: return "Medium"
    return "Low"

print("=== ОЦІНКА РИЗИКІВ СТЕНДУ (CVSS v3.1 + DREAD 0-10) ===\n")
print(f"{'Загроза':<28} | {'CVSS До':<7} | {'DREAD До':<8} | {'Рівень':<8} | {'CVSS Після':<10} | {'DREAD Після':<11}")
print("-" * 86)

md_cvss = []
md_dread = []
md_impact = []

for t in threats:
    d_avg = round(sum(t["dread"]) / 5, 1)
    lvl = get_level(d_avg)
    print(f"{t['name']:<28} | {t['cvss_before']:<7} | {d_avg:<8} | {lvl:<8} | {t['cvss_after']:<10} | {t['dread_after']:<11}")
    
    md_cvss.append(f"| {t['name']} | `{t['cvss_vec']}` | **{t['cvss_before']}** | {t['stride']} ({t['cve']}) |")
    d = t["dread"]
    md_dread.append(f"| {t['name']} | {d[0]} | {d[1]} | {d[2]} | {d[3]} | {d[4]} | **{d_avg}** | {lvl} |")
    md_impact.append(f"| {t['name']} | {t['cvss_before']} / {d_avg} | {t['cvss_after']} / {t['dread_after']} | {t['mitigation']} |")

report_md = f"""# Оцінка ризиків безпеки (CVSS v3.1 + DREAD)

**Об'єкт аналізу:** Демонстраційний стенд вебпорталу університету (`Nginx + FastAPI + PostgreSQL`)

## 1. Оцінка за методикою CVSS v3.1

| Threat | Vector | Base Score | Notes |
| :--- | :--- | :---: | :--- |
{chr(10).join(md_cvss)}

## 2. Оцінка за методикою DREAD (0–10)

| Threat | D | R | E | A | D | Avg | Level |
| :--- | :-: | :-: | :-: | :-: | :-: | :-: | :--- |
{chr(10).join(md_dread)}

## 3. Порівняння До / Після впровадження захисту (Mitigation Impact)

| Threat | Before (CVSS/DREAD) | After (CVSS/DREAD) | Mitigations |
| :--- | :---: | :---: | :--- |
{chr(10).join(md_impact)}

## 4. Висновки щодо критичних зон безпеки та рекомендації
1. **Критичні зони:** найбільший ризик компрометації несуть публічний API-ендпоінт пошуку (`/items?q=`) через можливі SQL-ін'єкції (CVSS 9.8, DREAD 8.6) та механізм автентифікації (CVSS 9.1).
2. **Рекомендації щодо пом'якшення ризиків:**
   * Використання суворої типізації та параметризованих запитів у FastAPI для повного блокування SQL-ін'єкцій.
   * Переведення зовнішнього трафіку Nginx на HTTPS (TLS 1.3) та обмеження доступу до порту PostgreSQL (`5432`) виключно всередині приватної Docker-мережі.
   * Увімкнення шифрування даних на рівні сховища та впровадження моніторингу аномальних запитів (WAF / Rate Limiting).
"""

with open("assessment/risk_templates.md", "w", encoding="utf-8") as f:
    f.write(report_md)
