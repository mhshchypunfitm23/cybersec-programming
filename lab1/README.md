# Лабораторна робота №1: Моделювання загроз (Threat Modeling as Code)

**Об'єкт дослідження:** Вебпортал особистого кабінету студента (*University Student Portal*).

## Структура проєкту
* `model/portal_tm.py` — опис архітектури системи, меж довіри (Internet, DMZ, Internal Network) та потоків даних на Python (`PyTM`).
* `scripts/collect_env.sh` — Bash-скрипт для перевірки налаштувань безпеки ОС Kali Linux (`ufw`, `auditd`, користувач `student_sec`, порти).
* `scripts/risk_calc.py` — скрипт аналізу виявлених загроз та оцінки ризиків за шкалами **CVSS v3.1** та **OWASP Risk Rating** до і після впровадження захисних заходів.
* `outputs/` — згенеровані діаграми потоків даних (`dfd_before.png`, `dfd_after.png`), JSON-звіти загроз та текстові звіти (`env_report.txt`, `risk_report.txt`).

## Інструкція запуску
```bash
# 1. Збір інформації про налаштування безпеки середовища
./lab1/scripts/collect_env.sh

# 2. Генерація діаграми та аналіз загроз (PyTM)
source .venv/bin/activate
python3 lab1/model/portal_tm.py --dfd | dot -Tpng -o lab1/outputs/dfd_after.png
python3 lab1/model/portal_tm.py --json lab1/outputs/threats_after.json

# 3. Розрахунок ризиків (до / після впровадження захисту)
python3 lab1/scripts/risk_calc.py
```
