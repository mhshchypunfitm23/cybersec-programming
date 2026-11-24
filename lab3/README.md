# Лабораторна робота №3: Моделювання загроз та оцінка ризиків

**Об'єкт дослідження:** Демонстраційний стенд вебпорталу університету (`Nginx + FastAPI + PostgreSQL`).

## Склад проєкту
* `docker-compose.yml`, `nginx/nginx.conf`, `api/app/main.py` — демонстраційне трирівневе середовище (Reverse Proxy -> REST API -> БД).
* `diagrams/architecture.txt` — опис логіки взаємодії компонентів, меж довіри та критичних активів.
* `model/pytm_model.py` — модель загроз на Python (`PyTM`) за методологією STRIDE.
* `scripts/collect_env.sh` — скрипт збору конфігурації контейнерів та перевірки працездатності сервісів.
* `scripts/evaluate_risks.py` — Python-скрипт розрахунку оцінок ризиків за шкалами **CVSS v3.1** та **DREAD**.
* `assessment/risk_templates.md` — підсумковий звіт оцінки ризиків до і після впровадження захисних заходів та рекомендації.
* `outputs/` — візуальна діаграма потоків даних (`dfd_architecture.png`), звіт середовища (`env_report.txt`) та JSON-звіт загроз (`threats.json`).

## Запуск
```bash
sudo docker-compose up -d
python3 model/pytm_model.py --dfd | dot -Tpng -o outputs/dfd_architecture.png
python3 scripts/evaluate_risks.py
```
