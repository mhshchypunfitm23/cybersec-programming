# ЛР №3. Моделювання загроз та оцінка ризиків

> Це **поради**, а не інструкція. Можливі неточності; перевіряйте офіційні джерела.

## Склад
- docker-compose.yml — Nginx (8080), FastAPI (8000), PostgreSQL (5432)
- api/app/main.py — простий API (health, items)
- nginx/nginx.conf — reverse proxy
- model/pytm_model.py — базова PyTM‑модель Client→API→DB
- assessment/risk_templates.md — шаблони CVSS і DREAD
- diagrams/architecture.txt — текстова схема
- scripts/collect_env.sh — збір технічних відомостей

## Швидкий старт
```bash
# 1) Запуск сервісів
docker compose up -d

# 2) Перевірка
curl http://localhost:8080/health
curl 'http://localhost:8080/items?q=test'

# 3) PyTM
python3 -m venv .venv && source .venv/bin/activate
pip install pytm==1.6.1
python model/pytm_model.py > outputs/threats.txt
```
