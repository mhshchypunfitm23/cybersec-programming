#!/bin/bash

OUT_FILE="lab1/outputs/env_report.txt"

echo "=== Перевірка середовища Kali Linux ===" > "$OUT_FILE"
echo "Дата: $(date)" >> "$OUT_FILE"
echo "Користувач: $(whoami)" >> "$OUT_FILE"
echo -e "\n--- Статус фаєрволу (UFW) ---" >> "$OUT_FILE"
sudo ufw status verbose >> "$OUT_FILE"

echo -e "\n--- Правила аудиту (auditd) ---" >> "$OUT_FILE"
sudo auditctl -l >> "$OUT_FILE"

echo -e "\n--- Перевірка нового користувача ---" >> "$OUT_FILE"
id student_sec >> "$OUT_FILE"

echo -e "\n--- Відкриті мережеві порти ---" >> "$OUT_FILE"
ss -tuln >> "$OUT_FILE"

echo "Звіт успішно збережено у $OUT_FILE"
