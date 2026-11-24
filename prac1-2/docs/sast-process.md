# SAST: процес керування та результати

1. **Автоматизація в CI:** статичний аналіз (`semgrep`, `bandit`, `pip-audit`) налаштовано через `.github/workflows/sast.yml` для перевірки коду при кожному `push` або `Pull Request`.
2. **Первинне локальне сканування (`bandit_before.txt`):** виявлено 3 вразливості у `src/app.py` (1 High — `B201: flask_debug_true`; 2 Medium — `B608: SQL injection`, `B104: bind all interfaces`).
3. **Тріаж та виправлення:** критичні й середні знахідки взято в роботу першочергово, виправлено у коді `src/app.py` та `src/db.py`.
4. **Повторне сканування (`bandit_after.txt`):** підтверджено повне усунення вразливостей (`Total issues identified: 0`).
