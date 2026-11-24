# Risk Assessment Templates (CVSS v3.1 + DREAD)

## CVSS v3.1 (приклад запису)
| Threat | Vector | Base Score | Notes |
|---|---|---:|---|
| SQL Injection | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H | 9.8 | unauthenticated param |

## DREAD (0–10)
| Threat | D | R | E | A | D | Avg | Level |
|---|--:|--:|--:|--:|--:|---:|---|
| SQLi | 9 | 9 | 9 | 8 | 8 | 8.6 | High |

## До/Після (Mitigation Impact)
| Threat | Before (CVSS/DREAD) | After (CVSS/DREAD) | Mitigations |
|---|---|---|---|
| SQLi | 9.8 / 8.6 | 6.5 / 4.2 | prepared statements, input validation, WAF |
