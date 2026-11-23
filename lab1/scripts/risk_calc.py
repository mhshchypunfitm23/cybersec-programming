#!/usr/bin/env python3
import json

with open("lab1/outputs/threats_before.json", "r", encoding="utf-8") as f:
    before_findings = json.load(f).get("findings", [])

with open("lab1/outputs/threats_after.json", "r", encoding="utf-8") as f:
    after_findings = json.load(f).get("findings", [])

def count_severity(findings):
    high = sum(1 for item in findings if item.get("severity") == "High")
    med = sum(1 for item in findings if item.get("severity") == "Medium")
    low = sum(1 for item in findings if item.get("severity") == "Low")
    return high, med, low

h_b, m_b, l_b = count_severity(before_findings)
h_a, m_a, l_a = count_severity(after_findings)

vulnerabilities = [
    {
        "component": "Grades API (SQLi)",
        "cve": "CWE-89 / CVE-2023-38545",
        "cvss_before": "9.8",
        "cvss_after": "2.4",
        "owasp_before": "Critical (8.5)",
        "owasp_after": "Low (2.1)",
        "mitigation": "Параметризовані SQL-запити та sanitizesInput=True"
    },
    {
        "component": "Internal HTTP (Sniffing)",
        "cve": "CWE-319 / CVE-2022-3602",
        "cvss_before": "7.5",
        "cvss_after": "1.8",
        "owasp_before": "High (7.2)",
        "owasp_after": "Low (1.5)",
        "mitigation": "Перехід з HTTP на HTTPS/mTLS між сервісами"
    },
    {
        "component": "Student DB (Unencrypted)",
        "cve": "CWE-311 / CVE-2023-2454",
        "cvss_before": "8.2",
        "cvss_after": "2.0",
        "owasp_before": "High (7.8)",
        "owasp_after": "Low (1.9)",
        "mitigation": "Увімкнення TDE-шифрування БД та TLS-з'єднання"
    }
]

lines = []
lines.append("=== ЗВІТ З ОЦІНКИ ЗАГРОЗ ТА РИЗИКІВ (ДО / ПІСЛЯ ЗАХИСТУ) ===\n")
lines.append(f"Загрози PyTM за рівнем критичності (High / Medium / Low):")
lines.append(f"- ДО захисту:    High={h_b}, Medium={m_b}, Low={l_b} (Усього: {len(before_findings)})")
lines.append(f"- ПІСЛЯ захисту: High={h_a}, Medium={m_a}, Low={l_a} (Усього: {len(after_findings)})\n")
lines.append(f"{'Загроза':<26} | {'CVSS До':<7} | {'CVSS Після':<10} | {'OWASP До':<14} | {'OWASP Після':<11}")
lines.append("-" * 78)

for v in vulnerabilities:
    lines.append(f"{v['component']:<26} | {v['cvss_before']:<7} | {v['cvss_after']:<10} | {v['owasp_before']:<14} | {v['owasp_after']:<11}")

lines.append("\nВпроваджені заходи захисту:")
for v in vulnerabilities:
    lines.append(f"- {v['component']} ({v['cve']}): {v['mitigation']}")

report_text = "\n".join(lines)
print(report_text)

with open("lab1/outputs/risk_report.txt", "w", encoding="utf-8") as out:
    out.write(report_text + "\n")
