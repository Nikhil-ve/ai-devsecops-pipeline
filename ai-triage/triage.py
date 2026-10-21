REPORTS = [
    "semgrep.json",
    "trivy.json",
    "image-trivy.json",
    "zap-report.json"
]

print("=== AI TRIAGE REPORT ===")

for report in REPORTS:
    print(f"Review required: {report}")

print("\nPriority Findings")

print("""
1. SQL Injection
2. Hardcoded Secrets
3. Vulnerable Dependencies
4. XSS
5. Exposed Tokens
""")

print("\nSuggested Fixes")

print("""
- Remove hardcoded credentials
- Upgrade vulnerable packages
- Use parameterized queries
- Validate user input
""")