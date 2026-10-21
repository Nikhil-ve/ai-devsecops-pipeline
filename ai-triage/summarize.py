import os
import json
from openai import OpenAI

client = OpenAI(
    api_key=os.environ["OPENAI_API_KEY"]
)

reports = []

files = [
    "semgrep.json",
    "trivy.json",
    "image-trivy.json",
    "gitleaks.json",
    "checkov.json",
    "zap.json"
]

for file in files:
    if os.path.exists(file):
        try:
            with open(file, "r", encoding="utf-8") as f:
                reports.append(f.read())
        except Exception as e:
            print(f"Could not read {file}: {e}")

combined_findings = "\n\n".join(reports)

prompt = f"""
You are a Senior Application Security Engineer.

Analyze the following security scan results and provide:

1. Executive Summary
2. Critical Findings
3. High Findings
4. Medium Findings
5. Risk Rating
6. OWASP Top 10 Mapping
7. Prioritized Remediation Plan
8. Security Score (0-100)

Scan Results:

{combined_findings[:50000]}
"""

response = client.chat.completions.create(
    model="gpt-4o-mini",
    messages=[
        {
            "role": "user",
            "content": prompt
        }
    ]
)

report_content = response.choices[0].message.content

with open("security-report.md", "