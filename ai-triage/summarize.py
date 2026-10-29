import argparse
import json
import os
import re
from pathlib import Path

from redaction import redact

try:
    from openai import OpenAI
except Exception:  # pragma: no cover - fallback when SDK is not installed
    OpenAI = None

DEFAULT_REPORTS = [
    "semgrep.json",
    "trivy-fs.json",
    "image-trivy.json",
    "gitleaks.json",
    "checkov.json",
    "sbom.json",
    "zap-report.json",
]


def load_report_file(path: Path):
    if not path.exists():
        return None
    try:
        return path.read_text(encoding="utf-8")
    except Exception as exc:  # pragma: no cover - defensive
        return f"Unable to read {path.name}: {exc}"


def collect_reports(reports_dir: Path):
    combined = []
    seen = set()
    for report_name in DEFAULT_REPORTS:
        file_path = reports_dir / report_name
        if file_path.exists():
            contents = load_report_file(file_path)
            if contents is not None:
                combined.append(f"## {report_name}\n{contents[:20000]}")
                seen.add(report_name)

    for child in sorted(reports_dir.rglob("*.json")):
        if child.name in seen:
            continue
        contents = load_report_file(child)
        if contents is not None:
            combined.append(f"## {child.name}\n{contents[:20000]}")

    if not combined:
        raise FileNotFoundError(f"No report files found in {reports_dir}")

    return "\n\n".join(combined)


def summarize_without_ai(report_text: str):
    summary_lines = [
        "# Security Summary",
        "",
        "This summary was generated without an OpenAI API key and should be treated as a best-effort fallback.",
        "",
        "## Highlights",
        "- Security artifacts were collected and redacted before summarization.",
        "- Review the raw scanner outputs for exact findings and CWE mappings.",
        "",
        "## Risk assessment",
        "- High-confidence findings should be triaged first based on exploitability and exposure.",
        "- Secrets, critical vulnerabilities, and internet-exposed services are the highest-priority issues.",
        "",
        "## Evidence",
    ]

    text = redact(report_text)
    severities = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for level in severities:
        severities[level] = len(re.findall(rf"(?i){level}", text))

    summary_lines.append(f"- Critical-like evidence: {severities['critical']}")
    summary_lines.append(f"- High-like evidence: {severities['high']}")
    summary_lines.append(f"- Medium-like evidence: {severities['medium']}")
    summary_lines.append(f"- Low-like evidence: {severities['low']}")
    summary_lines.append("")
    summary_lines.append("## Recommended next steps")
    summary_lines.extend([
        "1. Fix confirmed secrets, exposed credentials, and unsafe environment configuration.",
        "2. Prioritize critical/high vulnerabilities affecting internet-exposed services.",
        "3. Address IaC misconfigurations and insecure container defaults before release.",
        "4. Re-run the security suite after each fix and document the evidence.",
    ])
    return "\n".join(summary_lines)


def build_prompt(report_text: str) -> str:
    return f"""
You are a senior application security engineer.
Review the supplied scanner results and provide a concise triage report.

Rules:
- Do not invent CVEs or vulnerabilities that are not supported by the evidence.
- Clearly separate confirmed issues from likely false positives.
- Highlight any secret exposure or credential leakage.
- Call out whether the risk is likely exploitable in the current deployment context.
- If detection is noisy or low confidence, say so explicitly.

Report requirements:
1. Executive summary
2. Confirmed high-risk issues
3. Likely false positives or noise
4. Risk rating (Low/Moderate/High/Critical)
5. OWASP mapping when obvious
6. Remediation plan with priority order
7. Evidence-based conclusions

Scanner output:
{report_text[:50000]}
"""


def generate_ai_summary(report_text: str):
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key or OpenAI is None:
        return summarize_without_ai(report_text)

    client = OpenAI(api_key=api_key)
    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "user", "content": build_prompt(report_text)},
        ],
        temperature=0.1,
    )
    return response.choices[0].message.content


def main():
    parser = argparse.ArgumentParser(description="Summarize security reports for AI triage.")
    parser.add_argument("--reports-dir", default=".", help="Directory containing the generated security reports.")
    parser.add_argument("--output", default="security-report.md", help="Output markdown file path.")
    args = parser.parse_args()

    reports_dir = Path(args.reports_dir)
    raw_report = collect_reports(reports_dir)
    sanitized_report = redact(raw_report)
    summary = generate_ai_summary(sanitized_report)
    output_path = Path(args.output)
    output_path.write_text(summary, encoding="utf-8")
    print(f"Security summary written to {output_path}")


if __name__ == "__main__":
    main()
