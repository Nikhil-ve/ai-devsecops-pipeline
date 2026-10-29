import argparse
import json
from pathlib import Path
import sys


def load_json(path: Path):
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except Exception:
        return None


def walk_for_severities(value, counts):
    if isinstance(value, dict):
        sev = value.get("severity")
        if isinstance(sev, str):
            key = sev.upper()
            if key in counts:
                counts[key] += 1
        for child in value.values():
            walk_for_severities(child, counts)
    elif isinstance(value, list):
        for item in value:
            walk_for_severities(item, counts)


def summarize_reports(reports_dir: Path):
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    files = sorted(reports_dir.rglob("*.json"))
    if not files:
        return counts, []

    for path in files:
        payload = load_json(path)
        if payload is None:
            continue
        walk_for_severities(payload, counts)
    return counts, files


def main():
    parser = argparse.ArgumentParser(description="Policy gate for security scans.")
    parser.add_argument("--reports-dir", required=True, help="Directory with JSON artifacts")
    parser.add_argument("--summary", default="security-report.md", help="Generated summary filename")
    parser.add_argument("--max-critical", type=int, default=0)
    parser.add_argument("--max-high", type=int, default=3)
    parser.add_argument("--max-medium", type=int, default=10)
    args = parser.parse_args()

    reports_dir = Path(args.reports_dir)
    summary_path = Path(args.summary)
    counts, files = summarize_reports(reports_dir)

    if not summary_path.exists():
        print(f"Policy gate failed: required summary file not found: {summary_path}", file=sys.stderr)
        return 1

    violations = []
    if counts["CRITICAL"] > args.max_critical:
        violations.append(f"critical findings {counts['CRITICAL']} exceed limit {args.max_critical}")
    if counts["HIGH"] > args.max_high:
        violations.append(f"high findings {counts['HIGH']} exceed limit {args.max_high}")
    if counts["MEDIUM"] > args.max_medium:
        violations.append(f"medium findings {counts['MEDIUM']} exceed limit {args.max_medium}")

    for path in files:
        if path.name.lower().endswith("gitleaks.json"):
            payload = load_json(path)
            if isinstance(payload, dict):
                findings = payload.get("findings")
                if isinstance(findings, list) and findings:
                    violations.append(f"gitleaks detected {len(findings)} secret findings")

    if violations:
        print("Policy gate failed:")
        for item in violations:
            print(f" - {item}")
        print(f"Report counts: {counts}")
        return 1

    print("Policy gate passed.")
    print(f"Reports scanned: {len(files)}")
    print(f"Severities: {counts}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
