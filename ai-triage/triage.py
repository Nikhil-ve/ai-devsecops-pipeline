import json
import os

print("=== PipelineFortress AI Triage ===")

files = [
    "semgrep.json",
    "trivy.json",
    "image-trivy.json"
]

found = False

for file in files:
    if os.path.exists(file):
        print(f"[FOUND] {file}")
        found = True
    else:
        print(f"[MISSING] {file}")

if not found:
    print("No scanner reports available for analysis")
else:
    print("\nEvidence Based Findings")
    print("- Review HIGH and CRITICAL findings")
    print("- Validate secrets before remediation")
    print("- Human review required")