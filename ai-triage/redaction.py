import re

PATTERNS = [
    r"AKIA[0-9A-Z]{16}",
    r"ASIA[0-9A-Z]{16}",
    r"ghp_[A-Za-z0-9]{36}",
    r"github_pat_[A-Za-z0-9_]{20,}",
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
    r"(?i)(password|secret|token)\s*[:=]\s*['\"][^'\"]+['\"]",
    r"(?i)jdbc:[^\s]+",
]

def redact_text(text):
    for pattern in PATTERNS:
        text = re.sub(
            pattern,
            "[REDACTED]",
            text,
            flags=re.IGNORECASE | re.DOTALL
        )
    return text