import re


def redact(text):
    if text is None:
        return ""

    patterns = [
        r"AKIA[0-9A-Z]{16}",
        r"ASIA[0-9A-Z]{16}",
        r"(?i)aws[_-]?secret[_-]?access[_-]?key[=: ]['\"]?[A-Za-z0-9/+=]{40}",
        r"(?i)gh[pousr]_[A-Za-z0-9]{20,}",
        r"(?i)github_pat_[A-Za-z0-9_]{20,}",
        r"(?i)xox[baprs]-[A-Za-z0-9-]{10,}",
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----.*?-----END (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----",
        r"(?i)api[_-]?key[=: ]['\"]?[A-Za-z0-9_\-]{16,}['\"]?",
        r"(?i)secret[=: ]['\"]?[A-Za-z0-9_\-]{16,}['\"]?",
        r"(?i)token[=: ]['\"]?[A-Za-z0-9_\-]{20,}['\"]?",
        r"(?i)jwt[=: ]['\"]?[A-Za-z0-9\-._~+/=]{10,}['\"]?",
    ]

    redacted = text
    for pattern in patterns:
        redacted = re.sub(pattern, "[REDACTED]", redacted, flags=re.IGNORECASE | re.DOTALL)

    return redacted
