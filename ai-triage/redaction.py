import re

def redact(text):

    patterns = [
        r'AKIA[0-9A-Z]{16}',
        r'-----BEGIN PRIVATE KEY-----.*?-----END PRIVATE KEY-----',
        r'password=.*',
        r'jwt'
    ]

    for pattern in patterns:
        text = re.sub(
            pattern,
            '[REDACTED]',
            text,
            flags=re.IGNORECASE | re.DOTALL
        )

    return text