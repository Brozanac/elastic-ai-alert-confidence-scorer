import copy
import re
from typing import Any

SENSITIVE_KEYWORDS = {
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "access_token",
    "refresh_token",
    "api_key",
    "apikey",
    "client_secret",
    "private_key",
    "authorization",
    "cookie",
    "session",
    "credential",
    "credentials",
}


SECRET_PATTERNS = [
    # Authorization headers
    re.compile(r"(?i)(authorization\s*[:=]\s*bearer\s+)[A-Za-z0-9._\-]+"),
    re.compile(r"(?i)(authorization\s*[:=]\s*basic\s+)[A-Za-z0-9+/=]+"),

    # Common key=value or key: value secrets
    re.compile(r"(?i)(password\s*[:=]\s*)[^\s,;]+"),
    re.compile(r"(?i)(passwd\s*[:=]\s*)[^\s,;]+"),
    re.compile(r"(?i)(pwd\s*[:=]\s*)[^\s,;]+"),
    re.compile(r"(?i)(token\s*[:=]\s*)[A-Za-z0-9._\-]{8,}"),
    re.compile(r"(?i)(api[_-]?key\s*[:=]\s*)[A-Za-z0-9._\-]{8,}"),
    re.compile(r"(?i)(client[_-]?secret\s*[:=]\s*)[A-Za-z0-9._\-]{8,}"),

    # OpenAI-style API keys
    re.compile(r"sk-[A-Za-z0-9_\-]{20,}"),

    # JWT-like tokens
    re.compile(
        r"\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b"
    ),

    # AWS access key IDs
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),

    # Private key blocks
    re.compile(
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
        re.DOTALL,
    ),
]


def is_sensitive_key(key: str) -> bool:
    normalized_key = key.lower().replace("-", "_")

    if normalized_key in SENSITIVE_KEYWORDS:
        return True

    return any(keyword in normalized_key for keyword in SENSITIVE_KEYWORDS)


def redact_string(value: str) -> str:
    redacted = value

    for pattern in SECRET_PATTERNS:
        if pattern.groups:
            redacted = pattern.sub(r"\1[REDACTED]", redacted)
        else:
            redacted = pattern.sub("[REDACTED]", redacted)

    return redacted


def redact_alert_data(data: Any) -> Any:
    """
    Recursively redacts sensitive values from dictionaries, lists, and strings.

    It handles:
    - sensitive dictionary keys, such as password/api_key/token
    - secrets inside command-line strings
    - authorization headers
    - private key blocks
    - JWT-like tokens
    """

    if isinstance(data, dict):
        redacted_dict = {}

        for key, value in data.items():
            if is_sensitive_key(str(key)):
                redacted_dict[key] = "[REDACTED]"
            else:
                redacted_dict[key] = redact_alert_data(value)

        return redacted_dict

    if isinstance(data, list):
        return [redact_alert_data(item) for item in data]

    if isinstance(data, str):
        return redact_string(data)

    return data


def create_redacted_copy(data: Any) -> Any:
    """
    Creates a defensive copy before redaction so the original alert object
    remains unchanged during scoring.
    """

    copied_data = copy.deepcopy(data)
    return redact_alert_data(copied_data)