import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
BACKEND_DIR = PROJECT_ROOT / "backend"

sys.path.insert(0, str(BACKEND_DIR))

from redaction import create_redacted_copy, redact_string


def test_redact_string_masks_common_secrets():
    value = (
        "api_key=sk-test12345678901234567890 "
        "password=SuperSecret123 "
        "token=eyJhbGciOiJIUzI1NiJ9.fake.fake"
    )

    redacted = redact_string(value)

    assert "sk-test12345678901234567890" not in redacted
    assert "SuperSecret123" not in redacted
    assert "eyJhbGciOiJIUzI1NiJ9.fake.fake" not in redacted
    assert "[REDACTED]" in redacted


def test_redact_sensitive_dictionary_keys():
    alert = {
        "authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.fake.fake",
        "api_key": "sk-test12345678901234567890",
        "nested": {
            "password": "SuperSecret123"
        }
    }

    redacted = create_redacted_copy(alert)

    assert redacted["authorization"] == "[REDACTED]"
    assert redacted["api_key"] == "[REDACTED]"
    assert redacted["nested"]["password"] == "[REDACTED]"


def test_redaction_does_not_mutate_original_data():
    alert = {
        "api_key": "sk-test12345678901234567890"
    }

    redacted = create_redacted_copy(alert)

    assert alert["api_key"] == "sk-test12345678901234567890"
    assert redacted["api_key"] == "[REDACTED]"