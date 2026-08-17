from fastapi.testclient import TestClient
from main import app

client = TestClient(app)


VALID_ALERT = {
    "rule": {
        "name": "Suspicious PowerShell Encoded Command",
        "severity": "high",
        "risk_score": 73
    },
    "host": {
        "name": "WIN-DEV-01"
    },
    "user": {
        "name": "user"
    },
    "process": {
        "name": "powershell.exe",
        "command_line": "powershell.exe -NoP -W Hidden -enc SQBFAFgA...",
        "parent": {
            "name": "winword.exe"
        }
    },
    "event": {
        "category": ["process"],
        "action": "start"
    },
    "destination": {
        "ip": "185.199.108.133"
    }
}


def test_empty_alert_does_not_crash():
    response = client.post("/score-alert/full", json={})

    assert response.status_code == 200

    data = response.json()

    assert "confidence" in data
    assert "evidence" in data
    assert "missing_context" in data


def test_invalid_top_level_section_is_rejected():
    response = client.post(
        "/score-alert/full",
        json={
            "rule": "this should be an object"
        }
    )

    assert response.status_code == 422


def test_invalid_risk_score_is_rejected():
    response = client.post(
        "/score-alert/full",
        json={
            "rule": {
                "name": "Invalid Risk Score",
                "severity": "high",
                "risk_score": 999
            }
        }
    )

    assert response.status_code == 422


def test_invalid_port_is_rejected():
    response = client.post(
        "/score-alert/full",
        json={
            "rule": {
                "name": "Invalid Port",
                "severity": "medium",
                "risk_score": 50
            },
            "destination": {
                "ip": "10.0.0.5",
                "port": 99999
            }
        }
    )

    assert response.status_code == 422


def test_large_request_is_rejected_safely():
    large_value = "A" * 1_200_000

    response = client.post(
        "/score-alert/full",
        json={
            "rule": {
                "name": "Large Request Test",
                "severity": "high",
                "risk_score": 90
            },
            "extra_large_field": large_value
        }
    )

    assert response.status_code in [413, 422]


def test_html_like_payload_does_not_crash_or_expose_internal_errors():
    response = client.post(
        "/score-alert/full",
        json={
            "rule": {
                "name": "XSS Safety Test",
                "severity": "medium",
                "risk_score": 50
            },
            "host": {
                "name": "WIN-DEV-01"
            },
            "user": {
                "name": "ulas"
            },
            "process": {
                "name": "powershell.exe",
                "command_line": "<img src=x onerror=alert('xss')>",
                "parent": {
                    "name": "winword.exe"
                }
            },
            "event": {
                "category": ["process"],
                "action": "start"
            }
        }
    )

    assert response.status_code == 200

    response_text = str(response.json()).lower()

    assert "<img src=x onerror=alert" not in response_text
    assert "traceback" not in response_text
    assert "exception" not in response_text
    assert "sqlalchemy" not in response_text
    assert "sqlite" not in response_text
    assert "internal server error" not in response_text

    assert response.status_code == 200

    response_text = str(response.json())

    assert "<img src=x onerror=alert" not in response_text


def test_history_requires_api_key_when_configured(monkeypatch):
    monkeypatch.setenv("APP_API_KEY", "test-key")

    response = client.get("/alerts/history")

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid or missing API key."


def test_history_accepts_valid_api_key_when_configured(monkeypatch):
    monkeypatch.setenv("APP_API_KEY", "test-key")

    response = client.get(
        "/alerts/history",
        headers={"X-API-Key": "test-key"}
    )

    assert response.status_code == 200


def test_wrong_history_api_key_is_rejected(monkeypatch):
    monkeypatch.setenv("APP_API_KEY", "test-key")

    response = client.get(
        "/alerts/history",
        headers={"X-API-Key": "wrong-key"}
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid or missing API key."


def test_history_limit_too_large_returns_422(monkeypatch):
    monkeypatch.setenv("APP_API_KEY", "test-key")

    response = client.get(
        "/alerts/history?limit=999999",
        headers={"X-API-Key": "test-key"}
    )

    assert response.status_code == 422


def test_missing_history_record_returns_safe_404(monkeypatch):
    monkeypatch.setenv("APP_API_KEY", "test-key")

    response = client.get(
        "/alerts/history/999999999",
        headers={"X-API-Key": "test-key"}
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "Alert history record not found."

    response_text = str(response.json()).lower()

    assert "sqlite" not in response_text
    assert "sqlalchemy" not in response_text
    assert "traceback" not in response_text
    assert "operationalerror" not in response_text


def test_delete_missing_history_record_returns_safe_404(monkeypatch):
    monkeypatch.setenv("APP_API_KEY", "test-key")

    response = client.delete(
        "/alerts/history/999999999",
        headers={"X-API-Key": "test-key"}
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "Alert history record not found."


def test_saved_history_redacts_secrets(monkeypatch):
    monkeypatch.setenv("APP_API_KEY", "test-key")

    alert_with_secret = {
        "rule": {
            "name": "Suspicious PowerShell With Secret",
            "severity": "high",
            "risk_score": 80
        },
        "host": {
            "name": "WIN-DEV-01"
        },
        "user": {
            "name": "ulas"
        },
        "process": {
            "name": "powershell.exe",
            "command_line": (
                "powershell.exe -Command "
                "\"api_key=sk-test12345678901234567890 "
                "password=SuperSecret123\""
            ),
            "parent": {
                "name": "winword.exe"
            }
        },
        "event": {
            "category": ["process"],
            "action": "start"
        },
        "authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.fake.fake"
    }

    create_response = client.post(
        "/score-alert/full",
        json=alert_with_secret
    )

    assert create_response.status_code == 200

    history_id = create_response.json()["history_id"]

    history_response = client.get(
        f"/alerts/history/{history_id}",
        headers={"X-API-Key": "test-key"}
    )

    assert history_response.status_code == 200

    history_text = str(history_response.json())

    assert "sk-test12345678901234567890" not in history_text
    assert "SuperSecret123" not in history_text
    assert "eyJhbGciOiJIUzI1NiJ9.fake.fake" not in history_text
    assert "[REDACTED]" in history_text


def test_llm_missing_api_key_fails_safely(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    response = client.post("/score-alert/llm-explain", json=VALID_ALERT)

    assert response.status_code == 200

    data = response.json()
    llm_result = data.get("llm_explanation", data)

    assert llm_result["enabled"] is False
    assert "rule-based score is still valid" in llm_result["message"].lower()


def test_security_headers_are_present():
    response = client.get("/health")

    assert response.status_code == 200
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert response.headers["permissions-policy"] == (
        "camera=(), microphone=(), geolocation=()"
    )