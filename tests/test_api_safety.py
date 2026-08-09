from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

def test_saved_history_redacts_secrets():
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
        }
    }

    create_response = client.post("/score-alert/full", json=alert_with_secret)

    assert create_response.status_code == 200

    history_id = create_response.json()["history_id"]

    history_response = client.get(f"/alerts/history/{history_id}")

    assert history_response.status_code == 200

    history_text = str(history_response.json())

    assert "sk-test12345678901234567890" not in history_text
    assert "SuperSecret123" not in history_text
    assert "[REDACTED]" in history_text

def test_cors_allows_local_vite_origin():
    response = client.options(
        "/score-alert/full",
        headers={
            "Origin": "http://127.0.0.1:5173",
            "Access-Control-Request-Method": "POST",
        },
    )

    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "http://127.0.0.1:5173"


def test_cors_rejects_unknown_origin():
    response = client.options(
        "/score-alert/full",
        headers={
            "Origin": "http://evil.example",
            "Access-Control-Request-Method": "POST",
        },
    )

    assert "access-control-allow-origin" not in response.headers