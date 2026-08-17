from fastapi.testclient import TestClient
from main import app

client = TestClient(app)


def test_large_request_is_rejected_safely():
    large_command = "A" * 1_200_000

    payload = {
        "rule": {
            "name": "Huge Alert Test",
            "severity": "high",
            "risk_score": 90
        },
        "host": {
            "name": "WIN-TEST-01"
        },
        "user": {
            "name": "user"
        },
        "process": {
            "name": "powershell.exe",
            "command_line": large_command,
            "parent": {
                "name": "winword.exe"
            }
        },
        "event": {
            "category": ["process"],
            "action": "start"
        }
    }

    response = client.post("/score-alert/full", json=payload)

    assert response.status_code in [413, 422]