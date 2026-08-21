from fastapi.testclient import TestClient
from main import app

client = TestClient(app)


def test_realistic_elastic_ecs_powershell_alert_scores_successfully():
    alert = {
        "@timestamp": "2026-08-20T08:00:00.000Z",
        "ecs": {
            "version": "9.5.0"
        },
        "event": {
            "kind": "signal",
            "category": ["process"],
            "type": ["start"],
            "action": "process_start",
            "risk_score": 73,
            "risk_score_norm": 73,
            "severity": 73,
            "dataset": "endpoint.events.process",
            "module": "endpoint"
        },
        "rule": {
            "id": "rule-001",
            "name": "Suspicious PowerShell Encoded Command",
            "description": "Detects PowerShell execution with encoded command arguments.",
            "ruleset": "Elastic Security"
        },
        "host": {
            "name": "win-dev-01",
            "os": {
                "type": "windows",
                "name": "Windows 11"
            }
        },
        "user": {
            "name": "ulas"
        },
        "process": {
            "name": "powershell.exe",
            "command_line": "powershell.exe -NoP -W Hidden -enc SQBFAFgA...",
            "parent": {
                "name": "winword.exe"
            }
        },
        "destination": {
            "ip": "185.199.108.133",
            "port": 443
        },
        "network": {
            "transport": "tcp",
            "protocol": "https",
            "direction": "outbound"
        },
        "threat": {
            "framework": "MITRE ATT&CK",
            "tactic": {
                "id": ["TA0002"],
                "name": ["Execution"]
            },
            "technique": {
                "id": ["T1059.001"],
                "name": ["PowerShell"]
            }
        }
    }

    response = client.post("/score-alert/full", json=alert)

    assert response.status_code == 200

    data = response.json()

    assert data["alert_name"] == "Suspicious PowerShell Encoded Command"
    assert data["host"] == "win-dev-01"
    assert data["user"] == "ulas"
    assert "confidence" in data
    assert "mitre_mapping" in data
    assert data["elastic_context"]["ecs_version"] == "9.5.0"
    assert data["elastic_context"]["event_category"] == ["process"]


def test_invalid_ecs_event_category_is_rejected():
    alert = {
        "event": {
            "kind": "event",
            "category": ["totally_invalid_category"],
            "type": ["start"]
        }
    }

    response = client.post("/score-alert/full", json=alert)

    assert response.status_code == 422


def test_invalid_ecs_event_type_is_rejected():
    alert = {
        "event": {
            "kind": "event",
            "category": ["process"],
            "type": ["totally_invalid_type"]
        }
    }

    response = client.post("/score-alert/full", json=alert)

    assert response.status_code == 422


def test_ecs_alert_with_dotted_fields_is_supported():
    alert = {
        "@timestamp": "2026-08-20T08:00:00.000Z",
        "ecs.version": "9.5.0",
        "event.kind": "signal",
        "event.category": ["process"],
        "event.type": ["start"],
        "rule.name": "Suspicious PowerShell Encoded Command",
        "event.risk_score_norm": 73,
        "host.name": "win-dev-01",
        "user.name": "ulas",
        "process.name": "powershell.exe",
        "process.command_line": "powershell.exe -NoP -W Hidden -enc SQBFAFgA...",
        "process.parent.name": "winword.exe",
        "destination.ip": "185.199.108.133",
        "destination.port": 443
    }

    response = client.post("/score-alert/full", json=alert)

    assert response.status_code == 200

    data = response.json()

    assert data["alert_name"] == "Suspicious PowerShell Encoded Command"
    assert data["host"] == "win-dev-01"