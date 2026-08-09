import requests

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

response = requests.post(
    "http://127.0.0.1:8000/score-alert/full",
    json=payload,
    timeout=10
)

print(response.status_code)
print(response.text)