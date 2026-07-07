SUSPICIOUS_PROCESSES = [
    "powershell.exe",
    "cmd.exe",
    "wscript.exe",
    "cscript.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "mshta.exe"
]

SUSPICIOUS_OFFICE_PARENTS = [
    "winword.exe",
    "excel.exe",
    "outlook.exe",
    "powerpnt.exe"
]

KNOWN_ADMIN_USERS = [
    "admin-deploy",
    "sccm-admin"
]

KNOWN_MANAGEMENT_HOSTS = [
    "SCCM-01",
    "JUMPBOX-01"
]


def get_confidence_label(score: int) -> str:
    if score >= 70:
        return "High"
    elif score >= 40:
        return "Medium"
    return "Low"


def score_alert(alert: dict) -> dict:
    score = 0
    evidence = []
    missing_context = []
    false_positive_notes = []

    rule = alert.get("rule", {})
    host = alert.get("host", {})
    user = alert.get("user", {})
    process = alert.get("process", {})
    parent = process.get("parent", {})
    destination = alert.get("destination", {})

    rule_name = rule.get("name", "Unknown rule")
    severity = rule.get("severity", "").lower()
    risk_score = rule.get("risk_score")

    host_name = host.get("name")
    user_name = user.get("name")

    process_name = process.get("name", "").lower()
    command_line = process.get("command_line", "").lower()
    parent_name = parent.get("name", "").lower()

    destination_ip = destination.get("ip")

    # Positive suspicious indicators

    if severity in ["high", "critical"]:
        score += 15
        evidence.append(f"Rule severity is {severity}")

    if isinstance(risk_score, int) and risk_score >= 70:
        score += 10
        evidence.append(f"Rule risk score is high: {risk_score}")

    if process_name in SUSPICIOUS_PROCESSES:
        score += 20
        evidence.append(f"Suspicious process executed: {process_name}")

    if "-enc" in command_line or "encodedcommand" in command_line:
        score += 20
        evidence.append("Encoded PowerShell command detected")

    if "-nop" in command_line or "-w hidden" in command_line:
        score += 10
        evidence.append("PowerShell command uses stealthy flags")

    if parent_name in SUSPICIOUS_OFFICE_PARENTS:
        score += 15
        evidence.append(f"Suspicious Office parent process: {parent_name}")

    if destination_ip:
        score += 10
        evidence.append(f"Network destination is present: {destination_ip}")

    # Missing context penalties

    if not host_name:
        score -= 10
        missing_context.append("Missing host name")

    if not user_name:
        score -= 10
        missing_context.append("Missing user name")

    if not process_name:
        score -= 10
        missing_context.append("Missing process name")

    if not command_line:
        score -= 10
        missing_context.append("Missing process command line")

    if not parent_name:
        score -= 10
        missing_context.append("Missing parent process")

    if not destination_ip:
        missing_context.append("Missing destination IP or network context")

    # False-positive indicators

    if user_name in KNOWN_ADMIN_USERS:
        score -= 15
        false_positive_notes.append("User is a known admin or automation account")

    if host_name in KNOWN_MANAGEMENT_HOSTS:
        score -= 15
        false_positive_notes.append("Host is a known management server")

    # Keep score between 0 and 100

    score = max(0, min(score, 100))

    return {
        "rule_name": rule_name,
        "host": host_name or "Unknown host",
        "user": user_name or "Unknown user",
        "score": score,
        "confidence": get_confidence_label(score),
        "evidence": evidence,
        "missing_context": missing_context,
        "false_positive_notes": false_positive_notes
    }