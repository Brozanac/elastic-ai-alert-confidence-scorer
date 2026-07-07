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

def is_external_ip(ip_address: str) -> bool:
    if not ip_address:
        return False

    private_prefixes = [
        "10.",
        "192.168.",
        "172.16.",
        "172.17.",
        "172.18.",
        "172.19.",
        "172.20.",
        "172.21.",
        "172.22.",
        "172.23.",
        "172.24.",
        "172.25.",
        "172.26.",
        "172.27.",
        "172.28.",
        "172.29.",
        "172.30.",
        "172.31."
    ]

    return not any(ip_address.startswith(prefix) for prefix in private_prefixes)

def get_confidence_label(score: int) -> str:
    if score >= 70:
        return "High"
    elif score >= 40:
        return "Medium"
    return "Low"

def detect_alert_type(alert: dict) -> str:
    event = alert.get("event", {})
    process = alert.get("process", {})
    network = alert.get("network", {})
    rule = alert.get("rule", {})

    event_categories = event.get("category", [])
    rule_name = rule.get("name", "").lower()

    if process:
        return "process_execution"

    if "authentication" in event_categories:
        return "authentication"

    if network or "network" in event_categories:
        return "network"

    if "malware" in rule_name:
        return "file_or_malware"

    return "unknown"

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
    event = alert.get("event", {})
    source = alert.get("source", {})
    alert_type = detect_alert_type(alert)


    rule_name = rule.get("name", "Unknown rule")
    severity = rule.get("severity", "").lower()
    risk_score = rule.get("risk_score")

    host_name = host.get("name")
    user_name = user.get("name")

    process_name = process.get("name", "").lower()
    command_line = process.get("command_line", "").lower()
    parent_name = parent.get("name", "").lower()

    event_action = event.get("action", "").lower()
    event_categories = event.get("category", [])
    source_ip = source.get("ip")

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

        # Authentication-based suspicious indicators

    if "authentication" in event_categories and "failed" in event_action:
        score += 25
        evidence.append("Failed authentication activity detected")

    if source_ip and is_external_ip(source_ip):
        score += 10
        evidence.append(f"External source IP observed: {source_ip}")

    if "vpn" in (host_name or "").lower() and "authentication" in event_categories:
        score += 10
        evidence.append("Authentication activity targeted a VPN-related host")

    # Missing context penalties

    if not host_name:
        score -= 10
        missing_context.append("Missing host name")

    if not user_name:
        score -= 10
        missing_context.append("Missing user name")

    if alert_type == "process_execution":
        if not process_name:
            score -= 10
            missing_context.append("Missing process name")

        if not command_line:
            score -= 10
            missing_context.append("Missing process command line")

        if not parent_name:
            score -= 10
            missing_context.append("Missing parent process")

    if alert_type == "authentication":
        if not source_ip:
            score -= 10
            missing_context.append("Missing source IP")

        if "authentication" not in event_categories:
            score -= 10
            missing_context.append("Missing authentication event category")
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