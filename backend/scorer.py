from context_loader import load_environment_context

SUSPICIOUS_PROCESSES = [
    "powershell.exe",
    "cmd.exe",
    "wscript.exe",
    "cscript.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "mshta.exe",
    "certutil.exe",
    "bitsadmin.exe"
]

SUSPICIOUS_OFFICE_PARENTS = [
    "winword.exe",
    "excel.exe",
    "outlook.exe",
    "powerpnt.exe"
]



SENSITIVE_PORTS = [
    22,
    23,
    3389,
    445,
    135,
    139,
    5985,
    5986
]


def get_confidence_label(score: int) -> str:
    if score >= 70:
        return "High"
    elif score >= 40:
        return "Medium"
    return "Low"


def is_external_ip(ip_address: str, environment_context: dict | None = None) -> bool:
    if not ip_address:
        return False

    if environment_context is None:
        environment_context = load_environment_context()

    trusted_prefixes = environment_context.get("trusted_internal_subnets", [])

    return not any(ip_address.startswith(prefix) for prefix in trusted_prefixes)


def detect_alert_type(alert: dict) -> str:
    event = alert.get("event", {})
    process = alert.get("process", {})
    file = alert.get("file", {})
    network = alert.get("network", {})
    rule = alert.get("rule", {})

    event_categories = event.get("category", [])
    rule_name = rule.get("name", "").lower()

    if "authentication" in event_categories:
        return "authentication"

    if process:
        return "process_execution"

    if network or "network" in event_categories:
        return "network"

    if file or "malware" in rule_name or "ransomware" in rule_name:
        return "file_or_malware"

    if "privilege" in rule_name or "escalation" in rule_name or "admin" in rule_name:
        return "privilege_escalation"

    return "unknown"


def apply_global_rule_scoring(rule: dict, evidence: list) -> int:
    score = 0

    severity = rule.get("severity", "").lower()
    risk_score = rule.get("risk_score")

    if severity in ["critical"]:
        score += 20
        evidence.append("Rule severity is critical")
    elif severity in ["high"]:
        score += 15
        evidence.append("Rule severity is high")
    elif severity in ["medium"]:
        score += 5
        evidence.append("Rule severity is medium")

    if isinstance(risk_score, int) and risk_score >= 70:
        score += 10
        evidence.append(f"Rule risk score is high: {risk_score}")
    elif isinstance(risk_score, int) and risk_score >= 40:
        score += 5
        evidence.append(f"Rule risk score is moderate: {risk_score}")

    return score


def score_process_execution_alert(
    process: dict,
    destination: dict,
    evidence: list,
    missing_context: list
) -> int:
    score = 0

    parent = process.get("parent", {})

    process_name = process.get("name", "").lower()
    command_line = process.get("command_line", "").lower()
    parent_name = parent.get("name", "").lower()
    destination_ip = destination.get("ip")

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

    return score


def score_authentication_alert(
    event: dict,
    host_name: str,
    source: dict,
    evidence: list,
    missing_context: list
) -> int:
    score = 0

    event_action = event.get("action", "").lower()
    event_outcome = event.get("outcome", "").lower()
    event_categories = event.get("category", [])
    source_ip = source.get("ip")

    failed_login_detected = (
        "authentication" in event_categories
        and (
            "failed" in event_action
            or "failure" in event_action
            or event_outcome == "failure"
        )
    )

    if failed_login_detected:
        score += 25
        evidence.append("Failed authentication activity detected")

    environment_context = load_environment_context()

    if source_ip and is_external_ip(source_ip, environment_context):
        score += 10
        evidence.append(f"External source IP observed: {source_ip}")

    if host_name and "vpn" in host_name.lower():
        score += 10
        evidence.append("Authentication activity targeted a VPN-related host")

    if not source_ip:
        score -= 10
        missing_context.append("Missing source IP")

    if "authentication" not in event_categories:
        score -= 10
        missing_context.append("Missing authentication event category")

    if not event_action and not event_outcome:
        score -= 10
        missing_context.append("Missing authentication action or outcome")

    return score


def score_network_alert(
    source: dict,
    destination: dict,
    network: dict,
    evidence: list,
    missing_context: list
) -> int:
    score = 0
    environment_context = load_environment_context()

    source_ip = source.get("ip")
    destination_ip = destination.get("ip")
    destination_port = destination.get("port")
    protocol = network.get("protocol", "").lower()

    if source_ip and is_external_ip(source_ip, environment_context):
        score += 10
        evidence.append(f"External source IP observed: {source_ip}")

    if destination_ip:
        score += 10
        evidence.append(f"Destination IP observed: {destination_ip}")

    if destination_port in SENSITIVE_PORTS:
        score += 15
        evidence.append(f"Connection to sensitive port observed: {destination_port}")

    if protocol:
        score += 5
        evidence.append(f"Network protocol observed: {protocol}")

    if not source_ip:
        score -= 10
        missing_context.append("Missing source IP")

    if not destination_ip:
        score -= 10
        missing_context.append("Missing destination IP")

    if not destination_port:
        missing_context.append("Missing destination port")

    return score


def score_file_or_malware_alert(
    file: dict,
    evidence: list,
    missing_context: list
) -> int:
    score = 0

    file_name = file.get("name", "").lower()
    file_path = file.get("path", "")
    file_hash = file.get("hash", {})
    sha256 = file_hash.get("sha256")

    suspicious_extensions = [
        ".exe",
        ".dll",
        ".ps1",
        ".vbs",
        ".js",
        ".hta",
        ".scr"
    ]

    if any(file_name.endswith(extension) for extension in suspicious_extensions):
        score += 15
        evidence.append(f"Suspicious file extension observed: {file_name}")

    if file_path:
        score += 5
        evidence.append(f"File path is present: {file_path}")

    if sha256:
        score += 10
        evidence.append("File SHA256 hash is present")

    if not file_name:
        score -= 10
        missing_context.append("Missing file name")

    if not sha256:
        missing_context.append("Missing file SHA256 hash")

    return score


def score_privilege_escalation_alert(
    rule: dict,
    user: dict,
    evidence: list,
    missing_context: list
) -> int:
    score = 0

    rule_name = rule.get("name", "").lower()
    user_name = user.get("name")

    if "privilege" in rule_name or "escalation" in rule_name:
        score += 25
        evidence.append("Rule name suggests possible privilege escalation")

    if user_name:
        score += 5
        evidence.append(f"User context is present: {user_name}")
    else:
        score -= 10
        missing_context.append("Missing user name")

    return score


def apply_common_missing_context(
    host_name: str,
    user_name: str,
    missing_context: list
) -> int:
    score = 0

    if not host_name:
        score -= 10
        missing_context.append("Missing host name")

    if not user_name:
        score -= 10
        missing_context.append("Missing user name")

    return score


def apply_false_positive_context(
    host_name: str,
    user_name: str,
    process: dict,
    false_positive_notes: list
) -> int:
    score = 0
    environment_context = load_environment_context()

    known_admin_users = environment_context.get("known_admin_users", [])
    known_management_hosts = environment_context.get("known_management_hosts", [])
    known_security_tools = environment_context.get("known_security_tools", [])
    expected_automation_users = environment_context.get("expected_automation_users", [])
    expected_automation_hosts = environment_context.get("expected_automation_hosts", [])

    process_name = process.get("name", "").lower()

    if user_name in known_admin_users:
        score -= 15
        false_positive_notes.append("User is a known admin or automation account from environment context")

    if host_name in known_management_hosts:
        score -= 15
        false_positive_notes.append("Host is a known management server from environment context")

    if process_name in known_security_tools:
        score -= 20
        false_positive_notes.append("Process is a known security tool from environment context")

    if user_name in expected_automation_users and host_name in expected_automation_hosts:
        score -= 15
        false_positive_notes.append("Activity matches expected automation user and host context")

    return score


def score_alert(alert: dict) -> dict:
    score = 0
    evidence = []
    missing_context = []
    false_positive_notes = []

    rule = alert.get("rule", {})
    host = alert.get("host", {})
    user = alert.get("user", {})
    process = alert.get("process", {})
    event = alert.get("event", {})
    source = alert.get("source", {})
    destination = alert.get("destination", {})
    network = alert.get("network", {})
    file = alert.get("file", {})

    rule_name = rule.get("name", "Unknown rule")
    host_name = host.get("name")
    user_name = user.get("name")

    alert_type = detect_alert_type(alert)

    score += apply_global_rule_scoring(rule, evidence)
    score += apply_common_missing_context(host_name, user_name, missing_context)

    if alert_type == "process_execution":
        score += score_process_execution_alert(
            process=process,
            destination=destination,
            evidence=evidence,
            missing_context=missing_context
        )

    elif alert_type == "authentication":
        score += score_authentication_alert(
            event=event,
            host_name=host_name,
            source=source,
            evidence=evidence,
            missing_context=missing_context
        )

    elif alert_type == "network":
        score += score_network_alert(
            source=source,
            destination=destination,
            network=network,
            evidence=evidence,
            missing_context=missing_context
        )

    elif alert_type == "file_or_malware":
        score += score_file_or_malware_alert(
            file=file,
            evidence=evidence,
            missing_context=missing_context
        )

    elif alert_type == "privilege_escalation":
        score += score_privilege_escalation_alert(
            rule=rule,
            user=user,
            evidence=evidence,
            missing_context=missing_context
        )

    else:
        missing_context.append("Unknown alert type; no category-specific scoring applied")

    score += apply_asset_context(
    host_name=host_name,
    evidence=evidence
)

    score += apply_false_positive_context(
        host_name=host_name,
        user_name=user_name,
        process=process,
        false_positive_notes=false_positive_notes
    )

    score = max(0, min(score, 100))

    return {
        "alert_type": alert_type,
        "rule_name": rule_name,
        "host": host_name or "Unknown host",
        "user": user_name or "Unknown user",
        "score": score,
        "confidence": get_confidence_label(score),
        "evidence": evidence,
        "missing_context": missing_context,
        "false_positive_notes": false_positive_notes
    }