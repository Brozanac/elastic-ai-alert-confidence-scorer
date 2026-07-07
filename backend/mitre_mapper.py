def map_mitre(alert: dict) -> dict:
    mappings = []

    process = alert.get("process", {})
    parent = process.get("parent", {})
    event = alert.get("event", {})

    process_name = process.get("name", "").lower()
    command_line = process.get("command_line", "").lower()
    parent_name = parent.get("name", "").lower()

    event_action = event.get("action", "").lower()
    event_categories = event.get("category", [])

    # PowerShell execution
    if process_name == "powershell.exe":
        mappings.append({
            "technique_id": "T1059.001",
            "technique_name": "PowerShell",
            "tactic": "Execution",
            "confidence": "High",
            "reason": "PowerShell process execution was observed."
        })

    # Encoded or obfuscated command
    if "-enc" in command_line or "encodedcommand" in command_line:
        mappings.append({
            "technique_id": "T1027",
            "technique_name": "Obfuscated Files or Information",
            "tactic": "Defense Evasion",
            "confidence": "Medium",
            "reason": "Encoded or obfuscated command-line argument was observed."
        })

    # Office spawning PowerShell
    if parent_name in ["winword.exe", "excel.exe", "outlook.exe", "powerpnt.exe"]:
        mappings.append({
            "technique_id": "T1204",
            "technique_name": "User Execution",
            "tactic": "Execution",
            "confidence": "Medium",
            "reason": "An Office application spawned a suspicious child process."
        })

    # Failed login brute force
    if "authentication" in event_categories and "failed" in event_action:
        mappings.append({
            "technique_id": "T1110",
            "technique_name": "Brute Force",
            "tactic": "Credential Access",
            "confidence": "Medium",
            "reason": "Multiple failed authentication attempts may indicate brute-force activity."
        })

    if not mappings:
        return {
            "mappings": [],
            "mapping_confidence": "Low",
            "summary": "No clear MITRE ATT&CK mapping found from the available alert fields."
        }

    return {
        "mappings": mappings,
        "mapping_confidence": calculate_mapping_confidence(mappings),
        "summary": f"{len(mappings)} MITRE ATT&CK mapping(s) identified."
    }


def calculate_mapping_confidence(mappings: list) -> str:
    if any(mapping["confidence"] == "High" for mapping in mappings):
        return "High"

    if any(mapping["confidence"] == "Medium" for mapping in mappings):
        return "Medium"

    return "Low"