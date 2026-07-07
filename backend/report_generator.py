def generate_next_steps(score_result: dict, mitre_result: dict) -> list:
    next_steps = []

    evidence_text = " ".join(score_result.get("evidence", [])).lower()
    missing_context = score_result.get("missing_context", [])

    if "powershell" in evidence_text:
        next_steps.append("Review the full PowerShell command line and decode any encoded command.")
        next_steps.append("Check PowerShell script block logs if available.")
        next_steps.append("Search for the same command line across other hosts.")

    if "office parent" in evidence_text or "winword.exe" in evidence_text:
        next_steps.append("Investigate the parent Office document, including file hash, source, and user interaction.")

    if "failed authentication" in evidence_text:
        next_steps.append("Check whether failed logins were followed by a successful login.")
        next_steps.append("Review source IP reputation and geolocation.")
        next_steps.append("Search for the same source IP targeting other users.")

    if "external source ip" in evidence_text or "network destination" in evidence_text:
        next_steps.append("Review network connections related to the source or destination IP.")

    for item in missing_context:
        if "command line" in item.lower():
            next_steps.append("Collect full process command-line telemetry.")
        if "parent process" in item.lower():
            next_steps.append("Collect parent process information.")
        if "user" in item.lower():
            next_steps.append("Identify the user associated with the activity.")

    if not next_steps:
        next_steps.append("Review the alert manually and collect additional host, user, and process context.")

    return remove_duplicates(next_steps)


def remove_duplicates(items: list) -> list:
    seen = set()
    unique_items = []

    for item in items:
        if item not in seen:
            unique_items.append(item)
            seen.add(item)

    return unique_items


def generate_markdown_report(alert: dict, score_result: dict, mitre_result: dict) -> str:
    lines = []

    lines.append("# Alert Confidence Report")
    lines.append("")

    lines.append("## Alert Summary")
    lines.append(f"- Rule: {score_result.get('rule_name')}")
    lines.append(f"- Host: {score_result.get('host')}")
    lines.append(f"- User: {score_result.get('user')}")
    lines.append(f"- Confidence Score: {score_result.get('score')}/100")
    lines.append(f"- Confidence Level: {score_result.get('confidence')}")
    lines.append("")

    lines.append("## Evidence")
    evidence = score_result.get("evidence", [])

    if evidence:
        for item in evidence:
            lines.append(f"- {item}")
    else:
        lines.append("- No strong evidence found.")

    lines.append("")

    lines.append("## Missing Context")
    missing_context = score_result.get("missing_context", [])

    if missing_context:
        for item in missing_context:
            lines.append(f"- {item}")
    else:
        lines.append("- No major missing context.")

    lines.append("")

    lines.append("## False-Positive Notes")
    false_positive_notes = score_result.get("false_positive_notes", [])

    if false_positive_notes:
        for item in false_positive_notes:
            lines.append(f"- {item}")
    else:
        lines.append("- No obvious false-positive indicators.")

    lines.append("")

    lines.append("## MITRE ATT&CK Mapping")
    mappings = mitre_result.get("mappings", [])

    if mappings:
        for mapping in mappings:
            lines.append(
                f"- {mapping['technique_id']} — {mapping['technique_name']} "
                f"({mapping['tactic']}, confidence: {mapping['confidence']})"
            )
            lines.append(f"  - Reason: {mapping['reason']}")
    else:
        lines.append("- No clear MITRE ATT&CK mapping found.")

    lines.append("")

    lines.append("## Analyst Next Steps")
    next_steps = generate_next_steps(score_result, mitre_result)

    for index, step in enumerate(next_steps, start=1):
        lines.append(f"{index}. {step}")

    lines.append("")

    return "\n".join(lines)