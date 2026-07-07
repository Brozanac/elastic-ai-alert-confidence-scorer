def generate_ai_style_explanation(
    alert: dict,
    score_result: dict,
    mitre_result: dict,
    next_steps: list
) -> dict:
    """
    Generates a safe analyst-friendly explanation.

    Important design choice:
    This function does not invent facts and does not calculate the score.
    It only explains the score using evidence already extracted by the system.
    """

    score = score_result.get("score", 0)
    confidence = score_result.get("confidence", "Unknown")
    rule_name = score_result.get("rule_name", "Unknown rule")
    host = score_result.get("host", "Unknown host")
    user = score_result.get("user", "Unknown user")

    evidence = score_result.get("evidence", [])
    missing_context = score_result.get("missing_context", [])
    false_positive_notes = score_result.get("false_positive_notes", [])
    mitre_mappings = mitre_result.get("mappings", [])

    executive_summary = build_executive_summary(
        rule_name=rule_name,
        host=host,
        user=user,
        score=score,
        confidence=confidence,
        evidence=evidence,
        false_positive_notes=false_positive_notes
    )

    evidence_summary = build_evidence_summary(evidence)
    missing_context_summary = build_missing_context_summary(missing_context)
    false_positive_summary = build_false_positive_summary(false_positive_notes)
    mitre_summary = build_mitre_summary(mitre_mappings)
    recommendation = build_recommendation(confidence, false_positive_notes, missing_context)

    return {
        "executive_summary": executive_summary,
        "evidence_summary": evidence_summary,
        "missing_context_summary": missing_context_summary,
        "false_positive_summary": false_positive_summary,
        "mitre_summary": mitre_summary,
        "recommendation": recommendation,
        "safety_note": "This explanation is based only on extracted alert evidence. It does not invent additional facts or replace analyst review."
    }


def build_executive_summary(
    rule_name: str,
    host: str,
    user: str,
    score: int,
    confidence: str,
    evidence: list,
    false_positive_notes: list
) -> str:
    if confidence == "High":
        return (
            f"The alert '{rule_name}' on host '{host}' for user '{user}' has a high confidence score "
            f"of {score}/100. The alert contains multiple suspicious indicators that support analyst investigation."
        )

    if confidence == "Medium":
        return (
            f"The alert '{rule_name}' on host '{host}' for user '{user}' has a medium confidence score "
            f"of {score}/100. Some suspicious indicators are present, but additional context is needed before reaching a final verdict."
        )

    return (
        f"The alert '{rule_name}' on host '{host}' for user '{user}' has a low confidence score "
        f"of {score}/100. The available evidence is limited or contains possible false-positive indicators."
    )


def build_evidence_summary(evidence: list) -> str:
    if not evidence:
        return "No strong supporting evidence was extracted from the alert."

    if len(evidence) == 1:
        return f"The main supporting evidence is: {evidence[0]}."

    top_evidence = evidence[:3]
    return "The strongest supporting evidence includes: " + "; ".join(top_evidence) + "."


def build_missing_context_summary(missing_context: list) -> str:
    if not missing_context:
        return "No major missing context was identified in the current alert data."

    return (
        "The alert is missing useful investigation context such as: "
        + "; ".join(missing_context)
        + "."
    )


def build_false_positive_summary(false_positive_notes: list) -> str:
    if not false_positive_notes:
        return "No obvious false-positive indicators were identified."

    return (
        "Possible false-positive indicators were found: "
        + "; ".join(false_positive_notes)
        + "."
    )


def build_mitre_summary(mitre_mappings: list) -> str:
    if not mitre_mappings:
        return "No clear MITRE ATT&CK technique was mapped from the available fields."

    mapping_text = []

    for mapping in mitre_mappings:
        technique_id = mapping.get("technique_id", "Unknown ID")
        technique_name = mapping.get("technique_name", "Unknown technique")
        tactic = mapping.get("tactic", "Unknown tactic")
        confidence = mapping.get("confidence", "Unknown confidence")

        mapping_text.append(
            f"{technique_id} — {technique_name} under {tactic} with {confidence.lower()} mapping confidence"
        )

    return "The alert maps to: " + "; ".join(mapping_text) + "."


def build_recommendation(
    confidence: str,
    false_positive_notes: list,
    missing_context: list
) -> str:
    if confidence == "High" and not false_positive_notes:
        return (
            "Treat this as a likely true positive until proven otherwise. "
            "Prioritize investigation and validate the suspicious behavior using host, process, user, and network telemetry."
        )

    if confidence == "High" and false_positive_notes:
        return (
            "Investigate this alert, but review the false-positive indicators before escalation. "
            "The alert has strong suspicious evidence, but some environmental context may reduce severity."
        )

    if confidence == "Medium":
        return (
            "Perform additional triage before escalation. "
            "The alert has suspicious indicators, but the missing context should be collected first."
        )

    return (
        "Do not escalate based only on the current evidence. "
        "Collect additional context and confirm whether the activity is expected in this environment."
    )