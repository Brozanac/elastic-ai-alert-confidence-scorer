import json
from pathlib import Path

from ai_explainer import generate_ai_style_explanation
from mitre_mapper import map_mitre
from report_generator import generate_next_steps
from scorer import score_alert

SAMPLE_ALERT_DIR = Path(__file__).parent / "sample_alerts"


def load_alert(file_path: Path) -> dict:
    with open(file_path, "r", encoding="utf-8") as file:
        return json.load(file)


def print_demo_result(alert_file: Path) -> None:
    alert = load_alert(alert_file)

    score_result = score_alert(alert)
    mitre_result = map_mitre(alert)
    next_steps = generate_next_steps(score_result, mitre_result)

    explanation = generate_ai_style_explanation(
        alert=alert,
        score_result=score_result,
        mitre_result=mitre_result,
        next_steps=next_steps
    )

    print("\n==========================================")
    print(f"Alert file: {alert_file.name}")
    print("==========================================")
    print(f"Rule: {score_result.get('rule_name')}")
    print(f"Alert Type: {score_result.get('alert_type')}")
    print(f"Host: {score_result.get('host')}")
    print(f"User: {score_result.get('user')}")
    print(f"Score: {score_result.get('score')}/100")
    print(f"Confidence: {score_result.get('confidence')}")
    
    print("\nScore Breakdown:")
    score_breakdown = score_result.get("score_breakdown", {})
    print(f"- Positive Points: {score_breakdown.get('positive_points')}")
    print(f"- Negative Points: {score_breakdown.get('negative_points')}")
    print(f"- Raw Score: {score_breakdown.get('raw_score')}")
    print(f"- Final Score: {score_breakdown.get('final_score')}")

    print("\nScoring Events:")
    scoring_events = score_result.get("scoring_events", [])

    if scoring_events:
        for event in scoring_events:
            points = event.get("points", 0)
            sign = "+" if points > 0 else ""
            component = event.get("component")
            print(f"- {sign}{points} {component}")

            for detail in event.get("details", []):
                print(f"  - {detail}")
    else:
        print("- No scoring events recorded")

    print("\nEvidence:")
    for item in score_result.get("evidence", []):
        print(f"- {item}")

    if not score_result.get("evidence"):
        print("- No strong evidence found")

    print("\nMissing Context:")
    for item in score_result.get("missing_context", []):
        print(f"- {item}")

    if not score_result.get("missing_context"):
        print("- No major missing context")

    print("\nFalse-Positive Notes:")
    for item in score_result.get("false_positive_notes", []):
        print(f"- {item}")

    if not score_result.get("false_positive_notes"):
        print("- No obvious false-positive indicators")

    print("\nMITRE ATT&CK:")
    mappings = mitre_result.get("mappings", [])

    if mappings:
        for mapping in mappings:
            print(
                f"- {mapping.get('technique_id')} — "
                f"{mapping.get('technique_name')} "
                f"({mapping.get('tactic')})"
            )
    else:
        print("- No clear MITRE mapping found")

    print("\nAI-Style Explanation:")
    print(explanation.get("executive_summary"))

    print("\nRecommendation:")
    print(explanation.get("recommendation"))


def main():
    alert_files = sorted(SAMPLE_ALERT_DIR.glob("*.json"))

    if not alert_files:
        print("No sample alerts found.")
        return

    for alert_file in alert_files:
        print_demo_result(alert_file)


if __name__ == "__main__":
    main()
