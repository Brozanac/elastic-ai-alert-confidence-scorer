import json
import sys

from scorer import score_alert


def load_alert(file_path: str) -> dict:
    with open(file_path, "r", encoding="utf-8") as file:
        return json.load(file)


def print_report(result: dict) -> None:
    print("\n=== Elastic AI Alert Confidence Report ===\n")

    print(f"Rule: {result['rule_name']}")
    print(f"Host: {result['host']}")
    print(f"User: {result['user']}")
    print(f"Confidence Score: {result['score']}/100")
    print(f"Confidence Level: {result['confidence']}")

    print("\nEvidence:")
    if result["evidence"]:
        for item in result["evidence"]:
            print(f"- {item}")
    else:
        print("- No strong evidence found")

    print("\nMissing Context:")
    if result["missing_context"]:
        for item in result["missing_context"]:
            print(f"- {item}")
    else:
        print("- No major missing context")

    print("\nFalse-Positive Notes:")
    if result["false_positive_notes"]:
        for item in result["false_positive_notes"]:
            print(f"- {item}")
    else:
        print("- No obvious false-positive indicators")

    print("\n==========================================\n")


def main():
    if len(sys.argv) != 2:
        print("Usage: python backend/run_day1.py <alert_json_file>")
        sys.exit(1)

    alert_file = sys.argv[1]
    alert = load_alert(alert_file)
    result = score_alert(alert)

    print_report(result)


if __name__ == "__main__":
    main()