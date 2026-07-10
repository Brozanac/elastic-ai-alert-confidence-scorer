import json
from pathlib import Path

DEFAULT_CONTEXT = {
    "known_admin_users": [],
    "known_management_hosts": [],
    "known_security_tools": [],
    "trusted_internal_subnets": [
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
    ],
    "critical_assets": [],
    "expected_automation_users": [],
    "expected_automation_hosts": []
}


CONTEXT_FILE = Path(__file__).parent / "config" / "environment_context.json"


def load_environment_context() -> dict:
    """
    Loads environment-specific SOC context from JSON.

    If the file does not exist or contains invalid JSON, the scorer still works
    with a safe default context.
    """

    if not CONTEXT_FILE.exists():
        return DEFAULT_CONTEXT

    try:
        with open(CONTEXT_FILE, "r", encoding="utf-8") as file:
            loaded_context = json.load(file)

        return merge_with_defaults(loaded_context)

    except json.JSONDecodeError:
        return DEFAULT_CONTEXT


def merge_with_defaults(loaded_context: dict) -> dict:
    context = DEFAULT_CONTEXT.copy()

    for key, value in loaded_context.items():
        context[key] = value

    return context