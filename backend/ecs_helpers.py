from typing import Any


def get_path(data: dict[str, Any], path: str, default: Any = None) -> Any:
    """
    Reads both nested ECS fields and dotted fields.

    Supports:
      {"process": {"name": "powershell.exe"}}
    and:
      {"process.name": "powershell.exe"}
    """

    if not isinstance(data, dict):
        return default

    if path in data:
        return data[path]

    current: Any = data

    for part in path.split("."):
        if not isinstance(current, dict):
            return default

        if part not in current:
            return default

        current = current[part]

    return current


def first_present(data: dict[str, Any], paths: list[str], default: Any = None) -> Any:
    for path in paths:
        value = get_path(data, path)

        if value is not None:
            return value

    return default


def as_list(value: Any) -> list[Any]:
    if value is None:
        return []

    if isinstance(value, list):
        return value

    return [value]


def lower_string(value: Any) -> str:
    if value is None:
        return ""

    return str(value).lower()


def normalize_severity(value: Any) -> str:
    if value is None:
        return "unknown"

    severity = str(value).lower()

    if severity in {"low", "medium", "high", "critical"}:
        return severity

    return severity


def normalize_risk_score(value: Any) -> int:
    if value is None:
        return 0

    try:
        score = int(float(value))
    except (TypeError, ValueError):
        return 0

    return max(0, min(score, 100))