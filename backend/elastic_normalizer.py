from typing import Any

from ecs_helpers import (as_list, first_present, get_path,
                         normalize_risk_score, normalize_severity)


def normalize_elastic_alert_for_scoring(alert: dict[str, Any]) -> dict[str, Any]:
    """
    Converts a real Elastic/ECS-shaped alert into the simplified shape
    your existing scoring engine already understands.

    This keeps the scoring code stable while making the input realistic.
    """

    rule_name = first_present(
        alert,
        [
            "kibana.alert.rule.name",
            "signal.rule.name",
            "rule.name",
        ],
        default="Unknown Rule"
    )

    rule_id = first_present(
        alert,
        [
            "kibana.alert.rule.uuid",
            "kibana.alert.rule.rule_id",
            "signal.rule.id",
            "signal.rule.rule_id",
            "rule.uuid",
            "rule.id",
        ],
        default=None
    )

    severity = first_present(
        alert,
        [
            "kibana.alert.severity",
            "signal.rule.severity",
            "event.severity",
            "rule.severity",
        ],
        default="unknown"
    )

    risk_score = first_present(
        alert,
        [
            "kibana.alert.risk_score",
            "signal.rule.risk_score",
            "event.risk_score_norm",
            "event.risk_score",
            "rule.risk_score",
        ],
        default=0
    )

    host_name = first_present(
        alert,
        [
            "host.name",
            "host.hostname",
            "observer.hostname",
        ],
        default="unknown"
    )

    user_name = first_present(
        alert,
        [
            "user.name",
            "user.id",
            "source.user.name",
            "destination.user.name",
        ],
        default="unknown"
    )

    process_name = first_present(
        alert,
        [
            "process.name",
            "process.executable",
        ],
        default=None
    )

    process_command_line = first_present(
        alert,
        [
            "process.command_line",
        ],
        default=None
    )

    parent_process_name = first_present(
        alert,
        [
            "process.parent.name",
            "process.parent.executable",
        ],
        default=None
    )

    source_ip = first_present(
        alert,
        [
            "source.ip",
            "client.ip",
        ],
        default=None
    )

    destination_ip = first_present(
        alert,
        [
            "destination.ip",
            "server.ip",
        ],
        default=None
    )

    destination_port = first_present(
        alert,
        [
            "destination.port",
            "server.port",
        ],
        default=None
    )

    source_port = first_present(
        alert,
        [
            "source.port",
            "client.port",
        ],
        default=None
    )

    network_protocol = first_present(
        alert,
        [
            "network.protocol",
            "network.transport",
        ],
        default=None
    )

    event_category = as_list(get_path(alert, "event.category"))
    event_type = as_list(get_path(alert, "event.type"))

    normalized = {
        "rule": {
            "name": rule_name,
            "id": rule_id,
            "severity": normalize_severity(severity),
            "risk_score": normalize_risk_score(risk_score),
        },
        "host": {
            "name": host_name,
            "os": get_path(alert, "host.os", default={}),
        },
        "user": {
            "name": user_name,
        },
        "process": {
            "name": process_name,
            "command_line": process_command_line,
            "parent": {
                "name": parent_process_name,
            },
        },
        "event": {
            "kind": get_path(alert, "event.kind"),
            "category": event_category,
            "type": event_type,
            "action": get_path(alert, "event.action"),
            "outcome": get_path(alert, "event.outcome"),
            "created": get_path(alert, "event.created"),
            "risk_score": normalize_risk_score(get_path(alert, "event.risk_score")),
            "risk_score_norm": normalize_risk_score(get_path(alert, "event.risk_score_norm")),
        },
        "source": {
            "ip": source_ip,
            "port": source_port,
        },
        "destination": {
            "ip": destination_ip,
            "port": destination_port,
        },
        "network": {
            "protocol": network_protocol,
            "direction": get_path(alert, "network.direction"),
        },
        "file": {
            "name": get_path(alert, "file.name"),
            "path": get_path(alert, "file.path"),
            "hash": get_path(alert, "file.hash", default={}),
        },
        "threat": get_path(alert, "threat", default={}),
        "elastic": {
            "timestamp": get_path(alert, "@timestamp"),
            "ecs_version": get_path(alert, "ecs.version"),
            "event_id": get_path(alert, "event.id"),
            "event_dataset": get_path(alert, "event.dataset"),
            "event_module": get_path(alert, "event.module"),
            "original_alert": alert,
        },
    }

    return remove_none_values(normalized)


def remove_none_values(value: Any) -> Any:
    if isinstance(value, dict):
        cleaned = {}

        for key, item in value.items():
            cleaned_item = remove_none_values(item)

            if cleaned_item is not None:
                cleaned[key] = cleaned_item

        return cleaned

    if isinstance(value, list):
        return [remove_none_values(item) for item in value if item is not None]

    return value