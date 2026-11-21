"""Aggregate evidence coverage and matched pilot outcomes without publishing event data."""

from datetime import datetime, timezone
import json

from .evaluation import FULL_REFERENCE, VARIANTS
from .store import status_snapshot


def since_cutoff(value):
    if value is None:
        return "0001-01-01T00:00:00.000000+00:00"
    converted = datetime.fromisoformat(value)
    if converted.utcoffset() is None:
        raise ValueError("--since requires a timezone")
    return converted.astimezone(timezone.utc).isoformat(timespec="microseconds")


def summary(connection, since):
    connection.execute("SAVEPOINT pilot_snapshot")
    try:
        return _summary(connection, since)
    finally:
        connection.execute("RELEASE pilot_snapshot")


def _summary(connection, since):
    anchors, bound = connection.execute(
        """SELECT count(*), coalesce(sum(json_extract(payload, '$.session_key') IS NOT NULL),0)
           FROM events WHERE timestamp>=? AND json_extract(payload, '$.source')='systemd-journal'
           AND json_extract(payload, '$.kind') IN ('ssh_login','ssh_session_open')""",
        (since,),
    ).fetchone()
    denied, unverifiable = connection.execute(
        """SELECT
               coalesce(sum(json_extract(payload,'$.kind')='privilege_denied'),0),
               coalesce(sum(json_extract(payload,'$.kind')='privilege_denial_unverified'),0)
           FROM events WHERE timestamp>=? AND json_extract(payload,'$.source')='systemd-journal'""",
        (since,),
    ).fetchone()
    latest = connection.execute(
        """WITH recent AS (
               SELECT id, payload, row_number() OVER (
                   PARTITION BY json_extract(payload, '$.anchor_id') ORDER BY created DESC, id DESC
               ) AS revision
               FROM runs WHERE created>=?
                   AND json_type(payload,'$.scenario') IS NULL
                   AND json_type(payload,'$.session_attribution')='object'
           )
           SELECT r.payload, o.decision FROM recent r
           LEFT JOIN outcomes o ON o.run_id=r.id WHERE r.revision=1""",
        (since,),
    )
    cases = {"current": 0, "bound": 0, "unbound": 0, "decisions_confirmed": 0,
             "red_forecasts": 0, "red_forecasts_matched": 0}
    metrics = {
        variant: {"checked": 0, "correct": 0, "false_escalations": 0, "missed_escalations": 0}
        for variant in (*VARIANTS, FULL_REFERENCE, "recommendation")
    }
    operations = status_snapshot(connection)
    pairs = {"red_only_correct": 0, "standard_only_correct": 0}
    for encoded, expected in latest:
        report = json.loads(encoded)
        cases["current"] += 1
        cases[report["session_attribution"]["status"]] += 1
        matched = report["prediction_matched"]
        cases["red_forecasts"] += int(matched is not None)
        cases["red_forecasts_matched"] += int(matched is True)
        if expected is None:
            continue
        cases["decisions_confirmed"] += 1
        for variant, score in metrics.items():
            if variant not in report:
                continue
            decision = report[variant]["decision"]
            score["checked"] += 1
            score["correct"] += int(decision == expected)
            score["false_escalations"] += int(expected != "escalate" and decision == "escalate")
            score["missed_escalations"] += int(expected == "escalate" and decision != "escalate")
        standard = report["standard_review"]["decision"] == expected
        assisted = report["assisted"]["decision"] == expected
        pairs["red_only_correct"] += int(assisted and not standard)
        pairs["standard_only_correct"] += int(standard and not assisted)
    return {
        "since": since,
        "journal": {"login_observations": anchors, "bound_observations": bound,
                    "unbound_observations": anchors - bound,
                    "sudo_denials": denied, "sudo_denials_unverified": unverifiable},
        "operations": operations,
        "cases": cases,
        "decisions": metrics,
        "paired": pairs,
        "checks_per_variant": {"blue": 0, "standard_review": 1, "assisted": 1, FULL_REFERENCE: 3},
    }
