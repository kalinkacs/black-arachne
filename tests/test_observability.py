from dataclasses import asdict
from datetime import datetime, timedelta
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from arachne.lab import fixture
from arachne.mimicry import CHECKS
from arachne.observability import audit_observability


def case(identifier, family, expected, *, change=None, identity=None, variant=0, offset=0):
    kinds = [("deployment", 9), ("ssh_login", 10), ("privileged_activity", 11)]
    kinds.extend(("ssh_failure", minute) for minute in range(9 - variant, 9))
    events = [fixture(identifier, kind, minute) for kind, minute in kinds]
    anchor = next(event for event in events if event.kind == "ssh_login")
    for check, outcome in (("change_record", change), ("identity_record", identity)):
        fixture_kind = CHECKS[check]
        if outcome is not None:
            states = ("positive", "negative") if outcome == "conflict" else (outcome,)
            for state in states:
                events.append(fixture(identifier, fixture_kind[state], 12, fixture_kind["source"]))
    records = [asdict(event) for event in events]
    for record in records:
        shifted = datetime.fromisoformat(record["timestamp"]) + timedelta(hours=offset)
        record["timestamp"] = shifted.isoformat()
    return {"id": identifier, "family": family, "expected": expected, "anchor_id": anchor.id, "events": records}


def dataset(*rows):
    return io.StringIO("\n".join(json.dumps(row) for row in rows))


class ObservabilityTests(unittest.TestCase):
    def test_opposite_labels_with_same_telemetry_get_a_reproducible_witness(self):
        approved = case("approved", "authorization", "close", change="positive", offset=1)
        disputed = case("disputed", "authorization", "escalate", change="negative", offset=-1)
        report = audit_observability(dataset(approved, disputed))
        result = report["discovery"]
        self.assertEqual(report["selected_checks"], ("change_record",))
        self.assertEqual((result["pairs"], result["covered"]), (1, 1))
        witness = result["examples"][0]
        self.assertEqual((witness["close"]["case"], witness["escalate"]["case"]), ("approved", "disputed"))
        self.assertEqual(witness["explicit_separators"], ("change_record",))
        self.assertEqual(audit_observability(dataset(disputed, approved)), report)

    def test_missing_conflicting_and_wrong_session_records_cannot_separate(self):
        normal = case("normal", "authorization", "close", change="positive", identity="positive")
        flagged = case("flagged", "authorization", "escalate", identity="conflict")
        reviewed = case("unknown", "authorization", "review", change="negative")
        for row in (normal, flagged):
            for event in row["events"]:
                event.update(machine_id="a" * 32, session_key="b" * 64)
        misplaced = next(event for event in reviewed["events"] if event["kind"] == "change_disputed").copy()
        misplaced.update(host=flagged["events"][0]["host"], machine_id="c" * 32, session_key="d" * 64)
        wrong_session = {**misplaced, "id": "wrong-session", "machine_id": "a" * 32}
        flagged["events"].extend((misplaced, wrong_session))
        result = audit_observability(dataset(normal, flagged, reviewed))["discovery"]
        self.assertEqual((result["pairs"], result["covered"], result["without_explicit_separator"]), (1, 0, 1))
        self.assertEqual(result["review_cases_excluded"], 1)
        self.assertEqual(result["examples"][0]["escalate"]["states"],
                         {"change_record": "unknown", "identity_record": "conflict"})

    def test_two_sources_cover_different_pairs_and_expose_dependency(self):
        rows = (
            case("a-close", "authorization", "close", change="positive"),
            case("a-escalate", "authorization", "escalate", change="negative"),
            case("i-close", "identity", "close", identity="positive", variant=1),
            case("i-escalate", "identity", "escalate", identity="negative", variant=1),
        )
        report = audit_observability(dataset(*rows), max_checks=2)
        self.assertEqual(report["selected_checks"], ("change_record", "identity_record"))
        result = report["discovery"]
        self.assertEqual((result["pairs"], result["covered"]), (2, 2))
        self.assertEqual(result["fixed_single_source"], {"change_record": 1, "identity_record": 1})
        self.assertEqual(result["covered_after_removing_source"], {"change_record": 1, "identity_record": 1})
        self.assertEqual(audit_observability(dataset(*rows), max_checks=1)["discovery"]["covered"], 1)
        self.assertEqual(audit_observability(dataset(*rows), max_checks=0)["discovery"]["covered"], 0)

    def test_tolerance_means_opposite_evidence_from_both_sources_for_the_same_pair(self):
        rows = (
            case("confirmed", "redundant", "close", change="positive", identity="positive"),
            case("disputed", "redundant", "escalate", change="negative", identity="negative"),
        )
        report = audit_observability(dataset(*rows), tolerate_missing=1)
        self.assertEqual(report["selected_checks"], ("change_record", "identity_record"))
        self.assertEqual(report["discovery"]["covered"], 1)
        self.assertEqual(report["discovery"]["covered_after_removing_source"],
                         {"change_record": 1, "identity_record": 1})
        self.assertEqual(audit_observability(dataset(*rows), max_checks=1, tolerate_missing=1)["discovery"]["covered"], 0)

    def test_holdout_freezes_the_plan_and_rejects_shared_families(self):
        discovery = (
            case("approved", "authorization", "close", change="positive"),
            case("disputed", "authorization", "escalate", change="negative"),
        )
        unseen = (
            case("owner", "identity", "close", identity="positive"),
            case("identity-issue", "identity", "escalate", identity="negative"),
        )
        report = audit_observability(dataset(*discovery), holdout=dataset(*unseen))
        self.assertEqual(report["selected_checks"], ("change_record",))
        self.assertEqual(report["holdout"]["covered"], 0)
        self.assertEqual(report["holdout"]["fixed_single_source"]["identity_record"], 1)
        with self.assertRaisesRegex(ValueError, "families must be disjoint"):
            audit_observability(dataset(*discovery), holdout=dataset(*discovery))

    def test_new_measurement_can_resolve_a_gap_and_is_replayed_on_holdout(self):
        discovery = (
            case("a-close", "discovery", "close"),
            case("a-escalate", "discovery", "escalate"),
        )
        unseen = (
            case("b-close", "holdout", "close", variant=1),
            case("b-escalate", "holdout", "escalate", variant=1),
        )
        self.assertEqual(audit_observability(dataset(*discovery))["discovery"]["covered"], 0)
        for pair in (discovery, unseen):
            for row, state in zip(pair, ("supports", "disputes")):
                row["signals"] = {"session_attestation": state}
        report = audit_observability(dataset(*discovery), max_checks=1, holdout=dataset(*unseen))
        self.assertEqual(report["selected_checks"], ("session_attestation",))
        self.assertEqual(report["discovery"]["covered"], 1)
        self.assertEqual(report["holdout"]["covered"], 1)
        unseen[1]["signals"]["session_attestation"] = "unknown"
        self.assertEqual(audit_observability(dataset(*discovery), holdout=dataset(*unseen))["holdout"]["covered"], 0)

    def test_experimental_observations_cannot_replace_builtin_evidence(self):
        row = case("claim", "discovery", "close")
        for signals in ({"identity_record": "supports"}, {"candidate": "escalate"}):
            row["signals"] = signals
            with self.assertRaisesRegex(ValueError, "Invalid experimental signal"):
                audit_observability(dataset(row))

    def test_cli_reads_local_inputs_without_creating_an_operational_database(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            lab_db = root / "should-not-exist.sqlite3"
            command = [sys.executable, "-m", "arachne", "--db", str(lab_db), "observe-gaps",
                       "arachne/data/trial.jsonl", "--max-checks", "1"]
            result = subprocess.run(command, capture_output=True, text=True, check=True)
            self.assertFalse(lab_db.exists())
        report = json.loads(result.stdout)
        self.assertEqual(report["discovery"]["pairs"], 3)
        self.assertEqual(report["discovery"]["covered"], 1)
