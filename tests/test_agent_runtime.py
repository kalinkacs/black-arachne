from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from arachne.mimicry import mimic
from arachne.operations import triage
from arachne.role_runtime import RoleFailure, RoleProcess
from arachne.store import confirm_outcome, database, get_run, ingest, save_run, status_snapshot
from test_offline import bind_session, sample


class RuntimeTests(unittest.TestCase):
    def test_workers_are_distinct_persistent_processes_with_role_scoped_phases(self):
        coarse = {"profile": {"declared_change": False, "prior_failures": False, "privileged_activity": False},
                  "history": []}
        with RoleProcess("red") as red, RoleProcess("control") as control:
            self.assertNotEqual(red.process.pid, control.process.pid)
            self.assertIsNone(red.call("forecast", coarse)["prediction"])
            self.assertEqual(control.call("select", coarse)["check"], "identity_record")
            compared = red.call("compare", {"actual": "review",
                                           "result": "escalate", "observation": "disputes"})
            self.assertEqual(compared, {"prediction_matched": None, "decision_changed": True,
                                        "verification_state": "disputes"})
            with self.assertRaises(RoleFailure):
                red.call("assess", coarse)

    def test_blue_cannot_reconsider_before_freezing_its_own_initial_decision(self):
        with RoleProcess("blue") as worker:
            with self.assertRaises(RoleFailure):
                worker.call("reconsider", {"observation": {"check": "identity_record", "state": "unknown", "evidence_ids": []}})

    def test_transport_surfaces_dead_worker(self):
        with RoleProcess("blue") as worker:
            worker.process.terminate()
            worker.process.wait(timeout=2)
            with self.assertRaises(RoleFailure):
                worker.call("assess", {})

    def test_investigation_replaces_blue_and_preserves_the_frozen_assessment(self):
        stopped = []

        class InterruptedBlue(RoleProcess):
            def call(self, phase, payload):
                if self.role == "blue" and phase == "reconsider" and not stopped:
                    stopped.append(self.process)
                    self.process.kill()
                    self.process.wait(timeout=2)
                return super().call(phase, payload)

        anchor, events = sample("change-confirmed")
        original = mimic(anchor, events)
        with patch("arachne.mimicry.RoleProcess", InterruptedBlue):
            recovered = mimic(anchor, events)

        self.assertEqual(len(stopped), 1)
        self.assertEqual(recovered["recommendation"], original["recommendation"])
        self.assertEqual(recovered["mimicry"], original["mimicry"])
        self.assertEqual(
            [step for step in recovered["role_runtime"]["trace"] if step.get("replaced_worker")],
            [{"role": "blue", "phase": "reconsider", "replaced_worker": True}],
        )

    def test_replacement_refuses_to_continue_if_a_previous_response_changes(self):
        coarse = {"profile": {"declared_change": False, "prior_failures": False, "privileged_activity": False},
                  "history": []}
        comparison = {"actual": "review", "result": "escalate", "observation": "disputes"}
        with RoleProcess("red") as worker:
            worker.call_with_recovery("forecast", coarse)
            worker.process.kill()
            worker.process.wait(timeout=2)
            # Let the first write observe the dead pipe, then simulate a different forecast.
            exchange = worker._exchange

            def replay_with_different_forecast(phase, payload, deadline):
                result = exchange(phase, payload, deadline)
                return {**result, "prediction": "close"} if phase == "forecast" else result

            with patch.object(worker, "_exchange", side_effect=replay_with_different_forecast):
                with self.assertRaisesRegex(RoleFailure, "replacement changed its previous response"):
                    worker.call_with_recovery("compare", comparison)

    def test_initial_projections_do_not_change_when_hidden_evidence_is_inserted(self):
        initial_passes = []

        class ObservedWorker(RoleProcess):
            def call(self, phase, payload):
                if phase in {"forecast", "assess"}:
                    initial_passes.append((self.role, payload))
                return super().call(phase, payload)

        anchor, events = sample("change-confirmed")
        with patch("arachne.mimicry.RoleProcess", ObservedWorker):
            original = mimic(anchor, events)
            verified = next(event for event in events if event.kind == "change_verified")
            modified = replace(verified, id="hidden", timestamp=anchor.timestamp)
            alternative = mimic(anchor, sorted([*events, modified], key=lambda event: (event.timestamp, event.id)))
        self.assertEqual(initial_passes[:2], initial_passes[2:])
        self.assertEqual(original["role_runtime"]["trace"][0], {"role": "red", "phase": "forecast"})
        self.assertEqual(alternative["role_runtime"]["trace"][-1], {"role": "red", "phase": "compare"})
        self.assertEqual(original["role_runtime"]["mode"], "local-processes")
        self.assertEqual(original["mimicry"]["assisted_observation"]["state"], "supports")


class RuntimeRetryTests(unittest.TestCase):
    def test_role_failure_defers_only_affected_incident_and_retries_after_restart(self):
        _, first_events = sample("change-confirmed")
        first = next(event for event in first_events if event.kind == "ssh_login")
        now = datetime(2026, 1, 1, 13, tzinfo=timezone.utc)
        broken = replace(first, source="systemd-journal")
        healthy = replace(first, id="second-host-login", host="healthy", source="systemd-journal")
        with tempfile.TemporaryDirectory() as folder:
            db = Path(folder) / "cases.sqlite3"
            with database(db) as connection:
                ingest(connection, [broken, healthy])

            def fail_one(connection, anchor, events, model):
                if anchor.id == broken.id:
                    raise RoleFailure("worker timed out")
                return mimic(anchor, events)

            with patch("arachne.operations.operational_review", fail_one):
                summary = triage(db, now=now)
            self.assertEqual(summary["investigated"], 1)
            self.assertEqual(summary["retrying"], [broken.id])
            self.assertEqual(triage(db, now=now)["investigated"], 0)
            with database(db) as connection:
                self.assertEqual(status_snapshot(connection)["pending_role_retries"], 1)
            retried = triage(db, now=now + timedelta(minutes=1))
            self.assertEqual(retried["investigated"], 1)
            with database(db) as connection:
                self.assertEqual(status_snapshot(connection)["pending_role_retries"], 0)


class AgentFeedbackTests(unittest.TestCase):
    def test_worker_uses_three_operator_confirmations_in_the_next_queued_case(self):
        anchor, events = bind_session(*sample("repeated-failures-and-account-confirmation"))
        with tempfile.TemporaryDirectory() as folder:
            db = Path(folder) / "cases.sqlite3"
            with database(db) as connection:
                for cycle in range(3):
                    prior = [replace(event, id=f"prior-{cycle}-{event.id}") for event in events]
                    login = next(event for event in prior if event.kind == "ssh_login")
                    result = mimic(login, prior)
                    self.assertEqual(result["forecast"]["check"], "identity_record")
                    run = save_run(connection, result)
                    confirm_outcome(connection, run["id"], "escalate", f"Confirmed earlier case {cycle}")
                live = [replace(event, source="systemd-journal") if event.id == anchor.id else event for event in events]
                ingest(connection, live)
            summary = triage(db, now=datetime(2026, 1, 1, 13, tzinfo=timezone.utc))
            with database(db) as connection:
                result = get_run(connection, summary["runs"][0])
            self.assertEqual(result["forecast"]["check"], "activity_record")
            self.assertEqual(result["forecast"]["check_history"]["activity_record"]["observations"], 3)
            self.assertEqual(result["recommendation"]["decision"], "escalate")
            self.assertEqual(result["role_runtime"]["trace"][-1], {"role": "red", "phase": "compare"})
