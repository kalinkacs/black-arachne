"""Probe process loss against the same native Windows file-audit observations."""

from contextlib import contextmanager, ExitStack
from hashlib import sha256
import json
from pathlib import Path
from queue import Empty, Queue
import subprocess
import sys
from threading import Thread

WORKER_PATH = Path(__file__).resolve()


def checkpoint(paths, threshold):
    frozen = json.dumps({"paths": paths, "threshold": threshold}, separators=(",", ":"), sort_keys=True)
    return {"distinct_files": len(paths), "digest": sha256(frozen.encode()).hexdigest()}


def worker():
    request = json.loads(sys.stdin.readline())
    paths, threshold = request["paths"], request["threshold"]
    print(json.dumps(checkpoint(paths, threshold)), flush=True)
    if not (line := sys.stdin.readline()):
        return
    approval = json.loads(line)["approval"]
    if len(paths) < threshold:
        decision = "clear"
    elif approval is None:
        decision = "review"
    else:
        decision = "escalate" if set(paths).difference(approval) else "clear"
    print(json.dumps({"decision": decision}), flush=True)


@contextmanager
def worker_process():
    with subprocess.Popen([sys.executable, str(WORKER_PATH), "--worker"], stdin=subprocess.PIPE,
                          stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, encoding="utf-8") as process:
        messages = Queue()

        def read():
            for line in process.stdout:
                messages.put(line)
            messages.put(None)

        reader = Thread(target=read, daemon=True)
        reader.start()

        def call(request):
            process.stdin.write(json.dumps(request) + "\n")
            process.stdin.flush()
            try:
                line = messages.get(timeout=10)
            except Empty as error:
                raise RuntimeError("Windows pilot worker did not respond") from error
            if line is None:
                raise RuntimeError("Windows pilot worker exited before responding")
            return json.loads(line)

        try:
            yield process, call
        finally:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=10)
            reader.join(timeout=10)


def investigate(paths, threshold, approval, groups, crash):
    request = {"paths": paths, "threshold": threshold}
    expected = checkpoint(paths, threshold)
    with ExitStack() as stack:
        active = {team: stack.enter_context(worker_process()) for team in groups}

        def commit(agent):
            if agent[1](request) != expected:
                raise RuntimeError("A replacement changed the original Windows file scope")

        for agent in active.values():
            commit(agent)
        team = groups[0]
        if crash:
            process, _ = active[team]
            process.kill()
            process.wait(timeout=10)
            replacement = stack.enter_context(worker_process())
            commit(replacement)
            replacement[0].kill()
            replacement[0].wait(timeout=10)
            if len(groups) == 1:
                return {"decision": "pending", "approval_reads": 0, "handoff": None, "forced_stops": 2}
            team = groups[1]
        result = active[team][1]({"approval": approval})
        return {**result, "approval_reads": 1, "handoff": [groups[0], team] if crash else None,
                "forced_stops": 2 if crash else 0}


def compare(cases):
    scenarios = (("healthy", False, False), ("double_loss", True, False), ("loss_and_delayed_approval", True, True))
    reports = {}
    for scenario, crash, delay in scenarios:
        reports[scenario] = {}
        for label, use_swarm in (("solo", False), ("three_teams", True)):
            totals = dict(completed=0, correct=0, pending=0, manual_review=0, incorrect_clearances=0,
                          false_escalations=0, handoffs=0, forced_stops=0, approval_reads=0)
            for index, case in enumerate(cases):
                paths = sorted({item["path"] for item in case["writes"]})
                if set(paths) != set(case["written_paths"]):
                    raise ValueError("Native event coverage is incomplete")
                groups = tuple("ABC"[(index + offset) % 3] for offset in range(3 if use_swarm else 1))
                approval = None if delay else case["approval"]
                result = investigate(paths, case["threshold"], approval, groups, crash)
                decision, expected = result["decision"], case["expected_escalation"]
                totals["completed"] += decision != "pending"
                totals["correct"] += decision == ("escalate" if expected else "clear")
                totals["pending"] += decision == "pending"
                totals["manual_review"] += decision == "review"
                totals["incorrect_clearances"] += decision == "clear" and expected
                totals["false_escalations"] += decision == "escalate" and not expected
                totals["handoffs"] += result["handoff"] is not None
                totals["forced_stops"] += result["forced_stops"]
                totals["approval_reads"] += result["approval_reads"]
            reports[scenario][label] = totals
    return reports


if __name__ == "__main__":
    if sys.argv[1] == "--worker":
        worker()
    else:
        corpus = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8-sig"))
        print(json.dumps(compare(corpus), indent=2))
