#!/usr/bin/env bash
# Integration test for a disposable Ubuntu VM with systemd and OpenSSH.
# Generates two ordinary local SSH logins. One runs a harmless sudo command.
set -euo pipefail
if [[ "${GITHUB_ACTIONS:-}" != true || "${RUNNER_ENVIRONMENT:-}" != github-hosted ]]; then
  printf '%s
' 'This rehearsal uses a disposable GitHub-hosted runner.' >&2
  exit 1
fi
umask 077

pilot_dir=$(mktemp -d "$HOME/.arachne-native.XXXXXX")
pilot_unit="arachne-native-$$"
pilot_user=$(id -un)
pilot_start=$(date --iso-8601=seconds)
pilot_audit_key="arachne_pilot_$$"
pilot_decoy="$pilot_dir/test-decoy.txt"
pilot_watch_installed=false
pilot_syscalls=(-F arch=b64 -S open,openat -F "path=$pilot_decoy" -F perm=r -k "$pilot_audit_key")
pilot_task_filter=false
[[ "$pilot_user" =~ ^[a-zA-Z0-9_-]+$ ]]
cleanup() {
  if "$pilot_watch_installed"; then
    sudo -n auditctl -d always,exit "${pilot_syscalls[@]}" >/dev/null 2>&1 || true
  fi
  if "$pilot_task_filter"; then
    sudo -n auditctl -a never,task >/dev/null 2>&1 || true
  fi
  sudo -n systemctl stop "$pilot_unit.service" 2>/dev/null || true
  sudo -n rm -f /etc/sudoers.d/black-arachne-native-fixture
  rm -rf -- "$pilot_dir"
}
trap cleanup EXIT
printf '%s\n' 'Harmless decoy used by the Black Arachne pilot.' > "$pilot_decoy"
# An unconditional never,task rule prevents even the scoped exit rule
# from seeing the fixture. Temporarily remove it only on this disposable VM.
if sudo -n auditctl -l | grep -Fxq -- '-a never,task'; then
  sudo -n auditctl -d never,task
  pilot_task_filter=true
fi
sudo -n auditctl -A always,exit "${pilot_syscalls[@]}"
pilot_watch_installed=true

pilot_port=$(python3 - <<'PY'
from socket import socket
with socket() as listener:
    listener.bind(('127.0.0.1', 0))
    print(listener.getsockname()[1])
PY
)
ssh-keygen -q -t ed25519 -N '' -f "$pilot_dir/host-key"
ssh-keygen -q -t ed25519 -N '' -f "$pilot_dir/client-key"
printf '[127.0.0.1]:%s %s\n' "$pilot_port" "$(cat "$pilot_dir/host-key.pub")" > "$pilot_dir/known_hosts"
cat > "$pilot_dir/sshd.conf" <<CONFIG
Port $pilot_port
ListenAddress 127.0.0.1
HostKey "$pilot_dir/host-key"
AuthorizedKeysFile "$pilot_dir/client-key.pub"
AllowUsers $pilot_user
AuthenticationMethods publickey
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
UsePAM yes
DisableForwarding yes
PermitTTY no
LogLevel VERBOSE
CONFIG

sudo -n install -d -m 0755 /run/sshd
sudo -n /usr/sbin/sshd -t -f "$pilot_dir/sshd.conf"
sudo -n systemd-run --quiet --unit "$pilot_unit" /usr/sbin/sshd -D -f "$pilot_dir/sshd.conf"
python3 - "$pilot_port" <<'PY'
from socket import create_connection
import sys
from time import monotonic, sleep
deadline = monotonic() + 10
while True:
    try:
        with create_connection(("127.0.0.1", int(sys.argv[1])), timeout=1):
            break
    except OSError:
        if monotonic() >= deadline:
            raise
        sleep(0.2)
PY

cat > "$pilot_dir/first.sh" <<'SCRIPT'
set -eu
state_dir=$(dirname -- "$0")
touch "$state_dir/first-ready"
timeout 15 bash -c 'until [[ -f "$1" ]]; do sleep .2; done' _ "$state_dir/second-ready"
sudo -n -- /usr/bin/true
cat -- "$state_dir/test-decoy.txt" >/dev/null
touch "$state_dir/first-done"
SCRIPT
cat > "$pilot_dir/second.sh" <<'SCRIPT'
set -eu
state_dir=$(dirname -- "$0")
touch "$state_dir/second-ready"
timeout 15 bash -c 'until [[ -f "$1" ]]; do sleep .2; done' _ "$state_dir/first-done"
SCRIPT

pilot_ssh=(ssh -F /dev/null -o BatchMode=yes -o IdentitiesOnly=yes -o ConnectTimeout=5
           -o StrictHostKeyChecking=yes -o "UserKnownHostsFile=$pilot_dir/known_hosts"
           -i "$pilot_dir/client-key" -p "$pilot_port" "$pilot_user@127.0.0.1")
"${pilot_ssh[@]}" "bash $(printf '%q' "$pilot_dir/first.sh")" &
first_pid=$!
"${pilot_ssh[@]}" "bash $(printf '%q' "$pilot_dir/second.sh")" &
second_pid=$!
wait "$first_pid"
wait "$second_pid"

sudo -n useradd --system --user-group --no-create-home --shell /usr/sbin/nologin black-arachne
# Spell out a denial on the disposable VM's fixture account so sudo emits
# a policy decision rather than only returning a missing-password prompt.
printf '%s
' 'Defaults:black-arachne !authenticate' 'black-arachne ALL=(root) !/usr/bin/true' > "$pilot_dir/sudo-denial"
sudo -n visudo -cf "$pilot_dir/sudo-denial"
sudo -n install -m 0440 "$pilot_dir/sudo-denial" /etc/sudoers.d/black-arachne-native-fixture
if sudo -n -u black-arachne /usr/bin/sudo -n -- /usr/bin/true; then
  printf '%s
' 'The unprivileged rehearsal account unexpectedly received sudo access.' >&2
  exit 1
fi

sudo -n rm -f /etc/sudoers.d/black-arachne-native-fixture
sudo -n journalctl --sync
sudo -n journalctl --since "$pilot_start" --no-pager -o json \
  SYSLOG_IDENTIFIER=sshd SYSLOG_IDENTIFIER=sshd-session SYSLOG_IDENTIFIER=sudo > "$pilot_dir/native.jsonl"
python3 -m arachne --db "$pilot_dir/rehearsal.sqlite3" import-journal --native "$pilot_dir/native.jsonl"
python3 -m arachne --db "$pilot_dir/rehearsal.sqlite3" anchors > "$pilot_dir/anchors.json"
for attempt in {1..20}; do
  if sudo -n ausearch -k "$pilot_audit_key" --raw > "$pilot_dir/files.audit"; then
    break
  fi
  sleep .25
done
if ! test -s "$pilot_dir/files.audit"; then
  printf '%s\n' 'No events reached the pilot audit export.' >&2
  sudo -n auditctl -s
  sudo -n auditctl -l
  sudo -n grep -c -F "$pilot_audit_key" /var/log/audit/audit.log || true
  exit 1
fi
python3 - "$pilot_dir" "$pilot_audit_key" <<'PY'
from collections import Counter
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sqlite3
import subprocess
import sys

from arachne.audit_files import import_audit_files
from arachne.dead_souls import case_evidence, register_decoy
from arachne.events import ANCHOR_KINDS, from_journal
from arachne.operations import triage
from arachne.provenance import create_key, load_key
from arachne.store import database, get_run, ingest

root = Path(sys.argv[1])
anchors = json.loads((root / "anchors.json").read_text())
by_session = {anchor["session_key"]: anchor for anchor in anchors if anchor.get("session_key")}
if len(by_session) != 2:
    def describe(entry):
        message = entry.get("MESSAGE", "")
        prefix = next((key for key in ("Accepted", "pam_unix", "Starting session:", "Close session:")
                       if isinstance(message, str) and message.startswith(key)), "other")
        audit = entry.get("_AUDIT_SESSION")
        return (entry.get("SYSLOG_IDENTIFIER"), Path(entry.get("_EXE", "/unknown")).name, prefix,
                type(audit).__name__, audit in ("0", "4294967295"), bool(entry.get("_MACHINE_ID")), bool(entry.get("_BOOT_ID")))

    diagnostics = Counter(map(describe, map(json.loads, (root / "native.jsonl").read_text().splitlines())))
    print(f"Native journal source coverage: {dict(diagnostics)}", file=sys.stderr)
    raise SystemExit(f"Expected two audit-bound SSH sessions, captured {len(by_session)}")

counts = []
privileged_sessions = set()
for anchor in by_session.values():
    output = subprocess.check_output(
        [sys.executable, "-m", "arachne", "--db", str(root / "rehearsal.sqlite3"),
         "investigate", anchor["host"], anchor["id"], "--offline"],
        text=True,
    )
    case = json.loads(output)
    linked = set(case["session_attribution"]["linked"])
    count = sum(event["kind"] == "privileged_activity" and event["id"] in linked for event in case["events"])
    counts.append(count)
    if count:
        privileged_sessions.add(anchor["session_key"])
if sorted(counts) != [0, 1]:
    journal_sudo = [row for row in map(json.loads, (root / "native.jsonl").read_text().splitlines())
                    if row.get("SYSLOG_IDENTIFIER") == "sudo"]
    messages = [(bool(row.get("_AUDIT_SESSION")), isinstance(row.get("MESSAGE"), str)
                 and tuple(part for part in ("TTY=", "PWD=", "USER=", "COMMAND=") if part in row["MESSAGE"]))
                for row in journal_sudo]
    raise AssertionError((counts, Counter(messages)))
print("Confirmed native isolation: only the session that ran sudo received the privilege observation.")
machine_id = Path("/etc/machine-id").read_text().strip()
boot_id = Path("/proc/sys/kernel/random/boot_id").read_text().strip().replace("-", "")
host, = {anchor["host"] for anchor in by_session.values()}
key_path = root / "decoy.key"
create_key(key_path, "native-pilot", "decoy-monitor", host)
with database(root / "rehearsal.sqlite3") as db:
    register_decoy(db, "native-pilot-decoy", "file")
    with (root / "files.audit").open() as stream:
        result = import_audit_files(db, stream, load_key(key_path), machine_id, boot_id, sys.argv[2],
                                    {str(root / "test-decoy.txt"): "native-pilot-decoy"}, 25)
    assert result["new_verified"] == 1 and result["unattributed"] == 0, result
    for session, anchor in by_session.items():
        report = case_evidence(db, anchor["id"])
        assert report["touch_count"] == int(session in privileged_sessions), (session, result, report)
print("Confirmed native file attribution: one decoy read, attached only to the session that opened it.")

with sqlite3.connect(root / "rehearsal.sqlite3") as db:
    records = [json.loads(payload) for (payload,) in db.execute(
        "SELECT payload FROM events WHERE json_extract(payload, '$.actor')='black-arachne'"
    )]
    assert all(event["kind"] != "privileged_activity" for event in records), records
    assert any(event["kind"] in {"privilege_denied", "privilege_denial_unverified"} for event in records), records
print("The real declined sudo request was recorded separately from accepted privilege activity.")

# Replay authentic journal observations in two batches to exercise late delivery.
native = [event for row in map(json.loads, (root / "native.jsonl").read_text().splitlines())
          if isinstance(row, dict) and (event := from_journal(row, native=True))]
anchors = [event for event in native if event.kind in ANCHOR_KINDS and event.session_key in by_session]
delayed, = [event for event in native if event.kind == "privileged_activity" and event.session_key in by_session]
late_db = root / "late.sqlite3"
ready = datetime.now(timezone.utc) + timedelta(minutes=16)
with database(late_db) as db:
    ingest(db, anchors)
assert triage(late_db, now=ready)["investigated"] == 2
with database(late_db) as db:
    ingest(db, [delayed])
resumed, = triage(late_db, now=ready)["runs"]
with database(late_db) as db:
    assert get_run(db, resumed)["session_attribution"]["linked"] == [delayed.id]
assert triage(late_db, now=ready)["investigated"] == 0
print("Late native activity caused exactly one reassessment, limited to the matching session.")
PY

# Rehearse the shipped systemd unit on the disposable runner. The servicing
# account reads the journal through its supplementary group.
sudo -n install -d -m 0755 /opt/black-arachne
sudo -n cp -a arachne /opt/black-arachne/
sudo -n install -m 0644 deploy/black-arachne.service /etc/systemd/system/
sudo -n systemctl daemon-reload
sudo -n systemctl start black-arachne.service
sudo -n -u black-arachne /usr/bin/python3 -I -c '
import sys
sys.path.insert(0, "/opt/black-arachne")
from arachne.__main__ import cli
sys.argv = ["black-arachne", "--db", "/var/lib/black-arachne/evidence.sqlite3", "pilot-report"]
sys.exit(cli())
' > "$pilot_dir/service-status.json"
python3 - "$pilot_dir/service-status.json" <<'PY'
import json
import sys
from pathlib import Path
report = json.loads(Path(sys.argv[1]).read_text())
assert report["journal"]["bound_observations"] >= 2, report
assert report["operations"]["collector"] is not None, report
print("Installed systemd service collected real journal observations as its own account.")
PY
