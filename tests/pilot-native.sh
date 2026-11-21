#!/usr/bin/env bash
# Integration test for a disposable Ubuntu VM with systemd and OpenSSH.
# Generates two ordinary local SSH logins. One runs a harmless sudo command.
set -euo pipefail
umask 077

pilot_dir=$(mktemp -d "$HOME/.arachne-native.XXXXXX")
pilot_unit="arachne-native-$$"
pilot_user=$(id -un)
pilot_start=$(date --iso-8601=seconds)
[[ "$pilot_user" =~ ^[a-zA-Z0-9_-]+$ ]]
cleanup() {
  sudo -n systemctl stop "$pilot_unit.service" 2>/dev/null || true
  rm -rf -- "$pilot_dir"
}
trap cleanup EXIT

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

sudo -n journalctl --sync
sudo -n journalctl --since "$pilot_start" --no-pager -o json \
  SYSLOG_IDENTIFIER=sshd SYSLOG_IDENTIFIER=sshd-session SYSLOG_IDENTIFIER=sudo > "$pilot_dir/native.jsonl"
python3 -m arachne --db "$pilot_dir/rehearsal.sqlite3" import-journal --native "$pilot_dir/native.jsonl"
python3 -m arachne --db "$pilot_dir/rehearsal.sqlite3" anchors > "$pilot_dir/anchors.json"
python3 - "$pilot_dir" <<'PY'
from collections import Counter
import json
from pathlib import Path
import subprocess
import sys

root = Path(sys.argv[1])
anchors = json.loads((root / "anchors.json").read_text())
by_session = {anchor["session_key"]: anchor for anchor in anchors if anchor.get("session_key")}
if len(by_session) != 2:
    diagnostics = Counter((entry.get("SYSLOG_IDENTIFIER"), bool(entry.get("_AUDIT_SESSION")),
                           bool(entry.get("_MACHINE_ID")), bool(entry.get("_BOOT_ID")))
                          for entry in map(json.loads, (root / "native.jsonl").read_text().splitlines()))
    print(f"Native journal source coverage: {dict(diagnostics)}", file=sys.stderr)
    raise SystemExit(f"Expected two audit-bound SSH sessions, captured {len(by_session)}")

counts = []
for anchor in by_session.values():
    output = subprocess.check_output(
        [sys.executable, "-m", "arachne", "--db", str(root / "rehearsal.sqlite3"),
         "investigate", anchor["host"], anchor["id"], "--offline"],
        text=True,
    )
    case = json.loads(output)
    linked = set(case["session_attribution"]["linked"])
    counts.append(sum(event["kind"] == "privileged_activity" and event["id"] in linked
                      for event in case["events"]))
assert sorted(counts) == [0, 1], counts
print("Confirmed native isolation: only the session that ran sudo received the privilege observation.")
PY

# Rehearse the shipped systemd unit on the disposable runner. The servicing
# account reads the journal through its supplementary group.
sudo -n useradd --system --user-group --no-create-home --shell /usr/sbin/nologin black-arachne
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
