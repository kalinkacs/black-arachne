"""Supervised local role processes with a narrow JSON Lines protocol.

Workers receive only the coordinator's explicit projections. Process separation
does not confer a kernel security sandbox.
"""

from contextlib import AbstractContextManager
from copy import deepcopy
import json
import os
from pathlib import Path
import selectors
import subprocess
import sys
from time import monotonic

FORMAT = 1
MAX_PACKET = 512 * 1024
STARTUP = (
    "import runpy, sys; sys.path.insert(0, sys.argv.pop(1)); "
    "runpy.run_module('arachne.role_worker', run_name='__main__')"
)


class RoleFailure(ValueError):
    """A role did not produce a valid response within its execution budget."""


class RoleTransportFailure(RoleFailure):
    """A worker disconnected or stopped responding."""


class RoleProcess(AbstractContextManager):
    def __init__(self, role, timeout=4):
        self.role = role
        self.timeout = timeout
        self.history = []
        self.recovery_used = False
        self.process = None

    def __enter__(self):
        self.history.clear()
        self.recovery_used = False
        self._start()
        return self

    def _start(self):
        self.sequence = 0
        self.buffer = bytearray()
        root = Path(__file__).resolve().parent.parent
        try:
            self.process = subprocess.Popen(
                [sys.executable, "-I", "-c", STARTUP, str(root), self.role],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                env={"PATH": os.defpath},
                bufsize=0,
            )
        except OSError as error:
            raise RoleFailure(f"{self.role} worker could not start") from error

    def __exit__(self, *exception):
        self._stop()

    def _stop(self):
        process, self.process = self.process, None
        if process is None:
            return
        process.stdin.close()
        try:
            process.wait(timeout=.25)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
        finally:
            process.stdout.close()

    def call_with_recovery(self, phase, payload):
        try:
            result = self.call(phase, payload)
        except RoleTransportFailure:
            if self.recovery_used:
                raise
            self.recovery_used = True
            self._stop()
            self._start()
            deadline = monotonic() + self.timeout
            for prior_phase, request, expected in self.history:
                replayed = self._exchange(prior_phase, request, deadline)
                if replayed != expected:
                    raise RoleFailure(f"{self.role} replacement changed its previous response for {prior_phase}")
            result = self._exchange(phase, payload, deadline)
        self.history.append((phase, deepcopy(payload), deepcopy(result)))
        return result

    def call(self, phase, payload):
        return self._exchange(phase, payload, monotonic() + self.timeout)

    def _exchange(self, phase, payload, deadline):
        self.sequence += 1
        envelope = {"version": FORMAT, "sequence": self.sequence, "phase": phase, "payload": payload}
        encoded = json.dumps(envelope, ensure_ascii=False, allow_nan=False).encode() + b"\n"
        if len(encoded) > MAX_PACKET:
            raise RoleFailure(f"{self.role} request exceeds the packet budget")
        self._send(encoded, deadline)
        response = self._receive(deadline)
        if (
            not isinstance(response, dict)
            or set(response) != {"version", "sequence", "result"}
            or response["version"] != FORMAT
            or response["sequence"] != self.sequence
            or not isinstance(response["result"], dict)
        ):
            raise RoleFailure(f"{self.role} returned an invalid protocol response for {phase}")
        return response["result"]

    def _send(self, packet, deadline):
        # The child reads concurrently. Poll before each pipe-sized atomic write.
        with selectors.DefaultSelector() as poll:
            poll.register(self.process.stdin, selectors.EVENT_WRITE)
            sent = 0
            while sent < len(packet):
                if not poll.select(max(0, deadline - monotonic())):
                    raise RoleTransportFailure(f"{self.role} did not accept its input")
                try:
                    sent += os.write(self.process.stdin.fileno(), packet[sent:sent + 4096])
                except BrokenPipeError as error:
                    raise RoleTransportFailure(f"{self.role} exited before accepting its input") from error

    def _receive(self, deadline):
        with selectors.DefaultSelector() as poll:
            poll.register(self.process.stdout, selectors.EVENT_READ)
            while b"\n" not in self.buffer:
                if not poll.select(max(0, deadline - monotonic())):
                    raise RoleTransportFailure(f"{self.role} exceeded its response time limit")
                chunk = os.read(self.process.stdout.fileno(), 8192)
                if not chunk:
                    raise RoleTransportFailure(f"{self.role} exited without completing its response")
                self.buffer.extend(chunk)
                if len(self.buffer) > MAX_PACKET:
                    raise RoleFailure(f"{self.role} response exceeds the packet budget")
        message, _, rest = self.buffer.partition(b"\n")
        self.buffer = rest
        try:
            return json.loads(message)
        except ValueError as error:
            raise RoleFailure(f"{self.role} returned invalid JSON") from error
