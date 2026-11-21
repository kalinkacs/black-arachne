"""Supervised local role processes with a narrow JSON Lines protocol.

Workers receive only the coordinator's explicit projections. Process separation
does not confer a kernel security sandbox.
"""

from contextlib import AbstractContextManager
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


class RoleProcess(AbstractContextManager):
    def __init__(self, role, timeout=4):
        self.role = role
        self.timeout = timeout
        self.sequence = 0
        self.buffer = bytearray()

    def __enter__(self):
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
        return self

    def __exit__(self, *exception):
        self.process.stdin.close()
        try:
            self.process.wait(timeout=.25)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait()
        finally:
            self.process.stdout.close()

    def call(self, phase, payload):
        self.sequence += 1
        envelope = {"version": FORMAT, "sequence": self.sequence, "phase": phase, "payload": payload}
        encoded = json.dumps(envelope, ensure_ascii=False, allow_nan=False).encode() + b"\n"
        if len(encoded) > MAX_PACKET:
            raise RoleFailure(f"{self.role} request exceeds the packet budget")
        deadline = monotonic() + self.timeout
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
                    raise RoleFailure(f"{self.role} did not accept its input")
                try:
                    sent += os.write(self.process.stdin.fileno(), packet[sent:sent + 4096])
                except BrokenPipeError as error:
                    raise RoleFailure(f"{self.role} exited before accepting its input") from error

    def _receive(self, deadline):
        with selectors.DefaultSelector() as poll:
            poll.register(self.process.stdout, selectors.EVENT_READ)
            while b"\n" not in self.buffer:
                if not poll.select(max(0, deadline - monotonic())):
                    raise RoleFailure(f"{self.role} exceeded its response time limit")
                chunk = os.read(self.process.stdout.fileno(), 8192)
                if not chunk:
                    raise RoleFailure(f"{self.role} exited without completing its response")
                self.buffer.extend(chunk)
                if len(self.buffer) > MAX_PACKET:
                    raise RoleFailure(f"{self.role} response exceeds the packet budget")
        message, _, rest = self.buffer.partition(b"\n")
        self.buffer = rest
        try:
            return json.loads(message)
        except ValueError as error:
            raise RoleFailure(f"{self.role} returned invalid JSON") from error
