"""Authenticate independent defensive records and bind them to one login."""

from dataclasses import dataclass
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import stat

from .events import ANCHOR_KINDS, Event, encode, episode_window, records

SOURCE_KINDS = {
    "change-management": {"change_verified", "change_disputed"},
    "identity-management": {"identity_verified", "identity_disputed"},
}
VERIFICATION_KINDS = frozenset().union(*SOURCE_KINDS.values())
KEY_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
HEX_SECRET = re.compile(r"[a-f0-9]{64}")
FORMAT = 1
DOMAIN = b"black-arachne/verification/v1\x00"
MAX_KEY_DOCUMENT = 4096


@dataclass(frozen=True)
class VerificationKey:
    key_id: str
    source: str
    host: str
    secret: bytes

    @classmethod
    def from_record(cls, data):
        if not isinstance(data, dict) or set(data) != {"key_id", "source", "host", "secret"}:
            raise ValueError("Invalid key document")
        key_id, source, host, secret = (data[key] for key in ("key_id", "source", "host", "secret"))
        if not isinstance(key_id, str) or KEY_ID.fullmatch(key_id) is None:
            raise ValueError("Invalid key identifier")
        if not isinstance(source, str) or source not in SOURCE_KINDS:
            raise ValueError("Unsupported verification source")
        if not isinstance(host, str) or not host.strip() or host != host.strip() or len(host) > 256 or any(
            ord(char) < 32 or ord(char) == 127 for char in host
        ):
            raise ValueError("Invalid key host")
        if not isinstance(secret, str) or HEX_SECRET.fullmatch(secret) is None:
            raise ValueError("Invalid key material")
        return cls(key_id, source, host, bytes.fromhex(secret))


def create_key(path, key_id, source, host):
    data = {"key_id": key_id, "source": source, "host": host, "secret": secrets.token_hex(32)}
    key = VerificationKey.from_record(data)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        stream.write(encode(data) + "\n")
    return {"key_id": key.key_id, "source": key.source, "host": key.host, "path": str(path)}


def load_key(path):
    fd = os.open(Path(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise ValueError("Key file must be regular, owned by this account, and private (0600)")
        contents = stream.read(MAX_KEY_DOCUMENT + 1)
        if len(contents) > MAX_KEY_DOCUMENT:
            raise ValueError("Key file exceeds size limit")
    return VerificationKey.from_record(json.loads(contents))


def event_in_scope(key, event):
    if event.host != key.host or event.source != key.source or event.kind not in SOURCE_KINDS[key.source]:
        raise ValueError("Verification is outside this key's host or source scope")


def signature(key, body):
    return hmac.new(key.secret, DOMAIN + encode(body).encode(), hashlib.sha256).hexdigest()


def sign_record(key, anchor_id, event):
    if not isinstance(anchor_id, str) or not anchor_id.strip() or len(anchor_id) > 256:
        raise ValueError("Invalid anchor identifier")
    event_in_scope(key, event)
    body = {"version": FORMAT, "key_id": key.key_id, "anchor_id": anchor_id, "event": records((event,))[0]}
    return {**body, "mac": signature(key, body)}


def authenticate(key, envelope):
    if not isinstance(envelope, dict) or set(envelope) != {"version", "key_id", "anchor_id", "event", "mac"}:
        raise ValueError("Invalid verification envelope")
    if type(envelope["version"]) is not int or envelope["version"] != FORMAT or envelope["key_id"] != key.key_id:
        raise ValueError("Unsupported verification format or key")
    mac = envelope["mac"]
    if not isinstance(mac, str) or HEX_SECRET.fullmatch(mac) is None:
        raise ValueError("Invalid verification MAC")
    event = Event.parse(envelope["event"])
    expected = sign_record(key, envelope["anchor_id"], event)
    if not hmac.compare_digest(expected["mac"], mac):
        raise ValueError("Verification authentication failed")
    return event, envelope["anchor_id"]


def check_binding(anchor, event):
    lower, upper = episode_window(anchor)
    if anchor.kind not in ANCHOR_KINDS or (anchor.host, anchor.actor) != (event.host, event.actor):
        raise ValueError("Verification does not match the login host and account")
    if event.machine_id is not None and event.machine_id != anchor.machine_id:
        raise ValueError("Verification does not match the login machine")
    if event.session_key is not None and event.session_key != anchor.session_key:
        raise ValueError("Verification does not match the login session")
    if not lower <= event.timestamp <= upper:
        raise ValueError("Verification is outside the login's evidence window")
