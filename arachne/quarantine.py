"""Operator-confirmed, same-filesystem quarantine with no-overwrite restoration."""

from contextlib import contextmanager
import ctypes
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import stat
from uuid import uuid4

from .files import FILE_LIMITS, check_file

RENAME_NOREPLACE = 1


@contextmanager
def protected_directory(path, *, vault=False):
    path = Path(path).absolute()
    if path.resolve(strict=True) != path:
        raise ValueError("Use a canonical directory without symbolic links")
    fd = os.open(path, os.O_DIRECTORY | os.O_NOFOLLOW | os.O_RDONLY | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if info.st_uid != os.geteuid() or info.st_mode & (0o077 if vault else 0o022):
            raise ValueError("The vault must be private and both directories must be operator-owned")
        yield path, fd
    finally:
        os.close(fd)


def move_no_replace(source_fd, source, target_fd, target):
    rename = getattr(ctypes.CDLL(None, use_errno=True), "renameat2", None)
    if rename is None:
        raise ValueError("This system lacks atomic no-overwrite rename")
    rename.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
    rename.restype = ctypes.c_int
    if rename(source_fd, os.fsencode(source), target_fd, os.fsencode(target), RENAME_NOREPLACE):
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    os.fsync(source_fd)
    os.fsync(target_fd)


def checked_identity(directory, name, expected_hash):
    before = os.stat(name, dir_fd=directory, follow_symlinks=False)
    if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_uid != os.geteuid()
            or before.st_mode & (stat.S_ISUID | stat.S_ISGID | 0o022)):
        raise ValueError("Quarantine requires a regular, singly linked operator-owned file")
    status, _, snapshot = check_file(directory, name, FILE_LIMITS["max_bytes"])
    after = os.stat(name, dir_fd=directory, follow_symlinks=False)
    if status != "scanned" or snapshot["sha256"] != expected_hash or (
        before.st_dev, before.st_ino, before.st_ctime_ns
    ) != (after.st_dev, after.st_ino, after.st_ctime_ns):
        raise ValueError("The file changed or its SHA-256 does not match the approved hash")
    return [after.st_dev, after.st_ino]


def isolate(vault, source, expected_hash, reason):
    if not re.fullmatch(r"[a-fA-F0-9]{64}", expected_hash) or not reason.strip() or len(reason) > 400:
        raise ValueError("Supply the approved SHA-256 and a reason of 1–400 characters")
    source = Path(source).absolute()
    with protected_directory(vault, vault=True) as (vault_path, vault_fd):
        if source.is_relative_to(vault_path):
            raise ValueError("The source must be outside the vault")
        with protected_directory(source.parent) as (_, parent_fd):
            identity = checked_identity(parent_fd, source.name, expected_hash.lower())
            if identity[0] != os.fstat(vault_fd).st_dev:
                raise ValueError("The file and vault must be on the same filesystem")
            receipt_id = uuid4().hex
            parent_info = os.fstat(parent_fd)
            receipt = {"id": receipt_id, "original": str(source), "identity": identity,
                       "parent_identity": [parent_info.st_dev, parent_info.st_ino],
                       "sha256": expected_hash.lower(), "reason": reason.strip(),
                       "created": datetime.now(timezone.utc).isoformat()}
            fd = os.open(receipt_id + ".json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
                         0o600, dir_fd=vault_fd)
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump(receipt, stream, ensure_ascii=False)
                stream.flush()
                os.fsync(stream.fileno())
            os.fsync(vault_fd)
            move_no_replace(parent_fd, source.name, vault_fd, receipt_id + ".file")
    return {**receipt, "state": "quarantined"}


def restore(vault, receipt_id):
    if not re.fullmatch(r"[a-f0-9]{32}", receipt_id):
        raise ValueError("Invalid quarantine receipt identifier")
    with protected_directory(vault, vault=True) as (vault_path, vault_fd):
        fd = os.open(receipt_id + ".json", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=vault_fd)
        with os.fdopen(fd, "rb") as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise ValueError("Invalid quarantine receipt")
            receipt = json.loads(stream.read(8192))
        if receipt["id"] != receipt_id:
            raise ValueError("Quarantine receipt does not match its identifier")
        original = Path(receipt["original"])
        if not original.is_absolute() or original.is_relative_to(vault_path):
            raise ValueError("Invalid original location")
        with protected_directory(original.parent) as (_, parent_fd):
            parent_info = os.fstat(parent_fd)
            if [parent_info.st_dev, parent_info.st_ino] != receipt["parent_identity"]:
                raise ValueError("Original directory no longer matches the receipt")
            payload = receipt_id + ".file"
            try:
                identity = checked_identity(vault_fd, payload, receipt["sha256"])
            except FileNotFoundError:
                identity = checked_identity(parent_fd, original.name, receipt["sha256"])
                if identity != receipt["identity"]:
                    raise ValueError("Quarantine contents are missing and the original is different")
                return {**receipt, "state": "at_original_path"}
            if identity != receipt["identity"]:
                raise ValueError("Quarantine contents do not match the receipt")
            move_no_replace(vault_fd, payload, parent_fd, original.name)
    return {**receipt, "state": "restored"}
