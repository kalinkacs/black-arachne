"""Bounded, read-only file inventory and comparison with trusted SHA-256 indicators."""

from contextlib import closing
import errno
import hashlib
import os
from pathlib import Path
import re
import stat

from .events import read_records

CHUNK_SIZE = 65_536
SKIP_ERRORS = {errno.ELOOP, errno.ENOENT, errno.ENOTDIR}


def load_indicators(stream):
    indicators = {}
    for row in read_records(stream):
        if not isinstance(row, dict) or set(row) != {"sha256", "label"}:
            raise ValueError("Each indicator must contain sha256 and label")
        digest, label = row["sha256"], row["label"]
        if not isinstance(digest, str) or not re.fullmatch(r"[a-fA-F0-9]{64}", digest):
            raise ValueError("Invalid SHA-256 indicator")
        if not isinstance(label, str) or not label.strip() or len(label) > 200:
            raise ValueError("Provide a 1–200 character indicator label")
        digest = digest.lower()
        if digest in indicators and indicators[digest] != label:
            raise ValueError("An indicator has conflicting labels")
        indicators[digest] = label
    if not indicators:
        raise ValueError("Indicator file is empty")
    return indicators


def check_file(directory, name, max_bytes):
    read = 0
    try:
        before = os.stat(name, dir_fd=directory, follow_symlinks=False)
        if not stat.S_ISREG(before.st_mode):
            return "non_regular", 0, {"sha256": None, "mode": stat.S_IMODE(before.st_mode), "kind": stat.S_IFMT(before.st_mode)}
        if before.st_size > max_bytes:
            return "too_large", 0, None
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory)
        with os.fdopen(fd, "rb", buffering=0) as stream:
            opened = os.fstat(stream.fileno())
            if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
                return "changed", 0, None
            digest = hashlib.sha256()
            while read < max_bytes:
                data = stream.read(min(CHUNK_SIZE, max_bytes - read))
                if not data:
                    break
                read += len(data)
                digest.update(data)
            after = os.fstat(stream.fileno())
            if read != after.st_size or (after.st_size, after.st_mtime_ns, after.st_ctime_ns) != (
                opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns
            ):
                return "changed", read, None
            return "scanned", read, {"sha256": digest.hexdigest(), "mode": stat.S_IMODE(after.st_mode), "kind": stat.S_IFREG}
    except OSError as error:
        return ("changed" if error.errno in SKIP_ERRORS else "unreadable"), read, None



FILE_LIMITS = {"max_files": 1000, "max_bytes": 32 * 1024 * 1024, "total_bytes": 256 * 1024 * 1024}


def inventory(root, *, max_files=FILE_LIMITS["max_files"], max_bytes=FILE_LIMITS["max_bytes"],
              total_bytes=FILE_LIMITS["total_bytes"], include_linked_dirs=True):
    if min(max_files, max_bytes, total_bytes) < 1:
        raise ValueError("Scanner limits must be positive")
    root = Path(root).absolute()
    initial = root.lstat()
    if not stat.S_ISDIR(initial.st_mode):
        raise ValueError("Scan root must be a real directory")
    counts = {status: 0 for status in ("scanned", "non_regular", "too_large", "changed", "unreadable")}
    report = {"root": str(root), "counts": counts, "bytes_read": 0, "limit_reached": False, "directories": 0}
    entries = {}

    def visit_error(error):
        counts["unreadable"] += 1

    with closing(os.fwalk(root, follow_symlinks=False, onerror=visit_error)) as walk:
        for path, dirs, files, fd in walk:
            if report["directories"] >= max_files:
                report["limit_reached"] = True
                break
            report["directories"] += 1
            prefix = Path(path).relative_to(root)
            # Directory symlinks are not traversed. Record their presence so
            # that replacement of a monitored file remains observable.
            descend = []
            for name in sorted(dirs):
                try:
                    info = os.stat(name, dir_fd=fd, follow_symlinks=False)
                except OSError:
                    counts["changed"] += 1
                    continue
                if stat.S_ISDIR(info.st_mode):
                    descend.append(name)
                elif include_linked_dirs:
                    files.append(name)
            dirs[:] = descend
            for name in sorted(files):
                remaining = total_bytes - report["bytes_read"]
                if sum(counts.values()) >= max_files or remaining <= 0:
                    report["limit_reached"] = True
                    break
                status, read, snapshot = check_file(fd, name, min(max_bytes, remaining))
                counts[status] += 1
                report["bytes_read"] += read
                if snapshot is not None:
                    entries[str(prefix / name)] = snapshot
            if report["limit_reached"]:
                break
    final = root.lstat()
    if (final.st_dev, final.st_ino) != (initial.st_dev, initial.st_ino):
        raise ValueError("Scan root changed during inventory")
    report["root_identity"] = [initial.st_dev, initial.st_ino]
    return report, entries


def scan(root, indicators, *, max_files=FILE_LIMITS["max_files"], max_bytes=FILE_LIMITS["max_bytes"],
         total_bytes=FILE_LIMITS["total_bytes"]):
    report, entries = inventory(root, max_files=max_files, max_bytes=max_bytes,
                                total_bytes=total_bytes, include_linked_dirs=False)
    return {**report, "matched": [
        {"path": path, "sha256": entry["sha256"], "label": indicators[entry["sha256"]]}
        for path, entry in entries.items() if entry["sha256"] in indicators
    ]}
