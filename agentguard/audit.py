"""Tamper-evident audit log.

Every decision is appended as a JSON line. Each entry carries the hash of
the previous entry, so editing, deleting or reordering any line breaks the
chain and ``verify()`` reports where.
"""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any, Callable, Iterable, Optional

from .models import canonical_json

GENESIS = "0" * 64


def _entry_hash(prev_hash: str, record: dict[str, Any]) -> str:
    return hashlib.sha256((prev_hash + canonical_json(record)).encode("utf-8")).hexdigest()


class AuditLog:
    def __init__(self, path: Optional[str | Path] = None, clock: Callable[[], float] = time.time) -> None:
        self.path = Path(path) if path else None
        self._clock = clock
        self.entries: list[dict[str, Any]] = []
        self._last_hash = GENESIS
        if self.path and self.path.exists():
            self.entries = list(read_entries(self.path))
            if self.entries:
                self._last_hash = self.entries[-1]["hash"]

    def append(self, record: dict[str, Any]) -> dict[str, Any]:
        body = {"seq": len(self.entries) + 1, "ts": round(self._clock(), 3), **record}
        entry = {**body, "prev": self._last_hash}
        entry["hash"] = _entry_hash(self._last_hash, body)
        self.entries.append(entry)
        self._last_hash = entry["hash"]
        if self.path:
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
        return entry

    def verify(self) -> tuple[bool, str]:
        return verify_entries(self.entries)


def read_entries(path: str | Path) -> Iterable[dict[str, Any]]:
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                yield json.loads(line)


def verify_entries(entries: Iterable[dict[str, Any]]) -> tuple[bool, str]:
    prev = GENESIS
    count = 0
    for count, entry in enumerate(entries, start=1):
        body = {k: v for k, v in entry.items() if k not in ("prev", "hash")}
        if entry.get("prev") != prev:
            return False, f"chain broken at entry {count}: previous-hash mismatch"
        if entry.get("hash") != _entry_hash(prev, body):
            return False, f"chain broken at entry {count}: entry was modified"
        if body.get("seq") != count:
            return False, f"chain broken at entry {count}: sequence number out of order"
        prev = entry["hash"]
    return True, f"audit log intact ({count} entries)"
