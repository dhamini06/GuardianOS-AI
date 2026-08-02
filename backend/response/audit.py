"""Append-only, signed audit trail for response decisions.

Every approval, execution and rollback is recorded to a JSONL file that can
only grow. Each record carries an HMAC-SHA256 signature (when a signing
secret is configured) and a hash of the previous record, so tampering with a
middle record breaks the chain for the rest of the file. Without a secret the
trail still records every entry, but ``sig`` stays ``None``.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
import time
from pathlib import Path
from typing import Any

from backend.core.logging import get_logger

logger = get_logger("response.audit")


class Signer:
    """HMAC-SHA256 signer for audit records."""

    def __init__(self, secret: str) -> None:
        self.secret = secret.encode("utf-8")

    def sign(self, payload: dict[str, Any]) -> str:
        message = _canonical(payload).encode("utf-8")
        return hmac.new(self.secret, message, hashlib.sha256).hexdigest()

    def verify(self, payload: dict[str, Any], signature: str) -> bool:
        return hmac.compare_digest(self.sign(payload), signature)


class AuditTrail:
    """Append-only, tamper-evident log of signed security events."""

    def __init__(self, path: str | Path | None) -> None:
        self.path = Path(path) if path else None
        self._lock = threading.Lock()
        self._seq = 0
        if self.path is not None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            # Resume the sequence counter from any existing records.
            for line in self._read_lines():
                try:
                    self._seq = int(json.loads(line)["seq"])
                except (ValueError, KeyError, json.JSONDecodeError):
                    continue

    @property
    def seq(self) -> int:
        return self._seq

    def record(
        self,
        event: str,
        *,
        report_id: str | None = None,
        actor: str = "system",
        data: dict[str, Any] | None = None,
        signer: Signer | None = None,
    ) -> dict[str, Any]:
        """Append one immutable record; returns the stored entry."""
        if self.path is None:
            return {}
        with self._lock:
            self._seq += 1
            prev = self._previous_digest()
            entry: dict[str, Any] = {
                "seq": self._seq,
                "ts": time.time(),
                "event": event,
                "report_id": report_id,
                "actor": actor,
                "data": data or {},
                "prev": prev,
                "sig": None,
            }
            if signer is not None:
                entry["sig"] = signer.sign(entry)
            line = json.dumps(entry, sort_keys=True, separators=(",", ":"))
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")
                fh.flush()
                os.fsync(fh.fileno())
            return entry

    def entries(self) -> list[dict[str, Any]]:
        if self.path is None or not self.path.exists():
            return []
        result: list[dict[str, Any]] = []
        for line in self._read_lines():
            try:
                result.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return result

    def verify_all(self, signer: Signer | None = None) -> tuple[bool, list[str]]:
        """Verify hash-chain integrity and (optionally) signatures."""
        problems: list[str] = []
        previous_digest = ""
        for entry in self.entries():
            if entry.get("prev") != previous_digest:
                problems.append(f"record {entry.get('seq')}: broken hash chain")
            previous_digest = hashlib.sha256(
                json.dumps(entry, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()
            if signer is not None and entry.get("sig") and not signer.verify(entry, entry["sig"]):
                problems.append(f"record {entry.get('seq')}: invalid signature")
        return not problems, problems

    def _previous_digest(self) -> str:
        lines = self._read_lines()
        if not lines:
            return ""
        return hashlib.sha256(lines[-1].encode()).hexdigest()

    def _read_lines(self) -> list[str]:
        if self.path is None or not self.path.exists():
            return []
        with self.path.open("r", encoding="utf-8") as fh:
            return [line.rstrip("\n") for line in fh if line.strip()]


def _canonical(payload: dict[str, Any]) -> str:
    """Deterministic string for signing: every field of the record."""
    return "|".join(
        [
            str(payload.get("seq", "")),
            str(payload.get("ts", "")),
            str(payload.get("event", "")),
            str(payload.get("report_id", "") or ""),
            str(payload.get("actor", "")),
            json.dumps(payload.get("data", {}), sort_keys=True, separators=(",", ":")),
            str(payload.get("prev", "") or ""),
        ]
    )
