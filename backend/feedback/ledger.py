"""Analyst feedback ledger: confirmed verdicts persist across restarts.

Feedback turns the one-way detection pipeline into a closed loop. An analyst
marks a flagged chain as ``benign`` (false positive - the detector learns it
as normal) or ``malicious`` (confirmed attack - the chain is excluded from
the normal baseline and recorded for future supervised training). Verdicts
are persisted as JSONL so the model keeps learning between deployments.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

from backend.core.logging import get_logger

logger = get_logger("feedback.ledger")

BENIGN = "benign"
MALICIOUS = "malicious"
VERDICTS = (BENIGN, MALICIOUS)


class FeedbackLedger:
    """Latest-verdict-per-chain store, persisted as JSONL.

    ``record()`` keeps the most recent verdict for a chain (a chain that was
    once flagged and later confirmed benign wins over an older label) and
    rewrites the store so the on-disk state mirrors memory.
    """

    def __init__(self, path: str | Path | None = None) -> None:
        self._path = Path(path) if path else None
        self._entries: dict[str, dict] = {}
        if self._path and self._path.exists():
            self._load()

    def record(
        self,
        chain_key: str,
        verdict: str,
        *,
        report_id: str | None = None,
        note: str | None = None,
    ) -> bool:
        """Record an analyst verdict; returns True if it changed the label."""
        if verdict not in VERDICTS:
            raise ValueError(f"verdict must be one of {VERDICTS}")
        entry = {
            "chain_key": chain_key,
            "verdict": verdict,
            "report_id": report_id,
            "note": note,
            "timestamp": time.time(),
        }
        changed = self._entries.get(chain_key, {}).get("verdict") != verdict
        self._entries[chain_key] = entry
        if self._path:
            self.save()
        return changed

    def verdict_for(self, chain_key: str) -> str | None:
        entry = self._entries.get(chain_key)
        return entry["verdict"] if entry else None

    @property
    def benign_keys(self) -> set[str]:
        return {k for k, v in self._entries.items() if v["verdict"] == BENIGN}

    @property
    def malicious_keys(self) -> set[str]:
        return {k for k, v in self._entries.items() if v["verdict"] == MALICIOUS}

    @property
    def entries(self) -> dict[str, dict]:
        return dict(self._entries)

    def summary(self) -> dict[str, int]:
        return {"benign": len(self.benign_keys), "malicious": len(self.malicious_keys)}

    def save(self) -> None:
        if not self._path:
            return
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with self._path.open("w", encoding="utf-8") as fh:
            for entry in self._entries.values():
                fh.write(json.dumps(entry) + "\n")

    def _load(self) -> None:
        if self._path is None:
            return
        with self._path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    logger.warning("Skipping malformed feedback line in %s", self._path)
                    continue
                self._entries[entry["chain_key"]] = entry
        logger.info("Loaded %d feedback verdict(s) from %s", len(self._entries), self._path)
