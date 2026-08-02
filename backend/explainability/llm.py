"""Optional local-LLM narrative generation for analyst prose.

The rule-based summary in :mod:`backend.explainability.attribution` is the
default. When configured, the explainer can ask a local model (Ollama-
compatible `/api/generate` endpoint) for richer analyst prose. LLM failures
are never fatal: they log a warning and fall back to the deterministic
summary, so an unreachable or missing model cannot take the pipeline down.
"""

from __future__ import annotations

import json
import urllib.request

from backend.core.analysis import Explanation
from backend.core.logging import get_logger

logger = get_logger("explainability.llm")


class LlmNarrativeGenerator:
    """Generates analyst narratives from a local model via the Ollama API."""

    def __init__(
        self,
        *,
        endpoint: str,
        model: str,
        timeout: float = 10.0,
        max_tokens: int = 240,
    ) -> None:
        self._endpoint = endpoint.rstrip("/") + "/api/generate"
        self._model = model
        self._timeout = timeout
        self._max_tokens = max_tokens

    def summarize(self, explanation: Explanation) -> str | None:
        """Return LLM narrative prose, or ``None`` on any failure."""
        payload = json.dumps(
            {
                "model": self._model,
                "prompt": _build_prompt(explanation),
                "stream": False,
                "options": {"temperature": 0.2, "num_predict": self._max_tokens},
            }
        ).encode("utf-8")
        try:
            request = urllib.request.Request(
                self._endpoint,
                data=payload,
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(request, timeout=self._timeout) as response:
                data = json.loads(response.read().decode("utf-8"))
            text = (data.get("response") or "").strip()
            return text or None
        except Exception as exc:  # noqa: BLE001 - any failure must degrade safely
            logger.warning(
                "LLM narrative unavailable (%s); using rule-based summary", exc
            )
            return None


def _build_prompt(explanation: Explanation) -> str:
    chain = " -> ".join(s.description for s in explanation.chain) or "n/a"
    mitre = ", ".join(
        f"{m.technique_id} {m.name} ({m.confidence:.0%})" for m in explanation.mitre
    ) or "none"
    return "\n".join(
        [
            "You are a senior incident-response analyst. Write a concise 2-3 "
            "sentence narrative for a threat report. Do not invent evidence; "
            "use only the facts provided.",
            "",
            f"Summary: {explanation.summary}",
            f"Reasons: {'; '.join(explanation.reasons)}",
            f"Behaviour chain: {chain}",
            f"MITRE techniques: {mitre}",
            f"Severity: {explanation.severity.value}, confidence: {explanation.confidence:.0%}",
            "",
            "Narrative:",
        ]
    )
