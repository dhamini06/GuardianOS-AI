"""Explainability layer (Layer 4).

Converts raw AI scores and event history into analyst-friendly, evidence-backed
explanations: *why* something was flagged, what the behaviour chain looked
like, and which MITRE ATT&CK techniques it resembles.
"""

from backend.explainability.base import Explainer, ExplainerError
from backend.explainability.explainer import RuleBasedExplainer

__all__ = ["Explainer", "ExplainerError", "RuleBasedExplainer"]
