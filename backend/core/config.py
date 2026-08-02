"""Centralised configuration loading.

Configuration is hierarchical: file ``config/defaults.yaml`` provides the
baseline, an optional user file can override it, and constructor keyword
arguments win over everything. Values are exposed as a typed dataclass.
"""

from __future__ import annotations

import copy
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from backend.core.logging import setup_logging

DEFAULT_CONFIG_PATH = Path(__file__).resolve().parents[2] / "config" / "defaults.yaml"


@dataclass(slots=True)
class TelemetryConfig:
    polling_interval_seconds: float = 2.0
    window_seconds: int = 60
    provider: str = "process_monitor"
    audit_log_path: str = "/var/log/audit/audit.log"
    ring_capacity: int = 10_000
    max_events_per_collect: int = 500
    rate_limit_per_second: float = 0.0


@dataclass(slots=True)
class DetectionConfig:
    contamination: float = 0.01
    n_estimators: int = 200
    max_samples: int = 256
    normalise_threshold: float = 0.75
    flagged_threshold: float = 0.6
    min_baseline_samples: int = 25
    model_path: str | None = None
    autoload: bool = True
    refit_interval_windows: int = 10
    baseline_max_samples: int = 400


@dataclass(slots=True)
class ResponseConfig:
    auto_approve_destructive: bool = False
    dry_run: bool = True


@dataclass(slots=True)
class DashboardConfig:
    refresh_seconds: float = 3.0


@dataclass(slots=True)
class AppConfig:
    """Top-level application configuration bundle."""

    log_level: str = "INFO"
    data_dir: str = "data"
    telemetry: TelemetryConfig = field(default_factory=TelemetryConfig)
    detection: DetectionConfig = field(default_factory=DetectionConfig)
    response: ResponseConfig = field(default_factory=ResponseConfig)
    dashboard: DashboardConfig = field(default_factory=DashboardConfig)

    @classmethod
    def load(
        cls,
        path: Path | str | None = None,
        overrides: dict[str, Any] | None = None,
    ) -> AppConfig:
        """Load config from YAML, then apply dotted overrides.

        Overrides use dotted keys, e.g. ``{"telemetry.window_seconds": 120}``.
        """
        raw: dict[str, Any] = _load_yaml(path or DEFAULT_CONFIG_PATH)
        if overrides:
            for dotted, value in overrides.items():
                _set_dotted(raw, dotted, value)
        setup_logging(raw.get("log_level", "INFO"))
        return cls._from_dict(raw)

    @classmethod
    def _from_dict(cls, raw: dict[str, Any]) -> AppConfig:
        tel = raw.get("telemetry", {})
        det = raw.get("detection", {})
        resp = raw.get("response", {})
        dash = raw.get("dashboard", {})
        return cls(
            log_level=raw.get("log_level", "INFO"),
            data_dir=raw.get("data_dir", "data"),
            telemetry=TelemetryConfig(**{k: v for k, v in tel.items()}),
            detection=DetectionConfig(**{k: v for k, v in det.items()}),
            response=ResponseConfig(**{k: v for k, v in resp.items()}),
            dashboard=DashboardConfig(**{k: v for k, v in dash.items()}),
        )


def _load_yaml(path: Path | str) -> dict[str, Any]:
    p = Path(path)
    if not p.exists():
        return {}
    with p.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    return copy.deepcopy(data)


def _set_dotted(target: dict[str, Any], dotted: str, value: Any) -> None:
    parts = dotted.split(".")
    node = target
    for part in parts[:-1]:
        node = node.setdefault(part, {})
    node[parts[-1]] = value


def env_bool(name: str, default: bool = False) -> bool:
    """Read a boolean from the environment (GO_* variables)."""
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}
