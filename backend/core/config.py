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

DEFAULT_CONFIG_PATH = Path(__file__).resolve().parent.parent / "config" / "defaults.yaml"


@dataclass(slots=True)
class TelemetryConfig:
    polling_interval_seconds: float = 2.0
    window_seconds: int = 60
    provider: str = "process_monitor"
    audit_log_path: str = "/var/log/audit/audit.log"
    ring_capacity: int = 10_000
    max_events_per_collect: int = 500
    rate_limit_per_second: float = 0.0
    subprocess_queue_capacity: int = 10_000  # bounded stdout queue (tracee provider)
    subprocess_auto_restart: bool = True  # restart a dead tracee subprocess
    subprocess_restart_backoff_seconds: float = 1.0  # initial backoff (exponential)


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
    attribution_background_samples: int = 64


@dataclass(slots=True)
class ResponseConfig:
    auto_approve_destructive: bool = False
    dry_run: bool = True
    playbook_path: str | None = None  # YAML playbook rules; None = built-in defaults
    audit_path: str = "audit.jsonl"  # append-only, signed audit trail under data_dir
    signing_secret: str | None = None  # HMAC secret for audit signatures (env override recommended)


@dataclass(slots=True)
class StorageConfig:
    enabled: bool = True
    path: str = "guardian.db"  # SQLite file under data_dir
    save_events: bool = True
    save_reports: bool = True
    max_events: int = 100_000  # sliding-window cap for persisted events


@dataclass(slots=True)
class DashboardConfig:
    refresh_seconds: float = 3.0


@dataclass(slots=True)
class ServerConfig:
    """HTTP API + web dashboard server settings."""

    host: str = "127.0.0.1"
    port: int = 8000
    refresh_seconds: float = 1.0  # driver tick + WebSocket push cadence


@dataclass(slots=True)
class AuthConfig:
    """Role-based access control for the API.

    Tokens are mapped to users with roles. ``enabled=False`` grants every
    request all roles (convenient for local demo); production deployments
    enable it and set per-user tokens (overridable via ``GUARDIAN_TOKEN_<NAME>``
    env vars, e.g. ``GUARDIAN_TOKEN_ADMIN``).
    """

    enabled: bool = False
    token_header: str = "X-GUARDIAN-TOKEN"
    default_role: str = "viewer"
    users: list[dict[str, Any]] = field(default_factory=list)


@dataclass(slots=True)
class ExplainabilityConfig:
    narrative_provider: str = "rules"  # "rules" | "llm" (local model, optional)
    llm_endpoint: str = "http://127.0.0.1:11434"  # Ollama-compatible endpoint
    llm_model: str = "llama3.2:1b"
    llm_timeout_seconds: float = 10.0


@dataclass(slots=True)
class AppConfig:
    """Top-level application configuration bundle."""

    log_level: str = "INFO"
    data_dir: str = "data"
    telemetry: TelemetryConfig = field(default_factory=TelemetryConfig)
    detection: DetectionConfig = field(default_factory=DetectionConfig)
    explainability: ExplainabilityConfig = field(default_factory=ExplainabilityConfig)
    response: ResponseConfig = field(default_factory=ResponseConfig)
    storage: StorageConfig = field(default_factory=StorageConfig)
    dashboard: DashboardConfig = field(default_factory=DashboardConfig)
    server: ServerConfig = field(default_factory=ServerConfig)
    auth: AuthConfig = field(default_factory=AuthConfig)

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
        expl = raw.get("explainability", {})
        resp = raw.get("response", {})
        stor = raw.get("storage", {})
        dash = raw.get("dashboard", {})
        srv = raw.get("server", {})
        aut = raw.get("auth", {})
        return cls(
            log_level=raw.get("log_level", "INFO"),
            data_dir=raw.get("data_dir", "data"),
            telemetry=TelemetryConfig(**{k: v for k, v in tel.items()}),
            detection=DetectionConfig(**{k: v for k, v in det.items()}),
            explainability=ExplainabilityConfig(**{k: v for k, v in expl.items()}),
            response=ResponseConfig(**{k: v for k, v in resp.items()}),
            storage=StorageConfig(**{k: v for k, v in stor.items()}),
            dashboard=DashboardConfig(**{k: v for k, v in dash.items()}),
            server=ServerConfig(**{k: v for k, v in srv.items()}),
            auth=AuthConfig(**{k: v for k, v in aut.items()}),
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
