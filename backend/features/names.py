"""Canonical feature schema for the detection engine.

Feature names are stable identifiers shared by feature extraction, model
training, and explainability. Changing this list invalidates persisted
models, so it is versioned explicitly.
"""

FEATURE_NAMES: list[str] = [
    "num_children",
    "exec_frequency",
    "unique_binaries_spawned",
    "script_interpreters",
    "tmp_execs",
    "downloads",
    "unique_remote_ips",
    "connections_per_min",
    "suspicious_ports",
    "file_writes_per_min",
    "privilege_escalations",
    "process_depth",
    "chain_length",
]


class FeatureLabels:
    """Human-readable, explainer-facing descriptions for each feature."""

    LABELS: dict[str, str] = {
        "num_children": "number of child processes spawned",
        "exec_frequency": "execution rate (exec events per second)",
        "unique_binaries_spawned": "distinct binaries launched by this process",
        "script_interpreters": "script interpreters (python/bash/perl/sh) spawned",
        "tmp_execs": "executions from world-writable dirs (/tmp, /dev/shm)",
        "downloads": "outbound downloads to remote hosts",
        "unique_remote_ips": "distinct remote IPs contacted",
        "connections_per_min": "network connections per minute",
        "suspicious_ports": "connections to non-standard high ports",
        "file_writes_per_min": "file writes per minute",
        "privilege_escalations": "privilege escalation events",
        "process_depth": "depth of this process in the process tree",
        "chain_length": "length of the observed behaviour chain",
    }

    @classmethod
    def describe(cls, feature: str) -> str:
        return cls.LABELS.get(feature, feature.replace("_", " "))
