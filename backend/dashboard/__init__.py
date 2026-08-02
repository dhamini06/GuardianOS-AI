"""Dashboard layer (Layer 6). MVP ships a terminal dashboard; a web dashboard
is planned for a later milestone behind the same report data model."""

from backend.dashboard.cli import CliDashboard

__all__ = ["CliDashboard"]
