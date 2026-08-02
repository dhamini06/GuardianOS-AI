"""Live terminal dashboard (MVP Layer 6).

Renders pipeline output with ``rich``: threat timeline, AI explanations,
MITRE mapping, recommended response actions and live system health.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict

import psutil
from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table

from backend.core.analysis import ChainDAG
from backend.core.logging import get_logger
from backend.pipeline import GuardianPipeline

logger = get_logger("dashboard.cli")


class CliDashboard:
    """Renders pipeline state to the terminal in near real-time."""

    def __init__(self, pipeline: GuardianPipeline, refresh_seconds: float = 3.0) -> None:
        self.pipeline = pipeline
        self.refresh_seconds = refresh_seconds
        self._console = Console()
        self._stop_flag = threading.Event()

    def run(self, duration_seconds: float | None = None) -> None:
        """Block and render until stopped or ``duration_seconds`` elapses."""
        self.pipeline.start()
        try:
            with Live(self._render(), console=self._console, refresh_per_second=4) as live:
                deadline = (
                    time.time() + duration_seconds if duration_seconds is not None else None
                )
                while not self._stop_flag.is_set():
                    if self.pipeline.learning:
                        self.pipeline.learning_step(min_windows=5)
                    else:
                        self.pipeline.analyze_window()
                    live.update(self._render())
                    if deadline is not None and time.time() >= deadline:
                        break
                    time.sleep(self.refresh_seconds)
        finally:
            self.pipeline.stop()

    def stop(self) -> None:
        self._stop_flag.set()

    # -- rendering --------------------------------------------------------
    def _render(self) -> Layout:
        layout = Layout()
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="body"),
            Layout(name="health", size=5),
        )
        layout["body"].split_row(
            Layout(name="threats", ratio=3),
            Layout(name="detail", ratio=2),
        )
        layout["header"].update(
            Panel(
                "[bold cyan]GuardianOS-AI[/]  kernel-level behavioural security  "
                f"(learning={'ON' if self.pipeline.learning else 'OFF'})  "
                f"baseline={len(self.pipeline._baseline)} samples  threats={len(self.pipeline.reports)}",
                style="bold",
            )
        )
        layout["threats"].update(self._threat_table())
        layout["detail"].update(self._detail_panel())
        layout["health"].update(self._health_panel())
        return layout

    def _threat_table(self) -> Table:
        table = Table(title="Detected Threats", header_style="bold magenta")
        table.add_column("Time", width=8)
        table.add_column("Severity", width=8)
        table.add_column("PID", width=6)
        table.add_column("Process", width=16)
        table.add_column("Score", width=6)
        table.add_column("MITRE", width=20)
        table.add_column("Actions", width=14)
        for report in reversed(self.pipeline.reports[-12:]):
            d = report.detection
            table.add_row(
                time.strftime("%H:%M:%S", time.localtime(report.timestamp)),
                d.severity.value.upper(),
                str(d.pid),
                d.exe,
                f"{d.anomaly_score:.2f}",
                ",".join(m.technique_id for m in report.explanation.mitre) or "-",
                f"{len(report.actions)} recommended",
            )
        return table

    def _detail_panel(self) -> Panel:
        if not self.pipeline.reports:
            return Panel(
                "[dim]No threats detected yet. Baseline learning is "
                "building a profile of normal machine behaviour...[/]",
                title="AI Explanation",
            )
        report = self.pipeline.reports[-1]
        lines = [
            f"[bold]{report.explanation.summary}[/]",
            "",
            *[f"[yellow]- {r}[/]" for r in report.explanation.reasons[:4]],
            "",
            "Behaviour chain:",
        ]
        lines += [
            f"  {s.position}. {'[red]' if s.suspicious else ''}{s.description}"
            f"{'[/]' if s.suspicious else ''}"
            for s in report.explanation.chain[:6]
        ]
        if report.explanation.mitre:
            lines.append("")
            lines += [
                f"  [cyan]MITRE {m.technique_id} {m.name}[/] ({m.tactic}, {m.confidence:.0%})"
                for m in report.explanation.mitre
            ]
        lines.append("")
        lines.append("Process DAG:")
        lines += [f"  {line}" for line in self._chain_dag_text(report.explanation.dag)]
        if report.actions:
            lines.append("")
            lines.append("[bold]Recommended response:[/]")
            for action in report.actions:
                lines.append(f"  - {action.action_type}: {action.description} [{action.status.value}]")
        return Panel(
            "\n".join(lines),
            title=f"AI Explanation  (report {report.report_id}, confidence {report.explanation.confidence:.0%})",
        )

    def _chain_dag_text(self, dag: ChainDAG | None) -> list[str]:
        """Render the behaviour-chain DAG as an ASCII process tree."""
        if not dag or not dag.nodes:
            return ["[dim]No behaviour-chain DAG available.[/]"]
        by_id = {n.id: n for n in dag.nodes}
        spawn: dict[str, list[str]] = defaultdict(list)
        attach: dict[str, list[str]] = defaultdict(list)
        for edge in dag.edges:
            (spawn if edge.kind == "spawn" else attach)[edge.source].append(edge.target)

        def node_label(node_id: str) -> str:
            node = by_id[node_id]
            exe = node.exe.split("/")[-1].split("\\")[-1] or node.exe
            text = f"{exe} [dim](pid {node.pid})[/]"
            return f"[red]{text}[/]" if node.suspicious else text

        out: list[str] = []

        def walk(node_id: str, prefix: str, last: bool) -> None:
            out.append(f"{prefix}{'└─ ' if last else '├─ '}{node_label(node_id)}")
            child_prefix = prefix + ("   " if last else "│  ")
            items = spawn.get(node_id, []) + attach.get(node_id, [])
            for index, child_id in enumerate(items):
                child_last = index == len(items) - 1
                glyph = "└─ " if child_last else "├─ "
                if child_id in by_id and child_id not in spawn:
                    leaf = by_id[child_id]
                    text = leaf.description
                    out.append(f"{child_prefix}{glyph}{'[red]' if leaf.suspicious else ''}{text}{'[/]' if leaf.suspicious else ''}")
                else:
                    walk(child_id, child_prefix, child_last)

        roots = dag.roots or [n.id for n in dag.nodes if n.kind in ("process_created", "exec")]
        for index, root in enumerate(roots):
            walk(root, "", index == len(roots) - 1)
        return out

    def _health_panel(self) -> Panel:
        cpu = psutil.cpu_percent(interval=None)
        mem = psutil.virtual_memory()
        procs = len(psutil.pids())
        events = self.pipeline.buffer.window(self.pipeline.config.telemetry.window_seconds)
        return Panel(
            f"[green]CPU[/] {cpu:5.1f}%   "
            f"[green]Memory[/] {mem.percent:5.1f}%   "
            f"[green]Processes[/] {procs}   "
            f"[green]Events in window[/] {len(events)}",
            title="System Health",
        )
