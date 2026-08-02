"""Behaviour chain reconstruction for explanations."""

from __future__ import annotations

from backend.core.analysis import ChainDAG, ChainEdge, ChainNode, ChainStep
from backend.core.events import EventKind, KernelEvent
from backend.features.extractor import INTERPRETERS, SUSPICIOUS_DIRS


def build_chain(events: list[KernelEvent]) -> list[ChainStep]:
    """Rebuild a readable, ordered behaviour chain from a process family."""
    steps: list[ChainStep] = []
    for position, event in enumerate(sorted(events, key=lambda e: e.timestamp), start=1):
        description, suspicious = _describe(event)
        steps.append(
            ChainStep(
                position=position,
                description=description,
                kind=event.kind.value,
                exe=event.basename,
                pid=event.pid,
                suspicious=suspicious,
                detail=event.cwd,
            )
        )
    return steps


#: Event kinds that represent a process itself rather than an attached event.
_PROCESS_KINDS = {EventKind.PROCESS_CREATED, EventKind.EXEC, EventKind.PROCESS_EXITED}
#: Event kinds attached to their acting process as leaf nodes.
_ATTACHED_KINDS = {
    EventKind.NETWORK_CONNECT,
    EventKind.FILE_WRITE,
    EventKind.PRIVILEGE_ESCALATION,
    EventKind.SOCKET_BIND,
    EventKind.FILE_READ,
}


def build_dag(events: list[KernelEvent]) -> ChainDAG:
    """Build the behaviour-chain DAG.

    Processes are vertices; a ``spawn`` edge links a child to its parent
    process, and ``attach`` edges link leaf events (connections, writes,
    escalations) to the process that performed them. Roots are processes
    whose parent is not part of the chain.
    """
    nodes: list[ChainNode] = []
    edges: list[ChainEdge] = []
    process_node: dict[int, str] = {}  # pid -> node id
    child_of: dict[str, int] = {}  # node id -> parent pid

    def _pid_to_id(pid: int) -> str:
        # Merge PROCESS_CREATED and EXEC for the same pid into one node.
        if pid in process_node:
            return process_node[pid]
        node_id = f"p{pid}"
        process_node[pid] = node_id
        return node_id

    for event in sorted(events, key=lambda e: e.timestamp):
        description, suspicious = _describe(event)
        if event.kind in _PROCESS_KINDS:
            node_id = _pid_to_id(event.pid)
            # First sighting of a pid carries the lineage; a later EXEC adopts
            # the actually executed binary (bash -> curl for the same pid).
            existing = next((n for n in nodes if n.id == node_id), None)
            if existing is None:
                child_of[node_id] = event.ppid
                nodes.append(
                    ChainNode(
                        id=node_id,
                        pid=event.pid,
                        ppid=event.ppid,
                        exe=event.exe,
                        kind=event.kind.value,
                        timestamp=event.timestamp,
                        description=description,
                        suspicious=suspicious,
                    )
                )
            elif event.kind == EventKind.EXEC:
                existing.exe = event.exe
                existing.description = description
                existing.suspicious = suspicious
        elif event.kind in _ATTACHED_KINDS:
            node_id = _pid_to_id(event.pid)
            leaf_id = f"e{event.event_id}"
            nodes.append(
                ChainNode(
                    id=leaf_id,
                    pid=event.pid,
                    ppid=event.ppid,
                    exe=event.exe,
                    kind=event.kind.value,
                    timestamp=event.timestamp,
                    description=description,
                    suspicious=suspicious,
                )
            )
            edges.append(ChainEdge(source=node_id, target=leaf_id, kind="attach"))

    # Spawn edges between processes present in the chain.
    for node in list(nodes):
        parent_pid = child_of.get(node.id)
        if parent_pid in process_node and process_node[parent_pid] != node.id:
            edges.append(
                ChainEdge(source=process_node[parent_pid], target=node.id, kind="spawn")
            )

    roots = [
        node.id
        for node in nodes
        if node.kind in ("process_created", "exec")
        and child_of.get(node.id) not in process_node
    ]
    return ChainDAG(nodes=nodes, edges=edges, roots=roots)


def _describe(event: KernelEvent) -> tuple[str, bool]:
    kind = event.kind
    exe = event.basename
    parent_exe = event.cmdline[0].split("/")[-1] if event.cmdline else exe
    suspicious = False

    if kind == EventKind.PROCESS_CREATED:
        if exe in {i.split("/")[-1] for i in INTERPRETERS}:
            suspicious = True
            return f"{parent_exe} spawned script interpreter {exe}", suspicious
        return f"Process {exe} created", suspicious

    if kind == EventKind.EXEC:
        if event.exe.startswith(SUSPICIOUS_DIRS):
            suspicious = True
            return f"Executable launched from {event.exe}", suspicious
        return f"Executed {event.exe}", suspicious

    if kind == EventKind.NETWORK_CONNECT:
        ip = event.details.get("remote_ip")
        port = event.details.get("remote_port")
        suspicious = is_suspicious_connect(ip, port)
        return f"Outbound connection to {ip}:{port} (tcp)", suspicious

    if kind == EventKind.FILE_WRITE:
        path = event.details.get("path", "?")
        if any(path.startswith(d) for d in SUSPICIOUS_DIRS):
            suspicious = True
            return f"Payload written to {path}", suspicious
        return f"File write: {path}", suspicious

    if kind == EventKind.PRIVILEGE_ESCALATION:
        return (
            f"Privilege escalation {event.details.get('from_uid')} -> "
            f"{event.details.get('to_uid')}",
            True,
        )

    if kind == EventKind.PROCESS_EXITED:
        return f"Process {exe} exited", False

    return f"{kind.value}: {event.exe}", suspicious


def is_suspicious_connect(ip: str | None, port: int | None) -> bool:
    """Heuristic: is a remote connection suspicious on its own?"""
    if not ip or not port:
        return False
    if ip.startswith(("10.", "192.168.", "127.", "169.254.")):
        return False
    if ip == "127.0.0.1" or ip.startswith(("::1", "fe80:")):
        return False
    if port in (80, 443, 22, 53):
        return False
    return port > 1024
