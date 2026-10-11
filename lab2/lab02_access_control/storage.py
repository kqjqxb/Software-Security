"""Сховище документів: кожна операція проходить через монітор доступу."""
from __future__ import annotations

from datetime import datetime
from typing import Callable

from accesscontrol.monitor import Permission, ReferenceMonitor


class OperationLog:
    """Операційний журнал: фіксує лише виконані зміни стану."""

    def __init__(self, clock: Callable[[], datetime] = datetime.now) -> None:
        self._clock = clock
        self._entries: list[dict] = []

    def record(self, subject: str, obj: str, operation: str) -> None:
        self._entries.append({
            "ts": self._clock().isoformat(timespec="seconds"),
            "subject": subject,
            "object": obj,
            "operation": operation,
        })

    def entries(self) -> list[dict]:
        return [dict(entry) for entry in self._entries]

    def dump(self) -> str:
        return "\n".join(f"{e['ts']}  {e['subject']:<7} {e['operation']:<6} {e['object']}" for e in self._entries)


class DocumentStore:
    def __init__(self, monitor: ReferenceMonitor, documents: dict[str, str], oplog: OperationLog | None = None) -> None:
        self._monitor = monitor
        self._documents = dict(documents)
        self.oplog = oplog if oplog is not None else OperationLog()

    def read(self, subject: str, obj: str) -> str:
        self._monitor.enforce(subject, obj, Permission.READ)
        return self._documents[obj]

    def write(self, subject: str, obj: str, text: str) -> None:
        self._monitor.enforce(subject, obj, Permission.WRITE)
        self._documents[obj] = text
        self.oplog.record(subject, obj, "WRITE")

    def delete(self, subject: str, obj: str) -> None:
        self._monitor.enforce(subject, obj, Permission.DELETE)
        del self._documents[obj]
        self.oplog.record(subject, obj, "DELETE")
