"""Сховище документів: кожна операція проходить через монітор доступу."""
from __future__ import annotations

import json
import time
from typing import Callable

from accesscontrol.monitor import AuditLog, Permission, ReferenceMonitor


class TimedAuditLog(AuditLog):
    """Реєстраційний журнал із заданим джерелом часу для відтворюваних сценаріїв."""

    def __init__(self, clock: Callable[[], float]) -> None:
        super().__init__()
        self._clock = clock

    def _now(self) -> float:
        return self._clock()


class OperationLog:
    """Операційний журнал: фіксує лише виконані зміни стану."""

    def __init__(self, clock: Callable[[], float] = time.time) -> None:
        self._clock = clock
        self._records: list[dict] = []

    def record(self, subject: str, obj: str, operation: str) -> None:
        self._records.append({"ts": self._clock(), "subject": subject, "object": obj, "operation": operation})

    def entries(self) -> list[dict]:
        return list(self._records)

    def dump(self) -> str:
        return "\n".join(json.dumps(r, ensure_ascii=False) for r in self._records)


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
