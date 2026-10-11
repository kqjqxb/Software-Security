"""Каркас диспетчера доступу (reference monitor)."""
from __future__ import annotations

import enum
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from typing import Callable, Iterable


class Permission(enum.Flag):
    NONE = 0
    READ = enum.auto()
    WRITE = enum.auto()
    DELETE = enum.auto()
    ADMIN = READ | WRITE | DELETE


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str


class Policy(ABC):
    @abstractmethod
    def evaluate(self, subject: str, obj: str, action: Permission) -> Decision:
        """Повертає рішення щодо запиту суб'єкта на дію над об'єктом."""


class AuditLog:
    """Реєстраційний журнал: фіксує кожне рішення монітора."""

    def __init__(self, clock: Callable[[], datetime] = datetime.now) -> None:
        self._clock = clock
        self._entries: list[dict] = []

    def record(self, subject: str, obj: str, action: Permission, decision: Decision) -> None:
        self._entries.append({
            "ts": self._clock().isoformat(timespec="seconds"),
            "subject": subject,
            "object": obj,
            "action": action.name,
            "allowed": decision.allowed,
            "reason": decision.reason,
        })

    def entries(self) -> list[dict]:
        return [dict(entry) for entry in self._entries]

    def dump(self) -> str:
        return "\n".join(
            f"{e['ts']}  {'ALLOW' if e['allowed'] else 'DENY '}  {e['subject']:<7} {e['action']:<6} "
            f"{e['object']:<6} {e['reason']}"
            for e in self._entries
        )


class ReferenceMonitor:
    """Єдина точка посередництва між суб'єктами та об'єктами."""

    def __init__(self, policy: Policy, audit: AuditLog | None = None) -> None:
        self._policy = policy
        self.audit = audit if audit is not None else AuditLog()

    def check(self, subject: str, obj: str, action: Permission) -> Decision:
        decision = self._policy.evaluate(subject, obj, action)
        self.audit.record(subject, obj, action, decision)
        return decision

    def enforce(self, subject: str, obj: str, action: Permission) -> None:
        decision = self.check(subject, obj, action)
        if not decision.allowed:
            raise PermissionError(f"{subject} -> {obj} [{action.name}]: {decision.reason}")


class AnomalyDetector(ABC):
    @abstractmethod
    def scan(self, log: AuditLog) -> list[str]:
        """Повертає перелік сповіщень про аномалії в журналі."""


def subjects_with_access(policy: Policy, subjects: Iterable[str], obj: str, action: Permission) -> list[str]:
    return [s for s in subjects if policy.evaluate(s, obj, action).allowed]
