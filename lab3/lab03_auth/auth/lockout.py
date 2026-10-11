"""Блокування облікового запису: фіксоване, на 15 хв після 5 невдалих спроб."""
from __future__ import annotations

from dataclasses import dataclass

MAX_FAILURES = 5
LOCK_SECONDS = 15 * 60


@dataclass
class _State:
    failures: int = 0
    locked_until: float = 0.0


class FixedLockout:
    """Лічильник невдалих спроб поспіль; стан зберігається в пам'яті процесу."""

    def __init__(self, max_failures: int = MAX_FAILURES,
                 lock_seconds: float = LOCK_SECONDS) -> None:
        self.max_failures = max_failures
        self.lock_seconds = lock_seconds
        self._accounts: dict[str, _State] = {}

    def is_allowed(self, account: str, now: float) -> bool:
        state = self._accounts.get(account)
        return state is None or now >= state.locked_until

    def record_attempt(self, account: str, ok: bool, now: float) -> None:
        if not self.is_allowed(account, now):
            return
        state = self._accounts.get(account)
        if ok or (state and state.failures >= self.max_failures):
            self._accounts.pop(account, None)
            state = None
        if ok:
            return
        if state is None:
            state = self._accounts[account] = _State()
        state.failures += 1
        if state.failures >= self.max_failures:
            state.locked_until = now + self.lock_seconds

    def failures(self, account: str) -> int:
        state = self._accounts.get(account)
        return state.failures if state else 0

    def locked_until(self, account: str) -> float | None:
        state = self._accounts.get(account)
        return state.locked_until if state and state.locked_until else None


_default = FixedLockout()


def record_attempt(account: str, ok: bool, now: float) -> None:
    """Реєструє спробу входу в політиці з параметрами варіанта."""
    _default.record_attempt(account, ok, now)


def is_allowed(account: str, now: float) -> bool:
    """Чи дозволено обліковому запису чергову спробу в момент now."""
    return _default.is_allowed(account, now)
