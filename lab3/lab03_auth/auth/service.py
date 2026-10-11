"""Підсистема автентифікації: пароль, блокування і код відновлення."""
from __future__ import annotations

from dataclasses import dataclass

from auth.anderson import min_length, required_space
from auth.lockout import FixedLockout
from auth.passwords import hash_password, verify_password
from auth.recovery import RecoveryCodes, generate_codes

# Трійка Андерсона варіанта 12: R = 20/хв, T = 30 діб, P = 1e-6; алфавіт 95.
MIN_PASSWORD_LENGTH = min_length(required_space(20, 30, 1e-6), 95)

OK, DENIED, LOCKED = "вхід дозволено", "відмова", "заблоковано"


@dataclass
class _User:
    password_hash: str
    codes: RecoveryCodes


class AuthService:
    def __init__(self, lockout: FixedLockout | None = None) -> None:
        self.lockout = lockout or FixedLockout()
        self._users: dict[str, _User] = {}
        self._dummy_hash = hash_password("відсутній обліковий запис")

    def register(self, account: str, password: str) -> list[str]:
        """Створює обліковий запис і повертає коди відновлення (один раз)."""
        if account in self._users:
            raise ValueError("обліковий запис уже існує")
        if len(password) < MIN_PASSWORD_LENGTH:
            raise ValueError(
                f"пароль коротший за {MIN_PASSWORD_LENGTH} символів")
        codes = generate_codes()
        self._users[account] = _User(hash_password(password),
                                     RecoveryCodes(codes))
        return codes

    def login(self, account: str, password: str, code: str,
              now: float) -> str:
        """Перевіряє пароль, а потім код; обидві відмови рахує блокування."""
        if not self.lockout.is_allowed(account, now):
            return LOCKED
        user = self._users.get(account)
        stored = user.password_hash if user else self._dummy_hash
        ok = verify_password(stored, password) and user is not None
        ok = ok and user.codes.verify(code)
        self.lockout.record_attempt(account, ok, now)
        return OK if ok else DENIED

    def codes_left(self, account: str) -> int:
        return self._users[account].codes.remaining()
