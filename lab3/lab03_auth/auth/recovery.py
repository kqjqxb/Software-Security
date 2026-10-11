"""Другий чинник: одноразові коди відновлення."""
from __future__ import annotations

import hashlib
import hmac
import secrets

from auth.passwords import _peppered

ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # без схожих 0/O та 1/I
CODE_LENGTH = 12
GROUP = 4
CODE_COUNT = 10


def generate_codes(count: int = CODE_COUNT) -> list[str]:
    """Повертає count різних кодів виду XXXX-XXXX-XXXX (60 біт ентропії)."""
    codes: dict[str, None] = {}
    while len(codes) < count:
        raw = "".join(secrets.choice(ALPHABET) for _ in range(CODE_LENGTH))
        parts = (raw[i:i + GROUP] for i in range(0, CODE_LENGTH, GROUP))
        codes["-".join(parts)] = None
    return list(codes)


def _digest(code: str) -> bytes:
    normalized = "".join(ch for ch in code.upper() if ch.isalnum())
    return hashlib.sha256(_peppered(normalized.encode())).digest()


class RecoveryCodes:
    """Набір кодів одного користувача; зберігаються лише хеш-суми кодів."""

    def __init__(self, codes: list[str]) -> None:
        self._digests = [_digest(code) for code in codes]

    def verify(self, code: str) -> bool:
        """Приймає кожен код один раз; порівняння — за сталий час."""
        candidate = _digest(code)
        found = -1
        for index, digest in enumerate(self._digests):
            if hmac.compare_digest(digest, candidate):
                found = index
        if found < 0:
            return False
        del self._digests[found]
        return True

    def remaining(self) -> int:
        return len(self._digests)
