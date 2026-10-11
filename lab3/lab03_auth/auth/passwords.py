"""Зберігання та перевірка паролів — КАРКАС для лабораторної роботи 3.

Здобувач реалізує функцію зберігання за KDF свого варіанта
(Argon2id / scrypt / bcrypt / PBKDF2), додає «перець» і перевірку за сталий час.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os


PEPPER = os.environ.get("AUTH_PEPPER", "").encode()

ALGORITHM = "pbkdf2_sha256"
ITERATIONS = 600_000  # не менше 600 000 для PBKDF2-HMAC-SHA256
SALT_BYTES = 16
KEY_BYTES = 32


# ВРАЗЛИВИЙ зразок (для порівняння у звіті) — НЕ використовувати:
def hash_password_insecure(password: str) -> str:
    # ВРАЗЛИВО: швидка хеш-функція без солі — вразлива до райдужних таблиць.
    return hashlib.sha256(password.encode()).hexdigest()


def hash_password(password: str) -> str:
    """БЕЗПЕЧНО: PBKDF2-HMAC-SHA256 із сіллю та «перцем».

    Формат рядка: pbkdf2_sha256$<ітерації>$<b64(сіль)>$<b64(ключ)>.
    """
    salt = os.urandom(SALT_BYTES)
    key = _derive(password, salt, ITERATIONS)
    return f"{ALGORITHM}${ITERATIONS}${_b64(salt)}${_b64(key)}"


def verify_password(stored: str, password: str) -> bool:
    """Перевірка пароля. Порівняння ключів — лише за сталий час."""
    try:
        algorithm, iterations, salt, expected = stored.split("$")
        if algorithm != ALGORITHM:
            return False
        key = _derive(password, _unb64(salt), int(iterations))
        return hmac.compare_digest(key, _unb64(expected))
    except ValueError:
        return False


def _derive(password: str, salt: bytes, iterations: int) -> bytes:
    data = _peppered(password.encode())
    return hashlib.pbkdf2_hmac("sha256", data, salt, iterations, KEY_BYTES)


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def _unb64(text: str) -> bytes:
    return base64.b64decode(text, validate=True)


def _peppered(data: bytes) -> bytes:
    return hmac.new(PEPPER, data, hashlib.sha256).digest() if PEPPER else data
