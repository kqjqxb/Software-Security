"""Симетричне шифрування — КАРКАС для лабораторної роботи 4.

Здобувач реалізує шифрування за AEAD свого варіанта і демонструє наслідки
двох типових помилок зі свого завдання (ECB, повторний nonce тощо).

Варіант 12: ChaCha20-Poly1305. Формат результату: nonce ‖ шифротекст ‖ тег.
"""
from __future__ import annotations

import os

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

KEY_SIZE = 32
NONCE_SIZE = 12
TAG_SIZE = 16


def encrypt(plaintext: bytes, key: bytes, associated: bytes = b"") -> bytes:
    """БЕЗПЕЧНО: автентифіковане шифрування ChaCha20-Poly1305.

    Вимоги:
      – унікальний nonce на кожне повідомлення (лекція 10);
      – прив'язка асоційованих даних;
      – повернення nonce разом із шифротекстом і тегом.
    """
    nonce = os.urandom(NONCE_SIZE)
    sealed = ChaCha20Poly1305(key).encrypt(nonce, plaintext, associated)
    return nonce + sealed


def decrypt(blob: bytes, key: bytes, associated: bytes = b"") -> bytes:
    """Перевіряє тег і повертає відкритий текст; за розбіжності — InvalidTag."""
    if len(blob) < NONCE_SIZE + TAG_SIZE:
        raise ValueError("Повідомлення коротше за nonce і тег")
    nonce, sealed = blob[:NONCE_SIZE], blob[NONCE_SIZE:]
    return ChaCha20Poly1305(key).decrypt(nonce, sealed, associated)
