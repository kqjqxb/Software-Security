"""Перевірка автентифікованого шифрування варіанта 12 (крок 4)."""
from __future__ import annotations

import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

from crypto_lab.aead import NONCE_SIZE, TAG_SIZE, decrypt, encrypt

KEY = b"0" * 32  # ТЕСТОВИЙ КЛЮЧ — не використовувати поза стендом
OTHER_KEY = b"9" * 32  # ТЕСТОВИЙ КЛЮЧ — не використовувати поза стендом
MESSAGE = b"secret payload"
HEADER = b"hdr"


def flip_bit(data: bytes, bit: int) -> bytes:
    index, mask = bit // 8, 1 << (bit % 8)
    return data[:index] + bytes([data[index] ^ mask]) + data[index + 1:]


def accepted(blob: bytes, key: bytes = KEY, associated: bytes = HEADER) -> bool:
    try:
        decrypt(blob, key, associated)
        return True
    except InvalidTag:
        return False


def verdict(ok: bool) -> str:
    return "ПОМИЛКА: підміну не виявлено" if ok else "InvalidTag, даних не видано"


def stream_only(data: bytes, key: bytes, nonce: bytes) -> bytes:
    """ChaCha20 без Poly1305: лише шифрування, цілісність не контролюється."""
    # ВРАЗЛИВО: шифротекст без тегу – зміну в каналі приймач не помітить
    encryptor = Cipher(algorithms.ChaCha20(key, nonce), mode=None).encryptor()
    return encryptor.update(data)


def main() -> None:
    blob = encrypt(MESSAGE, KEY, associated=HEADER)
    body = len(blob) - NONCE_SIZE - TAG_SIZE
    print(f"відкритий текст {len(MESSAGE)} байтів -> пакет {len(blob)} байтів: "
          f"nonce {NONCE_SIZE} + шифротекст {body} + тег {TAG_SIZE}")
    print(f"nonce:      {blob[:NONCE_SIZE].hex()}")
    print(f"шифротекст: {blob[NONCE_SIZE:-TAG_SIZE].hex()}")
    print(f"тег:        {blob[-TAG_SIZE:].hex()}")
    print(f"розшифрування: {decrypt(blob, KEY, associated=HEADER)!r}")

    again = encrypt(MESSAGE, KEY, associated=HEADER)
    print(f"повторне шифрування дає інший nonce: {again[:12] != blob[:12]}, "
          f"інший шифротекст: {again[12:] != blob[12:]}")
    nonces = {encrypt(MESSAGE, KEY)[:NONCE_SIZE] for _ in range(10_000)}
    print(f"різних nonce у 10000 шифруваннях: {len(nonces)}")

    last = len(blob) * 8 - 1
    print(f"змінено біт тегу: {verdict(accepted(flip_bit(blob, last)))}")
    print("змінено біт шифротексту: "
          f"{verdict(accepted(flip_bit(blob, NONCE_SIZE * 8)))}")
    print(f"змінено біт nonce: {verdict(accepted(flip_bit(blob, 0)))}")
    print("змінено біт асоційованих даних: "
          f"{verdict(accepted(blob, associated=flip_bit(HEADER, 0)))}")
    print(f"асоційовані дані відсутні: {verdict(accepted(blob, associated=b''))}")
    print(f"інший ключ: {verdict(accepted(blob, key=OTHER_KEY))}")
    rejected = sum(not accepted(flip_bit(blob, bit)) for bit in range(last + 1))
    print(f"однобітових змін пакета відхилено: {rejected} із {last + 1}")

    print("-- лише шифрування, без тегу --")
    nonce = os.urandom(16)
    cipher = stream_only(MESSAGE, KEY, nonce)
    received = stream_only(flip_bit(cipher, 0), KEY, nonce)
    print(f"змінено біт шифротексту: приймач без помилки отримав {received!r}")


if __name__ == "__main__":
    main()
