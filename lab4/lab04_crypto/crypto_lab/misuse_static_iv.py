"""Помилка варіанта: статичний вектор ініціалізації в режимі CBC (крок 5)."""
from __future__ import annotations

import os

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

BLOCK = 16
STATIC_IV = bytes(BLOCK)
KEY = b"1" * 32  # ТЕСТОВИЙ КЛЮЧ — не використовувати поза стендом

REPORT_DRAFT = b"dept=FIN;doc=report-2026;page=01;status=draft"
REPORT_FINAL = b"dept=FIN;doc=report-2026;page=01;status=final"
MEMO = b"dept=HR;doc=memo-0007;page=03;status=draft"
SERIES = [REPORT_DRAFT, MEMO, REPORT_DRAFT, REPORT_FINAL, REPORT_DRAFT]


def _cbc_encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    padder = padding.PKCS7(BLOCK * 8).padder()
    data = padder.update(plaintext) + padder.finalize()
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return encryptor.update(data) + encryptor.finalize()


def encrypt_static_iv(plaintext: bytes, key: bytes) -> bytes:
    """Шифрування AES-CBC з незмінним вектором ініціалізації."""
    # ВРАЗЛИВО: той самий IV для всіх повідомлень – шифрування детерміноване
    return _cbc_encrypt(plaintext, key, STATIC_IV)


def encrypt_random_iv(plaintext: bytes, key: bytes) -> bytes:
    """Шифрування AES-CBC; результат: IV ‖ шифротекст."""
    # БЕЗПЕЧНО: новий випадковий IV на кожне повідомлення, IV передається відкрито
    iv = os.urandom(BLOCK)
    return iv + _cbc_encrypt(plaintext, key, iv)


def decrypt_random_iv(blob: bytes, key: bytes) -> bytes:
    iv, body = blob[:BLOCK], blob[BLOCK:]
    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    data = decryptor.update(body) + decryptor.finalize()
    unpadder = padding.PKCS7(BLOCK * 8).unpadder()
    return unpadder.update(data) + unpadder.finalize()


def blocks(data: bytes) -> list[bytes]:
    return [data[i:i + BLOCK] for i in range(0, len(data), BLOCK)]


def common_prefix_blocks(first: bytes, second: bytes) -> int:
    """Кількість однакових перших блоків двох шифротекстів."""
    count = 0
    for a, b in zip(blocks(first), blocks(second)):
        if a != b:
            break
        count += 1
    return count


def show(label: str, data: bytes) -> None:
    print(f"{label:<14}" + " ".join(b.hex()[:16] + "…" for b in blocks(data)))


def main() -> None:
    pairs = [("однакові повідомлення", REPORT_DRAFT, REPORT_DRAFT),
             ("спільні перші 40 байтів", REPORT_DRAFT, REPORT_FINAL),
             ("різні початки", REPORT_DRAFT, MEMO)]

    print("== Статичний IV ==")
    for name, data in (("draft", REPORT_DRAFT), ("draft ще раз", REPORT_DRAFT),
                       ("final", REPORT_FINAL), ("memo", MEMO)):
        show(name, encrypt_static_iv(data, KEY))
    for title, a, b in pairs:
        ca, cb = encrypt_static_iv(a, KEY), encrypt_static_iv(b, KEY)
        print(f"{title}: спільних перших блоків "
              f"{common_prefix_blocks(ca, cb)} із {len(blocks(ca))}, "
              f"шифротексти рівні: {ca == cb}")
    unique = len({encrypt_static_iv(m, KEY) for m in SERIES})
    print(f"серія з {len(SERIES)} повідомлень ({len(set(SERIES))} різних): "
          f"різних шифротекстів {unique}")

    print("\n== Випадковий IV ==")
    for name, data in (("draft", REPORT_DRAFT), ("draft ще раз", REPORT_DRAFT),
                       ("final", REPORT_FINAL), ("memo", MEMO)):
        show(name, encrypt_random_iv(data, KEY)[BLOCK:])
    for title, a, b in pairs:
        ca, cb = encrypt_random_iv(a, KEY), encrypt_random_iv(b, KEY)
        print(f"{title}: спільних перших блоків "
              f"{common_prefix_blocks(ca[BLOCK:], cb[BLOCK:])} із "
              f"{len(blocks(ca[BLOCK:]))}, шифротексти рівні: {ca == cb}")
    sealed = [encrypt_random_iv(m, KEY) for m in SERIES]
    print(f"серія з {len(SERIES)} повідомлень ({len(set(SERIES))} різних): "
          f"різних шифротекстів {len(set(sealed))}")
    restored = all(decrypt_random_iv(c, KEY) == m for c, m in zip(sealed, SERIES))
    print(f"розшифрування відновлює всі повідомлення серії: {restored}")


if __name__ == "__main__":
    main()
