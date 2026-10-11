"""Помилка варіанта: MAC-then-Encrypt замість Encrypt-then-MAC (крок 5)."""
from __future__ import annotations

import hashlib
import hmac
import os
from collections import Counter

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

BLOCK = 16
TAG = 32
ENC_KEY = b"2" * 32  # ТЕСТОВИЙ КЛЮЧ — не використовувати поза стендом
MAC_KEY = b"3" * 32  # ТЕСТОВИЙ КЛЮЧ — не використовувати поза стендом
MESSAGE = b"order=0042;item=notebook;qty=3;note=demo"

DECRYPT, UNPAD, CHECK = "розшифрування", "зняття доповнення", "перевірка MAC"


class PaddingError(Exception):
    """Розшифровані дані мають некоректне доповнення."""


class MacError(Exception):
    """Код автентифікації не збігається."""


def _mac(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


def _cbc_encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    padder = padding.PKCS7(BLOCK * 8).padder()
    data = padder.update(plaintext) + padder.finalize()
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return encryptor.update(data) + encryptor.finalize()


def _cbc_decrypt(body: bytes, key: bytes, iv: bytes, trace: list[str]) -> bytes:
    trace.append(DECRYPT)
    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    data = decryptor.update(body) + decryptor.finalize()
    trace.append(UNPAD)
    unpadder = padding.PKCS7(BLOCK * 8).unpadder()
    try:
        return unpadder.update(data) + unpadder.finalize()
    except ValueError:
        raise PaddingError("некоректне доповнення") from None


def mte_seal(plaintext: bytes, enc_key: bytes, mac_key: bytes) -> bytes:
    """MAC-then-Encrypt: IV ‖ CBC(відкритий текст ‖ MAC)."""
    # ВРАЗЛИВО: MAC обчислено над відкритим текстом і сховано під шифруванням
    iv = os.urandom(BLOCK)
    return iv + _cbc_encrypt(plaintext + _mac(mac_key, plaintext), enc_key, iv)


def mte_open(blob: bytes, enc_key: bytes, mac_key: bytes,
             trace: list[str]) -> bytes:
    # ВРАЗЛИВО: приймач розшифровує неперевірені дані, MAC перевіряється останнім
    iv, body = blob[:BLOCK], blob[BLOCK:]
    data = _cbc_decrypt(body, enc_key, iv, trace)
    trace.append(CHECK)
    if len(data) < TAG:
        raise MacError("код автентифікації не збігається")
    plaintext, tag = data[:-TAG], data[-TAG:]
    if not hmac.compare_digest(tag, _mac(mac_key, plaintext)):
        raise MacError("код автентифікації не збігається")
    return plaintext


def etm_seal(plaintext: bytes, enc_key: bytes, mac_key: bytes) -> bytes:
    """Encrypt-then-MAC: IV ‖ CBC(відкритий текст) ‖ MAC(IV ‖ шифротекст)."""
    # БЕЗПЕЧНО: MAC покриває IV і шифротекст, ключ MAC відмінний від ключа шифру
    iv = os.urandom(BLOCK)
    body = iv + _cbc_encrypt(plaintext, enc_key, iv)
    return body + _mac(mac_key, body)


def etm_open(blob: bytes, enc_key: bytes, mac_key: bytes,
             trace: list[str]) -> bytes:
    # БЕЗПЕЧНО: MAC перевіряється першим і за сталий час; змінені дані
    # відхиляються до розшифрування
    trace.append(CHECK)
    if len(blob) < 2 * BLOCK + TAG:
        raise MacError("код автентифікації не збігається")
    body, tag = blob[:-TAG], blob[-TAG:]
    if not hmac.compare_digest(tag, _mac(mac_key, body)):
        raise MacError("код автентифікації не збігається")
    return _cbc_decrypt(body[BLOCK:], enc_key, body[:BLOCK], trace)


def flip(blob: bytes, index: int) -> bytes:
    """Змінює молодший біт байта з номером index."""
    return blob[:index] + bytes([blob[index] ^ 1]) + blob[index + 1:]


def receive(opener, blob: bytes) -> tuple[str, list[str]]:
    """Повертає результат приймача та перелік виконаних ним етапів."""
    trace: list[str] = []
    try:
        opener(blob, ENC_KEY, MAC_KEY, trace)
        return "прийнято", trace
    except PaddingError:
        return "відмова: доповнення", trace
    except MacError:
        return "відмова: MAC", trace


def survey(opener, blob: bytes) -> tuple[Counter, int]:
    """Змінює по одному біту в кожному байті; рахує відповіді й розшифрування."""
    outcomes, decryptions = Counter(), 0
    for index in range(len(blob)):
        outcome, trace = receive(opener, flip(blob, index))
        outcomes[outcome] += 1
        decryptions += DECRYPT in trace
    return outcomes, decryptions


def main() -> None:
    schemes = [("MAC-then-Encrypt", mte_seal, mte_open, BLOCK, -BLOCK - 1),
               ("Encrypt-then-MAC", etm_seal, etm_open, BLOCK, -TAG - BLOCK - 1)]
    for name, seal, opener, first, last in schemes:
        blob = seal(MESSAGE, ENC_KEY, MAC_KEY)
        print(f"== {name} ==")
        print(f"повідомлення {len(MESSAGE)} байтів, пакет {len(blob)} байтів")
        cases = [("без змін", blob),
                 ("змінено біт у першому блоці шифротексту", flip(blob, first)),
                 ("змінено біт у передостанньому блоці", flip(blob, last))]
        for title, data in cases:
            outcome, trace = receive(opener, data)
            print(f"{title}: {outcome}")
            print(f"  етапи приймача: {' -> '.join(trace)}")
        outcomes, decryptions = survey(opener, blob)
        summary = ", ".join(f"{k} – {v}" for k, v in sorted(outcomes.items()))
        print(f"зміна біта в кожному з {len(blob)} байтів: {summary}")
        print(f"розшифрувань неавтентичних даних: {decryptions} із {len(blob)}")
        print()


if __name__ == "__main__":
    main()
