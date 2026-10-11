"""Електронний підпис RSA-PSS (2048) – схема варіанта 12 (крок 6)."""
from __future__ import annotations

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

KEY_BITS = 2048
MESSAGE = b"lab4 demo message"
PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                  salt_length=padding.PSS.MAX_LENGTH)


def generate_keys() -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    # ТЕСТОВИЙ КЛЮЧ — не використовувати поза стендом
    private = rsa.generate_private_key(public_exponent=65537, key_size=KEY_BITS)
    return private, private.public_key()


def sign(private: rsa.RSAPrivateKey, message: bytes) -> bytes:
    return private.sign(message, PSS, hashes.SHA256())


def verify(public: rsa.RSAPublicKey, signature: bytes, message: bytes) -> bool:
    """True, якщо підпис відповідає повідомленню й відкритому ключу."""
    try:
        public.verify(signature, message, PSS, hashes.SHA256())
        return True
    except InvalidSignature:
        return False


def flip_bit(data: bytes, bit: int) -> bytes:
    index, mask = bit // 8, 1 << (bit % 8)
    return data[:index] + bytes([data[index] ^ mask]) + data[index + 1:]


def verdict(valid: bool) -> str:
    return "підпис дійсний" if valid else "InvalidSignature"


def main() -> None:
    private, public = generate_keys()
    numbers = public.public_numbers()
    signature = sign(private, MESSAGE)
    print(f"модуль: {numbers.n.bit_length()} бітів, e = {numbers.e}")
    print(f"повідомлення: {MESSAGE!r}")
    print(f"підпис: {len(signature)} байтів, {signature[:24].hex()}…")
    print(f"коректне повідомлення: {verdict(verify(public, signature, MESSAGE))}")
    print("змінене повідомлення (msg + b'x'): "
          f"{verdict(verify(public, signature, MESSAGE + b'x'))}")
    print("змінено один біт повідомлення: "
          f"{verdict(verify(public, signature, flip_bit(MESSAGE, 0)))}")
    print("змінено один біт підпису: "
          f"{verdict(verify(public, flip_bit(signature, 0), MESSAGE))}")
    bits = len(signature) * 8
    rejected = sum(not verify(public, flip_bit(signature, bit), MESSAGE)
                   for bit in range(bits))
    print(f"однобітових змін підпису відхилено: {rejected} із {bits}")
    bits = len(MESSAGE) * 8
    rejected = sum(not verify(public, signature, flip_bit(MESSAGE, bit))
                   for bit in range(bits))
    print(f"однобітових змін повідомлення відхилено: {rejected} із {bits}")
    _, other_public = generate_keys()
    print(f"перевірка чужим відкритим ключем: "
          f"{verdict(verify(other_public, signature, MESSAGE))}")
    second = sign(private, MESSAGE)
    print(f"повторний підпис того самого повідомлення відрізняється: "
          f"{second != signature}, дійсний: {verify(public, second, MESSAGE)}")


if __name__ == "__main__":
    main()
