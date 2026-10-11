"""Покрокова верифікація навчального RSA та демонстраційні ключі (кроки 2–3)."""
from __future__ import annotations

from crypto_lab.rsa_edu import (decrypt, egcd, encrypt, fast_pow_mod,
                                is_probable_prime, keygen, modinv)

BITS = 32  # rsa_demo_bits варіанта 12
MESSAGE = 42
# Складені числа, що проходять тест за окремими основами (сильні псевдопрості)
PSEUDOPRIMES = (2047, 1373653, 3215031751)  # 23·89, 829·1657, 151·751·28351


def multiplications(steps: list[str]) -> tuple[int, int]:
    """Кількість піднесень до квадрата і множень у протоколі fast_pow_mod."""
    return len(steps), sum("bit=1" in step for step in steps)


def egcd_trace(a: int, b: int) -> list[tuple[int, int, int, int]]:
    """Рядки (q, r, x, y) розширеного алгоритму Евкліда: a·x + b·y = r."""
    rows = [(0, a, 1, 0), (0, b, 0, 1)]
    while rows[-1][1]:
        (_, r0, x0, y0), (_, r1, x1, y1) = rows[-2], rows[-1]
        q = r0 // r1
        rows.append((q, r0 - q * r1, x0 - q * x1, y0 - q * y1))
    return rows[:-1]


def miller_rabin_trace(n: int, a: int) -> tuple[int, int, list[int], bool]:
    """Розклад n − 1 = 2^r · d і послідовність a^d, a^(2d), … за модулем n."""
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    xs = [pow(a, d, n)]
    for _ in range(r - 1):
        xs.append(pow(xs[-1], 2, n))
    passed = xs[0] == 1 or n - 1 in xs
    return r, d, xs, passed


def show_power(base: int, exp: int, mod: int, full: bool = True) -> int:
    value, steps = fast_pow_mod(base, exp, mod)
    assert value == pow(base, exp, mod)
    squares, products = multiplications(steps)
    print(f"{base}^{exp} mod {mod} = {value}")
    if full:
        for step in steps:
            print("  " + step)
    print(f"  бітів показника: {exp.bit_length()}, з них одиничних: {products}; "
          f"множень: {squares + products} ({squares} квадр. + "
          f"{products} добутків)")
    return value


def main() -> None:
    print("== Швидке піднесення до степеня ==")
    show_power(7, 13, 100)

    print("\n== Тест простоти ==")
    for n in (7919, 7917, 104729, *PSEUDOPRIMES):
        print(f"is_probable_prime({n}) = {is_probable_prime(n)}")
    for n, a in ((104729, 2), (2047, 2), (2047, 3), (1373653, 2), (1373653, 5)):
        r, d, xs, passed = miller_rabin_trace(n, a)
        result = "можливо просте" if passed else "складене"
        print(f"n={n}: n-1 = 2^{r}·{d}, a={a}, x = {xs} -> {result}")

    print("\n== Розширений алгоритм Евкліда ==")
    g, x, y = egcd(240, 46)
    print(f"egcd(240, 46) = ({g}, {x}, {y}); 240·({x}) + 46·({y}) = "
          f"{240 * x + 46 * y}")
    print("обчислення d для e = 17, φ = 3120 (3120·x + 17·y = r):")
    print(f"{'q':>5}{'r':>6}{'x':>6}{'y':>7}")
    rows = egcd_trace(3120, 17)
    for q, r, x, y in rows:
        assert 3120 * x + 17 * y == r
        print(f"{q:>5}{r:>6}{x:>6}{y:>7}")
    y = rows[-1][3]
    print(f"y = {y}, d = y mod 3120 = {y % 3120}; modinv(17, 3120) = "
          f"{modinv(17, 3120)}")

    print("\n== Контрольний приклад ==")
    p, q, e = 61, 53, 17
    n, phi = p * q, (p - 1) * (q - 1)
    d = modinv(e, phi)
    print(f"p = {p}, q = {q}, n = {n}, φ(n) = {phi}, e = {e}, d = {d}")
    print(f"e·d mod φ(n) = {e * d % phi}")
    c = show_power(65, e, n)
    m = show_power(c, d, n)
    assert (c, m) == (encrypt(65, e, n), decrypt(c, d, n)) == (2790, 65)

    print(f"\n== Демонстраційні ключі ({BITS} біти) ==")
    k = keygen(bits=BITS)
    for name in ("p", "q", "n", "phi", "e", "d"):
        print(f"{name:<4}= {k[name]}")
    print(f"розрядність у бітах: p – {k['p'].bit_length()}, "
          f"q – {k['q'].bit_length()}, "
          f"n – {k['n'].bit_length()}, d – {k['d'].bit_length()}")
    print(f"is_probable_prime(p) = {is_probable_prime(k['p'])}, "
          f"is_probable_prime(q) = {is_probable_prime(k['q'])}")
    print(f"e·d mod φ(n) = {k['e'] * k['d'] % k['phi']}")
    c = encrypt(MESSAGE, k["e"], k["n"])
    assert decrypt(c, k["d"], k["n"]) == MESSAGE
    print(f"m = {MESSAGE} -> c = {c} -> m = {decrypt(c, k['d'], k['n'])}")
    show_power(MESSAGE, k["e"], k["n"])
    show_power(c, k["d"], k["n"], full=False)


if __name__ == "__main__":
    main()
