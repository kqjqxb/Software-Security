"""Час генерації простих чисел і факторизації навчального модуля (крок 7)."""
from __future__ import annotations

import math
import sys
import time

from crypto_lab.rsa_edu import gen_prime, keygen

DEMO_BITS = (16, 20, 24, 28, 32, 36, 40)
TRIAL_LIMIT = 32  # перебір дільників для більших множників триває години
PRIME_BITS = (16, 32, 64, 128, 256, 512, 1024)


def trial_division(n: int) -> tuple[int, int]:
    """Перебір непарних дільників; повертає множник і кількість ділень."""
    divisor, count = 3, 0
    while n % divisor:
        divisor += 2
        count += 1
    return divisor, count + 1


def pollard_rho(n: int) -> tuple[int, int]:
    """ρ-метод Полларда; повертає множник і кількість ітерацій."""
    for c in range(1, 20):
        x = y = 2
        steps = 0
        while True:
            x = (x * x + c) % n
            y = (y * y + c) % n
            y = (y * y + c) % n
            steps += 1
            g = math.gcd(abs(x - y), n)
            if g != 1:
                break
        if g != n:
            return g, steps
    raise ValueError("множник не знайдено")


def timed(function, *args):
    start = time.perf_counter()
    result = function(*args)
    return result, time.perf_counter() - start


def mean_time(function, argument, repeats: int) -> float:
    return sum(timed(function, argument)[1] for _ in range(repeats)) / repeats


def main(trial_limit: int = TRIAL_LIMIT) -> None:
    print("== Генерація простого числа ==")
    print(f"{'біт':>5}{'спроб':>7}{'середній час, мс':>18}")
    for bits in PRIME_BITS:
        repeats = 200 if bits <= 64 else 20 if bits <= 256 else 5
        seconds = mean_time(gen_prime, bits, repeats)
        print(f"{bits:>5}{repeats:>7}{seconds * 1000:>18.3f}")

    print("\n== Факторизація модуля n = p·q ==")
    print(f"{'біт p':>6}{'біт n':>6}{'ділень':>11}{'перебір, с':>12}"
          f"{'ітерацій ρ':>12}{'ρ-метод, с':>12}")
    for bits in DEMO_BITS:
        k = keygen(bits=bits)
        n, factors = k["n"], {k["p"], k["q"]}
        (factor, steps), rho_time = timed(pollard_rho, n)
        assert factor in factors
        if bits <= trial_limit:
            (factor, divisions), trial_time = timed(trial_division, n)
            assert factor in factors
            trial = f"{divisions:>11}{trial_time:>12.4f}"
        else:
            trial = f"{'–':>11}{'–':>12}"
        print(f"{bits:>6}{n.bit_length():>6}{trial}{steps:>12}{rho_time:>12.4f}")


if __name__ == "__main__":
    main(*map(int, sys.argv[1:2]))
