"""Демонстрація підсистеми автентифікації варіанта 12 (кроки 2–6)."""
import math
import os
import statistics
import time

# ТЕСТОВИЙ КЛЮЧ — не використовувати поза стендом
os.environ.setdefault("AUTH_PEPPER", "lab3-synthetic-pepper")

from auth import passwords  # noqa: E402
from auth.anderson import entropy_bits, min_length, required_space  # noqa: E402
from auth.lockout import LOCK_SECONDS, MAX_FAILURES, FixedLockout  # noqa: E402
from auth.passwords import (hash_password, hash_password_insecure,  # noqa: E402
                            verify_password)
from auth.recovery import RecoveryCodes, generate_codes  # noqa: E402
from auth.service import MIN_PASSWORD_LENGTH, AuthService  # noqa: E402

RATE, PERIOD_DAYS, PROBABILITY = 20, 30, 1e-6
ALPHABETS = (26, 62, 95)


def clock(seconds: float) -> str:
    return f"{int(seconds) // 60:02d}:{int(seconds) % 60:02d}"


def show_anderson() -> None:
    minutes = PERIOD_DAYS * 24 * 60
    space = required_space(RATE, PERIOD_DAYS, PROBABILITY)
    print(f"T = {PERIOD_DAYS} діб = {minutes} хв; R·T = {RATE * minutes}")
    print(f"G ≥ {space:.3e}")
    print("A    log G / log A    L    H, біт")
    for alphabet in ALPHABETS:
        length = min_length(space, alphabet)
        ratio = math.log(space) / math.log(alphabet)
        print(f"{alphabet:<5}{ratio:<17.3f}{length:<5}"
              f"{entropy_bits(alphabet, length):.1f}")
    effective = MAX_FAILURES / (LOCK_SECONDS / 60)
    limited = required_space(effective, PERIOD_DAYS, PROBABILITY)
    print(f"з блокуванням: R = {effective:.3f}/хв, G ≥ {limited:.3e}, L = "
          + ", ".join(f"{min_length(limited, a)} (A={a})" for a in ALPHABETS))


def show_storage() -> None:
    stored = hash_password("correct horse")
    algorithm, iterations, salt, key = stored.split("$")
    print("збережений рядок:", stored)
    print(f"алгоритм: {algorithm}; ітерацій: {iterations}; "
          f"сіль: {len(passwords._unb64(salt))} байтів; "
          f"ключ: {len(passwords._unb64(key))} байтів")
    print("вірний пароль:", verify_password(stored, "correct horse"))
    print("хибний пароль:", verify_password(stored, "wrong"))
    print("солі різні:", hash_password("same") != hash_password("same"))
    original = passwords.PEPPER
    passwords.PEPPER = b"another-synthetic-pepper"
    print("вірний пароль з іншим перцем:",
          verify_password(stored, "correct horse"))
    passwords.PEPPER = original


def show_comparison() -> None:
    first = hash_password_insecure("password123")
    second = hash_password_insecure("password123")
    print("SHA-256, спроба 1:", first)
    print("SHA-256, спроба 2:", second)
    print("вразливі хеші однакові:", first == second)
    first, second = hash_password("password123"), hash_password("password123")
    print("PBKDF2, спроба 1:", first)
    print("PBKDF2, спроба 2:", second)
    print("захищені рядки різні:", first != second)


def show_timing() -> None:
    samples = []
    for _ in range(7):
        start = time.perf_counter()
        hash_password("password123")
        samples.append(time.perf_counter() - start)
    slow = statistics.median(samples)
    runs = 200_000
    start = time.perf_counter()
    for _ in range(runs):
        hash_password_insecure("password123")
    fast = (time.perf_counter() - start) / runs
    print(f"hash_password (медіана з {len(samples)}): {slow * 1000:.1f} мс")
    print(f"hash_password_insecure (середнє з {runs}): {fast * 1e6:.3f} мкс")
    print(f"відношення: {slow / fast:.0f}")
    print(f"паролів за секунду: PBKDF2 {1 / slow:.1f}, SHA-256 {1 / fast:.0f}")


def show_lockout() -> None:
    lockout = FixedLockout()
    print("час   спроба       невдалих  дозволено далі")
    moments = [0, 10, 20, 30, 40]
    for moment in moments:
        lockout.record_attempt("alice", False, moment)
        print(f"{clock(moment)} невдала      {lockout.failures('alice'):<10}"
              f"{lockout.is_allowed('alice', moment)}")
    until = lockout.locked_until("alice")
    print(f"блокування до {clock(until)}")
    for moment in (until - 1, until, until + 1):
        allowed = lockout.is_allowed("alice", moment)
        print(f"{clock(moment)} is_allowed = {allowed}")
    lockout.record_attempt("alice", False, until)
    print(f"{clock(until)} невдала      {lockout.failures('alice'):<10}"
          f"{lockout.is_allowed('alice', until)}")
    lockout.record_attempt("alice", True, until + 5)
    print(f"{clock(until + 5)} успішна      {lockout.failures('alice'):<10}"
          f"{lockout.is_allowed('alice', until + 5)}")
    for moment in range(4):
        lockout.record_attempt("bob", False, moment)
    print(f"bob: 4 невдалі -> is_allowed = {lockout.is_allowed('bob', 4)}")
    lockout.record_attempt("bob", True, 5)
    print(f"bob: успішна -> невдалих {lockout.failures('bob')}")


def show_recovery() -> None:
    codes = generate_codes()
    for number, code in enumerate(codes, 1):
        print(f"{number:>2}. {code}")
    store = RecoveryCodes(codes)
    print("дійсних кодів:", store.remaining())
    print("перше пред'явлення коду 3:", store.verify(codes[2]))
    print("дійсних кодів:", store.remaining())
    print("повторне пред'явлення коду 3:", store.verify(codes[2]))
    print("код малими літерами без дефісів:",
          store.verify(codes[6].lower().replace("-", "")))
    print("вигаданий код AAAA-AAAA-AAAA:", store.verify("AAAA-AAAA-AAAA"))
    print("дійсних кодів:", store.remaining())


def show_service() -> None:
    service = AuthService()
    print("мінімальна довжина пароля:", MIN_PASSWORD_LENGTH)
    try:
        service.register("carol", "abc123")
    except ValueError as error:
        print("реєстрація з паролем abc123:", error)
    codes = service.register("carol", "Synthetic#Pass1")
    steps = [
        (0, "Synthetic#Pass1", codes[0], "вірний пароль, код 1"),
        (60, "Synthetic#Pass1", codes[0], "вірний пароль, код 1 повторно"),
        (70, "wrong-password", codes[1], "хибний пароль, код 2"),
        (80, "wrong-password", codes[1], "хибний пароль, код 2"),
        (90, "wrong-password", codes[1], "хибний пароль, код 2"),
        (100, "Synthetic#Pass1", "AAAA-AAAA-AAAA", "вірний пароль, хибний код"),
        (110, "Synthetic#Pass1", codes[1], "вірний пароль, код 2"),
        (1000, "Synthetic#Pass1", codes[1], "вірний пароль, код 2"),
        (1001, "Synthetic#Pass1", codes[2], "вірний пароль, код 3"),
    ]
    for moment, password, code, title in steps:
        result = service.login("carol", password, code, moment)
        print(f"{clock(moment)} {title:<32}{result:<16}"
              f"кодів: {service.codes_left('carol')}")
    print("невідомий обліковий запис:",
          service.login("mallory", "Synthetic#Pass1", codes[3], 0))


def main() -> None:
    sections = [
        ("Формула Андерсона", show_anderson),
        ("Зберігання пароля", show_storage),
        ("Порівняння з вразливим зберіганням", show_comparison),
        ("Час обчислення", show_timing),
        ("Блокування", show_lockout),
        ("Коди відновлення", show_recovery),
        ("Вхід у систему", show_service),
    ]
    for index, (title, show) in enumerate(sections):
        print(("\n" if index else "") + f"== {title} ==")
        show()


if __name__ == "__main__":
    main()
