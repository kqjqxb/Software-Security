"""Тести варіанта 12: PBKDF2, фіксоване блокування, коди відновлення."""
import base64
import inspect

import pytest

from auth import lockout as lockout_module
from auth import passwords, recovery
from auth.anderson import entropy_bits, min_length, required_space
from auth.lockout import LOCK_SECONDS, MAX_FAILURES, FixedLockout
from auth.passwords import (hash_password, hash_password_insecure,
                            verify_password)
from auth.recovery import ALPHABET, RecoveryCodes, generate_codes
from auth.service import DENIED, LOCKED, OK, AuthService

PASSWORD = "Synthetic#Pass1"  # синтетичний пароль


@pytest.fixture(scope="module")
def stored():
    return hash_password("correct horse")


@pytest.fixture
def policy():
    return FixedLockout()


def fail(policy, account, count, start=0.0):
    for index in range(count):
        policy.record_attempt(account, False, start + index)


# ---------------------------------------------------------------- Андерсон

def test_anderson_lecture_example():
    space = required_space(10, 90, 1e-6)
    assert space == pytest.approx(1.296e12)
    assert min_length(space, 95) == 7
    assert entropy_bits(95, 7) == pytest.approx(46.0, abs=0.05)


def test_anderson_variant_values():
    space = required_space(20, 30, 1e-6)
    assert space == pytest.approx(8.64e11)
    assert [min_length(space, a) for a in (26, 62, 95)] == [9, 7, 7]


def test_anderson_length_is_sufficient_and_minimal():
    space = required_space(20, 30, 1e-6)
    for alphabet in (26, 62, 95):
        length = min_length(space, alphabet)
        assert alphabet ** length >= space > alphabet ** (length - 1)


# ---------------------------------------------------------------- паролі

def test_hash_and_verify_roundtrip(stored):
    assert verify_password(stored, "correct horse")


def test_wrong_password_rejected(stored):
    assert not verify_password(stored, "wrong")
    assert not verify_password(stored, "correct horse ")
    assert not verify_password(stored, "")


def test_salt_is_unique():
    first, second = hash_password("same"), hash_password("same")
    assert first != second
    assert first.split("$")[2] != second.split("$")[2]
    assert verify_password(first, "same") and verify_password(second, "same")


def test_stored_format_and_parameters(stored):
    algorithm, iterations, salt, key = stored.split("$")
    assert algorithm == "pbkdf2_sha256"
    assert int(iterations) >= 600_000
    assert len(base64.b64decode(salt)) >= 16
    assert len(base64.b64decode(key)) == 32
    assert "correct horse" not in stored


def test_pbkdf2_matches_rfc7914_vector(monkeypatch):
    monkeypatch.setattr(passwords, "PEPPER", b"")
    key = passwords._derive("passwd", b"salt", 1)
    assert key.hex() == ("55ac046e56e3089fec1691c22544b605"
                         "f94185216dde0465e68b9d57c20dacbc")


def test_pepper_is_required_for_verification(stored, monkeypatch):
    monkeypatch.setattr(passwords, "PEPPER", b"another-synthetic-pepper")
    assert not verify_password(stored, "correct horse")
    monkeypatch.setattr(passwords, "PEPPER", b"")
    assert not verify_password(stored, "correct horse")


def test_malformed_stored_value_rejected(stored):
    algorithm, iterations, salt, key = stored.split("$")
    assert not verify_password("", "correct horse")
    assert not verify_password("pbkdf2_sha256$600000$only-three", "x")
    for broken in (f"sha256${iterations}${salt}${key}",
                   f"{algorithm}$abc${salt}${key}",
                   f"{algorithm}${iterations}$???${key}"):
        assert not verify_password(broken, "correct horse")
    assert not verify_password(hash_password_insecure("correct horse"),
                               "correct horse")


def test_verification_uses_constant_time_comparison():
    assert "hmac.compare_digest" in inspect.getsource(verify_password)
    assert "hmac.compare_digest" in inspect.getsource(RecoveryCodes.verify)


def test_insecure_hash_reveals_equal_passwords():
    assert (hash_password_insecure("password123")
            == hash_password_insecure("password123"))
    assert hash_password("password123") != hash_password("password123")


# ---------------------------------------------------------------- блокування

def test_variant_lockout_parameters():
    assert MAX_FAILURES == 5
    assert LOCK_SECONDS == 15 * 60


def test_four_failures_do_not_lock(policy):
    fail(policy, "alice", MAX_FAILURES - 1)
    assert policy.is_allowed("alice", 4)


def test_fifth_failure_locks(policy):
    fail(policy, "alice", MAX_FAILURES)
    assert not policy.is_allowed("alice", 4)
    assert policy.locked_until("alice") == 4 + LOCK_SECONDS


def test_lock_expires_exactly_after_interval(policy):
    fail(policy, "alice", MAX_FAILURES)
    until = 4 + LOCK_SECONDS
    assert not policy.is_allowed("alice", until - 0.001)
    assert policy.is_allowed("alice", until)
    assert policy.is_allowed("alice", until + 1)


def test_success_resets_failure_counter(policy):
    fail(policy, "alice", MAX_FAILURES - 1)
    policy.record_attempt("alice", True, 10)
    fail(policy, "alice", MAX_FAILURES - 1, start=20)
    assert policy.is_allowed("alice", 30)


def test_attempts_during_lock_do_not_extend_it(policy):
    fail(policy, "alice", MAX_FAILURES)
    for moment in (100, 500, 900):
        policy.record_attempt("alice", False, moment)
        policy.record_attempt("alice", True, moment)
    assert policy.locked_until("alice") == 4 + LOCK_SECONDS
    assert policy.is_allowed("alice", 4 + LOCK_SECONDS)


def test_counter_restarts_after_lock(policy):
    fail(policy, "alice", MAX_FAILURES)
    restart = 4 + LOCK_SECONDS
    fail(policy, "alice", MAX_FAILURES - 1, start=restart)
    assert policy.is_allowed("alice", restart + 10)
    policy.record_attempt("alice", False, restart + 10)
    assert not policy.is_allowed("alice", restart + 11)


def test_accounts_are_locked_independently(policy):
    fail(policy, "alice", MAX_FAILURES)
    assert policy.is_allowed("bob", 4)


def test_module_level_functions():
    for moment in range(MAX_FAILURES):
        assert lockout_module.is_allowed("module-user", moment)
        lockout_module.record_attempt("module-user", False, moment)
    assert not lockout_module.is_allowed("module-user", 5)
    assert lockout_module.is_allowed("module-user", 4 + LOCK_SECONDS)


# ---------------------------------------------------------------- коди

def test_ten_unique_codes_of_expected_form():
    codes = generate_codes()
    assert len(codes) == 10 == len(set(codes))
    for code in codes:
        groups = code.split("-")
        assert [len(group) for group in groups] == [4, 4, 4]
        assert set("".join(groups)) <= set(ALPHABET)


def test_code_sets_differ_between_calls():
    assert not set(generate_codes()) & set(generate_codes())


def test_code_accepted_only_once():
    codes = generate_codes()
    store = RecoveryCodes(codes)
    assert store.verify(codes[0])
    assert store.remaining() == 9
    assert not store.verify(codes[0])
    assert store.remaining() == 9


def test_every_code_is_valid_exactly_once():
    codes = generate_codes()
    store = RecoveryCodes(codes)
    assert all(store.verify(code) for code in codes)
    assert store.remaining() == 0
    assert not any(store.verify(code) for code in codes)


def test_unknown_code_rejected_and_nothing_spent():
    store = RecoveryCodes(generate_codes())
    assert not store.verify("AAAA-AAAA-AAAA")
    assert not store.verify("")
    assert store.remaining() == 10


def test_code_input_is_normalized():
    codes = generate_codes()
    store = RecoveryCodes(codes)
    assert store.verify(codes[0].lower().replace("-", " "))
    assert not store.verify(codes[0])


def test_codes_are_not_stored_in_plaintext():
    codes = ["ABCD-EFGH-JKLM"]  # синтетичний код
    store = RecoveryCodes(codes)
    assert store._digests == [recovery._digest("abcdefghjklm")]
    assert all(isinstance(digest, bytes) and len(digest) == 32
               for digest in store._digests)


# ---------------------------------------------------------------- вхід

@pytest.fixture
def service():
    service = AuthService()
    service.codes = service.register("carol", PASSWORD)
    return service


def test_login_requires_password_and_code(service):
    assert service.login("carol", PASSWORD, service.codes[0], 0) == OK
    assert service.login("carol", PASSWORD, service.codes[0], 1) == DENIED
    assert service.login("carol", "wrong-password", service.codes[1], 2) == DENIED
    assert service.codes_left("carol") == 9


def test_wrong_password_does_not_spend_code(service):
    assert service.login("carol", "wrong-password", service.codes[0], 0) == DENIED
    assert service.codes_left("carol") == 10
    assert service.login("carol", PASSWORD, service.codes[0], 1) == OK


def test_login_locked_after_five_failures(service):
    for moment in range(MAX_FAILURES):
        assert service.login("carol", "wrong-password", "", moment) == DENIED
    assert service.login("carol", PASSWORD, service.codes[0], 5) == LOCKED
    assert service.codes_left("carol") == 10
    after = 4 + LOCK_SECONDS
    assert service.login("carol", PASSWORD, service.codes[0], after) == OK


def test_wrong_codes_also_lock_account(service):
    for moment in range(MAX_FAILURES):
        result = service.login("carol", PASSWORD, "AAAA-AAAA-AAAA", moment)
        assert result == DENIED
    assert service.login("carol", PASSWORD, service.codes[0], 5) == LOCKED


def test_unknown_account_denied(service):
    assert service.login("mallory", PASSWORD, service.codes[0], 0) == DENIED


def test_short_password_rejected_at_registration(service):
    with pytest.raises(ValueError):
        service.register("dave", "abc123")
    with pytest.raises(ValueError):
        service.register("carol", PASSWORD)
