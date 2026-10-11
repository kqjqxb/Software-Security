"""Тести варіанта 12: ChaCha20-Poly1305, RSA-PSS, статичний IV, порядок MAC."""
import os
import sys

import pytest
from cryptography.exceptions import InvalidTag

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from crypto_lab import aead, sign_demo
from crypto_lab import misuse_mac_order as mac
from crypto_lab import misuse_static_iv as cbc
from crypto_lab.rsa_bench import pollard_rho, trial_division
from crypto_lab.rsa_demo import (BITS, egcd_trace, miller_rabin_trace,
                                 multiplications)
from crypto_lab.rsa_edu import (decrypt, encrypt, fast_pow_mod,
                                is_probable_prime, keygen, modinv)

KEY = b"0" * 32  # ТЕСТОВИЙ КЛЮЧ — не використовувати поза стендом
MESSAGE = b"secret payload"


@pytest.fixture(scope="module")
def keys():
    return sign_demo.generate_keys()


# ------------------------------------------------------------------ AEAD

def test_aead_roundtrip_with_associated_data():
    blob = aead.encrypt(MESSAGE, KEY, associated=b"hdr")
    assert aead.decrypt(blob, KEY, associated=b"hdr") == MESSAGE


def test_aead_blob_layout():
    blob = aead.encrypt(MESSAGE, KEY)
    assert len(blob) == aead.NONCE_SIZE + len(MESSAGE) + aead.TAG_SIZE
    assert MESSAGE not in blob


def test_aead_empty_message():
    blob = aead.encrypt(b"", KEY, associated=b"hdr")
    assert len(blob) == aead.NONCE_SIZE + aead.TAG_SIZE
    assert aead.decrypt(blob, KEY, associated=b"hdr") == b""


def test_aead_nonce_is_unique_per_message():
    blobs = [aead.encrypt(MESSAGE, KEY) for _ in range(1000)]
    assert len({b[:aead.NONCE_SIZE] for b in blobs}) == 1000
    assert len({b[aead.NONCE_SIZE:] for b in blobs}) == 1000


def test_aead_rejects_any_single_bit_change():
    blob = aead.encrypt(MESSAGE, KEY, associated=b"hdr")
    for bit in range(len(blob) * 8):
        tampered = sign_demo.flip_bit(blob, bit)
        with pytest.raises(InvalidTag):
            aead.decrypt(tampered, KEY, associated=b"hdr")


def test_aead_binds_associated_data():
    blob = aead.encrypt(MESSAGE, KEY, associated=b"hdr")
    for associated in (b"hds", b"", b"hdr "):
        with pytest.raises(InvalidTag):
            aead.decrypt(blob, KEY, associated=associated)


def test_aead_rejects_wrong_key():
    blob = aead.encrypt(MESSAGE, KEY)
    with pytest.raises(InvalidTag):
        aead.decrypt(blob, b"9" * 32)


def test_aead_rejects_truncated_blob():
    with pytest.raises(ValueError):
        aead.decrypt(b"\x00" * (aead.NONCE_SIZE + aead.TAG_SIZE - 1), KEY)
    blob = aead.encrypt(MESSAGE, KEY)
    with pytest.raises(InvalidTag):
        aead.decrypt(blob[:-1], KEY)


def test_aead_rejects_wrong_key_length():
    with pytest.raises(ValueError):
        aead.encrypt(MESSAGE, b"0" * 16)


# ------------------------------------------------------------ статичний IV

def test_static_iv_is_deterministic():
    first = cbc.encrypt_static_iv(cbc.REPORT_DRAFT, cbc.KEY)
    assert first == cbc.encrypt_static_iv(cbc.REPORT_DRAFT, cbc.KEY)


def test_static_iv_reveals_common_prefix():
    draft = cbc.encrypt_static_iv(cbc.REPORT_DRAFT, cbc.KEY)
    final = cbc.encrypt_static_iv(cbc.REPORT_FINAL, cbc.KEY)
    memo = cbc.encrypt_static_iv(cbc.MEMO, cbc.KEY)
    assert cbc.common_prefix_blocks(draft, final) == 2
    assert cbc.common_prefix_blocks(draft, memo) == 0


def test_static_iv_reveals_repeats_in_series():
    sealed = {cbc.encrypt_static_iv(m, cbc.KEY) for m in cbc.SERIES}
    assert len(sealed) == len(set(cbc.SERIES)) < len(cbc.SERIES)


def test_random_iv_hides_repeats_and_prefixes():
    first = cbc.encrypt_random_iv(cbc.REPORT_DRAFT, cbc.KEY)
    second = cbc.encrypt_random_iv(cbc.REPORT_DRAFT, cbc.KEY)
    final = cbc.encrypt_random_iv(cbc.REPORT_FINAL, cbc.KEY)
    assert first[:cbc.BLOCK] != second[:cbc.BLOCK]
    assert cbc.common_prefix_blocks(first[cbc.BLOCK:], second[cbc.BLOCK:]) == 0
    assert cbc.common_prefix_blocks(first[cbc.BLOCK:], final[cbc.BLOCK:]) == 0
    assert len({cbc.encrypt_random_iv(m, cbc.KEY) for m in cbc.SERIES}) == 5


def test_random_iv_roundtrip():
    for message in cbc.SERIES:
        blob = cbc.encrypt_random_iv(message, cbc.KEY)
        assert cbc.decrypt_random_iv(blob, cbc.KEY) == message


# ------------------------------------------------------------ порядок MAC

@pytest.mark.parametrize("seal, opener", [(mac.mte_seal, mac.mte_open),
                                          (mac.etm_seal, mac.etm_open)])
def test_mac_schemes_roundtrip(seal, opener):
    blob = seal(mac.MESSAGE, mac.ENC_KEY, mac.MAC_KEY)
    assert opener(blob, mac.ENC_KEY, mac.MAC_KEY, []) == mac.MESSAGE


def test_mte_decrypts_before_authentication():
    blob = mac.mte_seal(mac.MESSAGE, mac.ENC_KEY, mac.MAC_KEY)
    outcome, trace = mac.receive(mac.mte_open, mac.flip(blob, mac.BLOCK))
    assert outcome == "відмова: MAC"
    assert trace == [mac.DECRYPT, mac.UNPAD, mac.CHECK]


def test_mte_has_two_distinguishable_failures():
    blob = mac.mte_seal(mac.MESSAGE, mac.ENC_KEY, mac.MAC_KEY)
    outcomes, decryptions = mac.survey(mac.mte_open, blob)
    assert set(outcomes) == {"відмова: MAC", "відмова: доповнення"}
    assert decryptions == len(blob)


def test_etm_rejects_before_decryption():
    blob = mac.etm_seal(mac.MESSAGE, mac.ENC_KEY, mac.MAC_KEY)
    outcomes, decryptions = mac.survey(mac.etm_open, blob)
    assert outcomes == {"відмова: MAC": len(blob)}
    assert decryptions == 0


def test_etm_mac_covers_iv():
    blob = mac.etm_seal(mac.MESSAGE, mac.ENC_KEY, mac.MAC_KEY)
    outcome, trace = mac.receive(mac.etm_open, mac.flip(blob, 0))
    assert outcome == "відмова: MAC" and trace == [mac.CHECK]


def test_etm_rejects_truncated_blob():
    blob = mac.etm_seal(mac.MESSAGE, mac.ENC_KEY, mac.MAC_KEY)
    for size in (0, mac.TAG, len(blob) - 1):
        with pytest.raises(mac.MacError):
            mac.etm_open(blob[:size], mac.ENC_KEY, mac.MAC_KEY, [])


def test_etm_requires_matching_mac_key():
    blob = mac.etm_seal(mac.MESSAGE, mac.ENC_KEY, mac.MAC_KEY)
    with pytest.raises(mac.MacError):
        mac.etm_open(blob, mac.ENC_KEY, mac.ENC_KEY, [])


# ---------------------------------------------------------------- підпис

def test_signature_valid(keys):
    private, public = keys
    signature = sign_demo.sign(private, sign_demo.MESSAGE)
    assert len(signature) == sign_demo.KEY_BITS // 8
    assert sign_demo.verify(public, signature, sign_demo.MESSAGE)


def test_signature_rejects_changed_message(keys):
    private, public = keys
    signature = sign_demo.sign(private, sign_demo.MESSAGE)
    assert not sign_demo.verify(public, signature, sign_demo.MESSAGE + b"x")
    for bit in range(len(sign_demo.MESSAGE) * 8):
        changed = sign_demo.flip_bit(sign_demo.MESSAGE, bit)
        assert not sign_demo.verify(public, signature, changed)


def test_signature_rejects_changed_signature(keys):
    private, public = keys
    signature = sign_demo.sign(private, sign_demo.MESSAGE)
    for bit in range(0, len(signature) * 8, 37):
        changed = sign_demo.flip_bit(signature, bit)
        assert not sign_demo.verify(public, changed, sign_demo.MESSAGE)


def test_signature_rejects_other_key(keys):
    private, _ = keys
    _, other_public = sign_demo.generate_keys()
    signature = sign_demo.sign(private, sign_demo.MESSAGE)
    assert not sign_demo.verify(other_public, signature, sign_demo.MESSAGE)


def test_pss_signature_is_randomized(keys):
    private, public = keys
    first = sign_demo.sign(private, sign_demo.MESSAGE)
    second = sign_demo.sign(private, sign_demo.MESSAGE)
    assert first != second
    assert sign_demo.verify(public, second, sign_demo.MESSAGE)


# ------------------------------------------------------- навчальний RSA

def test_demo_keys_match_variant_bits():
    k = keygen(bits=BITS)
    assert k["p"].bit_length() == k["q"].bit_length() == BITS == 32
    assert is_probable_prime(k["p"]) and is_probable_prime(k["q"])
    assert k["e"] * k["d"] % k["phi"] == 1
    assert decrypt(encrypt(42, k["e"], k["n"]), k["d"], k["n"]) == 42


def test_multiplication_count():
    _, steps = fast_pow_mod(42, 65537, 3233)
    assert multiplications(steps) == (17, 2)
    _, steps = fast_pow_mod(7, 13, 100)
    assert multiplications(steps) == (4, 3)


def test_egcd_trace_gives_private_exponent():
    rows = egcd_trace(3120, 17)
    assert all(3120 * x + 17 * y == r for _, r, x, y in rows)
    assert rows[-1][1] == 1 and rows[-1][3] % 3120 == modinv(17, 3120) == 2753


def test_miller_rabin_trace():
    assert miller_rabin_trace(104729, 2)[3]
    assert miller_rabin_trace(2047, 2)[3]
    assert not miller_rabin_trace(2047, 3)[3]
    assert not is_probable_prime(2047)


def test_factorization_of_small_modulus():
    k = keygen(bits=16)
    assert trial_division(k["n"])[0] == min(k["p"], k["q"])
    assert pollard_rho(k["n"])[0] in (k["p"], k["q"])
