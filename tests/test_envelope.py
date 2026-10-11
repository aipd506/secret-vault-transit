"""Tests for secret-vault-transit envelope encryption module."""

import base64
import json
import pytest

from vaulttransit.envelope import (
    MACVerificationError,
    decrypt_envelope,
    derive_kek,
    encrypt_envelope,
    generate_ctr_keystream,
    generate_datakey,
    xor_bytes,
)


def test_derive_kek():
    # 32 raw bytes returned verbatim
    raw32 = b"\x01" * 32
    assert derive_kek(raw32) == raw32

    # 64 hex characters decoded
    hex64 = "01" * 32
    assert derive_kek(hex64) == raw32

    # Passphrase string derived via PBKDF2
    k1 = derive_kek("my-super-secret-passphrase")
    k2 = derive_kek("my-super-secret-passphrase")
    assert k1 == k2
    assert len(k1) == 32


def test_ctr_keystream_and_xor():
    key = b"A" * 32
    iv = b"B" * 16
    ks1 = generate_ctr_keystream(key, iv, 100)
    ks2 = generate_ctr_keystream(key, iv, 100)
    assert len(ks1) == 100
    assert ks1 == ks2

    msg = b"Hello, World! Security transit vault."
    enc = xor_bytes(msg, ks1[: len(msg)])
    dec = xor_bytes(enc, ks1[: len(msg)])
    assert dec == msg


def test_envelope_encryption_roundtrip():
    kek = "enterprise-master-key-2026"
    plaintext = "Confidential customer database credentials"

    envelope = encrypt_envelope(plaintext, kek, key_id="key-001")
    assert envelope["vault_version"] == 1
    assert envelope["key_id"] == "key-001"
    assert "iv" in envelope
    assert "wrapped_dek" in envelope
    assert "ciphertext" in envelope
    assert "mac" in envelope

    decrypted = decrypt_envelope(envelope, kek)
    assert decrypted == plaintext


def test_envelope_with_aad_context():
    kek = "enterprise-master-key-2026"
    plaintext = "Payload protected with AAD context"
    context = {"tenant_id": "cust-42", "env": "prod"}

    envelope = encrypt_envelope(plaintext, kek, context=context)
    # Decrypt with matching context succeeds
    decrypted = decrypt_envelope(envelope, kek, context=context)
    assert decrypted == plaintext

    # Decrypt with missing or wrong context fails
    with pytest.raises(MACVerificationError):
        decrypt_envelope(envelope, kek, context={"tenant_id": "cust-43", "env": "prod"})

    with pytest.raises(MACVerificationError):
        decrypt_envelope(envelope, kek, context=None)


def test_envelope_tamper_detection():
    kek = "tamper-test-key"
    plaintext = "Tamper evident envelope data"
    envelope = encrypt_envelope(plaintext, kek)

    # 1. Tamper ciphertext
    raw_ct = bytearray(base64.b64decode(envelope["ciphertext"]))
    raw_ct[0] ^= 0x01
    bad_envelope = dict(envelope)
    bad_envelope["ciphertext"] = base64.b64encode(raw_ct).decode("ascii")

    with pytest.raises(MACVerificationError):
        decrypt_envelope(bad_envelope, kek)

    # 2. Tamper IV
    raw_iv = bytearray(base64.b64decode(envelope["iv"]))
    raw_iv[0] ^= 0x01
    bad_envelope2 = dict(envelope)
    bad_envelope2["iv"] = base64.b64encode(raw_iv).decode("ascii")

    with pytest.raises(MACVerificationError):
        decrypt_envelope(bad_envelope2, kek)

    # 3. Wrong KEK
    with pytest.raises(MACVerificationError):
        decrypt_envelope(envelope, "wrong-kek")


def test_datakey_generation():
    kek = "kek-datakey-test"
    dk256 = generate_datakey(kek, bits=256)
    assert dk256["bits"] == 256
    raw_dek = base64.b64decode(dk256["plaintext"])
    assert len(raw_dek) == 32
    assert dk256["plaintext_hex"] == raw_dek.hex()

    # The returned envelope can be decrypted to reveal the raw DEK
    unwrapped = decrypt_envelope(dk256["envelope"], kek, return_bytes=True)
    assert unwrapped == raw_dek

    # 128-bit key
    dk128 = generate_datakey(kek, bits=128)
    assert dk128["bits"] == 128
    assert len(base64.b64decode(dk128["plaintext"])) == 16
