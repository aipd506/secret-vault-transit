"""Tests for secret-vault-transit Shamir (k, n) secret sharing module."""

import pytest

from vaulttransit.shamir import (
    PRIME_P,
    ShamirError,
    combine_shares,
    split_secret,
)


def test_shamir_split_and_combine_basic():
    secret = "root-master-recovery-key-9988"
    shares = split_secret(secret, k=3, n=5)
    assert len(shares) == 5

    # Any 3 of 5 shares reconstruct the secret
    assert combine_shares(shares[:3]) == secret
    assert combine_shares([shares[0], shares[2], shares[4]]) == secret
    assert combine_shares(shares[2:]) == secret
    # All 5 shares reconstruct
    assert combine_shares(shares) == secret


def test_shamir_threshold_enforcement():
    secret = "high-security-vault-seal"
    shares = split_secret(secret, k=4, n=6)

    # 3 shares (less than threshold 4) when threshold specified raises ShamirError
    with pytest.raises(ShamirError):
        combine_shares(shares[:3], threshold=4)

    # Exactly 4 shares works
    assert combine_shares(shares[:4], threshold=4) == secret


def test_shamir_duplicate_shares_rejected():
    secret = "duplicate-check-token"
    shares = split_secret(secret, k=3, n=5)

    # Pass duplicate of shares[0]
    with pytest.raises(ShamirError, match="Duplicate share index"):
        combine_shares([shares[0], shares[0], shares[1]])


def test_shamir_long_secret_multi_chunk():
    # Long secret that spans multiple 31-byte chunks (> 100 bytes)
    long_secret = "The quick brown fox jumps over the lazy dog. 1234567890! Special characters: @#$%^&*(). Extended security payload." * 2
    shares = split_secret(long_secret, k=3, n=5)
    assert len(shares) == 5

    reconstructed = combine_shares(shares[:3])
    assert reconstructed == long_secret


def test_shamir_binary_bytes():
    raw_key = b"\x00\x01\x02\x03\xff\xfe\xfd\xfc" * 8
    shares = split_secret(raw_key, k=2, n=3)
    reconstructed = combine_shares(shares[:2], return_bytes=True)
    assert reconstructed == raw_key


def test_shamir_invalid_args():
    with pytest.raises(ShamirError):
        split_secret("secret", k=1, n=3)  # k < 2

    with pytest.raises(ShamirError):
        split_secret("secret", k=5, n=3)  # k > n

    with pytest.raises(ShamirError):
        split_secret("", k=2, n=3)  # empty secret

    with pytest.raises(ShamirError):
        combine_shares([])  # empty shares
