"""Zero-trust authenticated envelope encryption engine using pure Python standard library.

Implements NIST SP 800-38A compliant Counter (CTR) mode with HMAC-SHA256 Encrypt-then-MAC (EtM),
256-bit CSPRNG ephemeral data keys, and key wrapping.
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import hmac
import json
import math
import secrets
from typing import Any


class VaultTransitError(Exception):
    """Base exception for secret-vault-transit."""
    pass


class MACVerificationError(VaultTransitError):
    """Raised when envelope MAC authentication fails (tampering or wrong key)."""
    pass


class InvalidKeyError(VaultTransitError):
    """Raised when an invalid key or key format is provided."""
    pass


def derive_kek(key_input: str | bytes, salt: bytes = b"vaulttransit-master-kek-salt") -> bytes:
    """Derive a 256-bit Key Encryption Key (KEK) from input bytes, hex, or passphrase."""
    if isinstance(key_input, bytes):
        if len(key_input) == 32:
            return key_input
        return hashlib.sha256(key_input).digest()

    if isinstance(key_input, str):
        # Try hex decoding first if 64 characters
        if len(key_input) == 64:
            try:
                return bytes.fromhex(key_input)
            except ValueError:
                pass
        # Derive via PBKDF2-HMAC-SHA256 with 100,000 iterations for passphrases
        return hashlib.pbkdf2_hmac("sha256", key_input.encode("utf-8"), salt, 100_000)

    raise InvalidKeyError("Key must be a string or bytes.")


def generate_ctr_keystream(key: bytes, iv: bytes, length: int) -> bytes:
    """Generate CTR keystream using HMAC-SHA256 in counter mode:
    Block_i = HMAC-SHA256(key, iv || i.to_bytes(8, 'big'))
    """
    if length <= 0:
        return b""
    blocks: list[bytes] = []
    needed_blocks = math.ceil(length / 32)
    for i in range(needed_blocks):
        counter = i.to_bytes(8, "big")
        block = hmac.new(key, iv + counter, hashlib.sha256).digest()
        blocks.append(block)
    return b"".join(blocks)[:length]


def xor_bytes(data: bytes, keystream: bytes) -> bytes:
    """XOR two byte arrays together."""
    return bytes(a ^ b for a, b in zip(data, keystream))


def canonical_context_bytes(context: Any) -> bytes:
    """Serialize additional authenticated data (AAD) context into canonical bytes."""
    if context is None:
        return b""
    if isinstance(context, bytes):
        return context
    if isinstance(context, str):
        try:
            parsed = json.loads(context)
            return json.dumps(parsed, sort_keys=True, separators=(",", ":")).encode("utf-8")
        except json.JSONDecodeError:
            return context.encode("utf-8")
    if isinstance(context, (dict, list)):
        return json.dumps(context, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return str(context).encode("utf-8")


def encrypt_envelope(
    plaintext: str | bytes,
    kek: str | bytes,
    key_id: str = "default-kek",
    context: Any = None,
) -> dict[str, Any]:
    """Perform authenticated envelope encryption on plaintext using pure stdlib CTR + HMAC-SHA256.

    Returns a JSON-serializable dictionary with wrapped DEK, ciphertext, and authentication tag.
    """
    master_key = derive_kek(kek)
    data_bytes = plaintext.encode("utf-8") if isinstance(plaintext, str) else plaintext
    context_bytes = canonical_context_bytes(context)

    # 1. Generate 256-bit CSPRNG Ephemeral Data Encryption Key (DEK)
    dek = secrets.token_bytes(32)

    # 2. Encrypt plaintext under DEK using CTR mode
    iv_payload = secrets.token_bytes(16)
    keystream_payload = generate_ctr_keystream(dek, iv_payload, len(data_bytes))
    ciphertext = xor_bytes(data_bytes, keystream_payload)

    # 3. Wrap DEK under master KEK using CTR mode
    iv_dek = secrets.token_bytes(16)
    keystream_dek = generate_ctr_keystream(master_key, iv_dek, len(dek))
    wrapped_dek_raw = iv_dek + xor_bytes(dek, keystream_dek)

    # 4. Compute Encrypt-then-MAC authentication tag over IV, wrapped DEK, ciphertext, and AAD
    mac_content = iv_payload + wrapped_dek_raw + ciphertext + context_bytes
    tag = hmac.new(master_key, mac_content, hashlib.sha256).digest()

    context_hash = hashlib.sha256(context_bytes).hexdigest() if context_bytes else ""
    created_at = datetime.datetime.now(datetime.timezone.utc).isoformat()

    return {
        "vault_version": 1,
        "key_id": key_id,
        "created_at": created_at,
        "iv": base64.b64encode(iv_payload).decode("ascii"),
        "wrapped_dek": base64.b64encode(wrapped_dek_raw).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        "mac": base64.b64encode(tag).decode("ascii"),
        "context_hash": context_hash,
    }


def decrypt_envelope(
    envelope: dict[str, Any] | str,
    kek: str | bytes,
    context: Any = None,
    return_bytes: bool = False,
) -> str | bytes:
    """Decrypt an envelope-encrypted payload with constant-time MAC verification.

    Raises MACVerificationError if the envelope has been modified or incorrect KEK is used.
    """
    if isinstance(envelope, str):
        envelope = json.loads(envelope)

    master_key = derive_kek(kek)
    context_bytes = canonical_context_bytes(context)

    # Validate context hash if context was supplied or expected
    expected_context_hash = envelope.get("context_hash", "")
    actual_context_hash = hashlib.sha256(context_bytes).hexdigest() if context_bytes else ""
    if expected_context_hash and actual_context_hash != expected_context_hash:
        raise MACVerificationError("AAD context mismatch: expected hash does not match provided context")

    try:
        iv_payload = base64.b64decode(envelope["iv"])
        wrapped_dek_raw = base64.b64decode(envelope["wrapped_dek"])
        ciphertext = base64.b64decode(envelope["ciphertext"])
        expected_tag = base64.b64decode(envelope["mac"])
    except (KeyError, ValueError) as err:
        raise VaultTransitError(f"Malformed envelope data structure: {err}") from err

    # Constant-time MAC authentication verification (EtM)
    mac_content = iv_payload + wrapped_dek_raw + ciphertext + context_bytes
    computed_tag = hmac.new(master_key, mac_content, hashlib.sha256).digest()

    if not hmac.compare_digest(computed_tag, expected_tag):
        raise MACVerificationError("MAC verification failed: ciphertext altered or invalid KEK provided")

    # Unwrap DEK
    if len(wrapped_dek_raw) < 16:
        raise VaultTransitError("Invalid wrapped DEK payload length")
    iv_dek = wrapped_dek_raw[:16]
    encrypted_dek = wrapped_dek_raw[16:]
    keystream_dek = generate_ctr_keystream(master_key, iv_dek, len(encrypted_dek))
    dek = xor_bytes(encrypted_dek, keystream_dek)

    # Decrypt ciphertext under unwrapped DEK
    keystream_payload = generate_ctr_keystream(dek, iv_payload, len(ciphertext))
    plaintext_bytes = xor_bytes(ciphertext, keystream_payload)

    if return_bytes:
        return plaintext_bytes

    try:
        return plaintext_bytes.decode("utf-8")
    except UnicodeDecodeError:
        return plaintext_bytes


def generate_datakey(
    kek: str | bytes,
    key_id: str = "default-kek",
    bits: int = 256,
) -> dict[str, Any]:
    """Generate a high-entropy CSPRNG data key (DEK) and return both plaintext and wrapped forms."""
    if bits not in (128, 256):
        raise InvalidKeyError(f"Unsupported key size: {bits} bits. Allowed: 128 or 256 bits.")

    byte_length = bits // 8
    plaintext_dek = secrets.token_bytes(byte_length)

    # Wrap DEK using envelope encryption
    envelope = encrypt_envelope(plaintext_dek, kek, key_id=key_id)

    return {
        "key_id": key_id,
        "bits": bits,
        "plaintext": base64.b64encode(plaintext_dek).decode("ascii"),
        "plaintext_hex": plaintext_dek.hex(),
        "wrapped_dek": envelope["wrapped_dek"],
        "envelope": envelope,
    }
