"""Shamir (k, n) secret sharing scheme over prime field F_P.

P = 2^256 - 189 = 115792089237316195423570985008687907853269984665640564039457584007913129639747.
Implements polynomial generation with cryptographically secure random coefficients and
Lagrange interpolation using Python native modular inverse pow(den, -1, P).
"""

from __future__ import annotations

import re
import secrets
from typing import Sequence

# Mersenne-adjacent 256-bit prime field modulus
PRIME_P: int = (1 << 256) - 189


class ShamirError(Exception):
    """Raised on Shamir secret sharing split or combination errors."""
    pass


def split_secret(
    secret: str | bytes,
    k: int = 3,
    n: int = 5,
) -> list[str]:
    """Split a secret string or bytes into n shares requiring threshold k to reconstruct.

    Returns a list of share strings in format: shard-<index>-<x_hex>-<y_hex>
    """
    if k < 2:
        raise ShamirError(f"Threshold k must be at least 2, got {k}")
    if n < k:
        raise ShamirError(f"Total shares n ({n}) must be greater than or equal to threshold k ({k})")
    if n > 1000:
        raise ShamirError(f"Total shares n ({n}) exceeds reasonable limit 1000")

    secret_bytes = secret.encode("utf-8") if isinstance(secret, str) else secret
    if not secret_bytes:
        raise ShamirError("Cannot split an empty secret")

    # Encode with 4-byte length header for exact byte recovery
    payload = len(secret_bytes).to_bytes(4, "big") + secret_bytes

    # Chunk into 31-byte segments (248 bits) to guarantee integer < PRIME_P
    chunk_size = 31
    rem = len(payload) % chunk_size
    if rem != 0:
        payload += b"\x00" * (chunk_size - rem)

    chunks = [payload[i : i + chunk_size] for i in range(0, len(payload), chunk_size)]

    # For each chunk, generate a random polynomial of degree k-1
    # f(x) = S + a_1*x + ... + a_{k-1}*x^{k-1} mod P
    chunk_evaluations: list[list[int]] = []  # chunk_evaluations[chunk_idx][share_idx]

    for chunk in chunks:
        s_int = int.from_bytes(chunk, "big")
        # Coefficients: a_0 is s_int, a_1..a_{k-1} are random in [1, P-1]
        coeffs = [s_int] + [secrets.randbelow(PRIME_P - 1) + 1 for _ in range(k - 1)]

        # Evaluate at x = 1 .. n
        y_vals: list[int] = []
        for x in range(1, n + 1):
            y = 0
            x_pow = 1
            for coeff in coeffs:
                y = (y + coeff * x_pow) % PRIME_P
                x_pow = (x_pow * x) % PRIME_P
            y_vals.append(y)
        chunk_evaluations.append(y_vals)

    # Format shares
    shares: list[str] = []
    for share_idx in range(n):
        x = share_idx + 1
        x_hex = f"{x:x}"
        y_parts = [f"{chunk_evaluations[c][share_idx]:x}" for c in range(len(chunks))]
        y_hex = ":".join(y_parts)
        shares.append(f"shard-{x}-{x_hex}-{y_hex}")

    return shares


def _parse_share(share_str: str) -> tuple[int, int, list[int]]:
    """Parse share string 'shard-<index>-<x_hex>-<y_hex>' into (index, x, [y_ints])."""
    parts = share_str.strip().split("-")
    if len(parts) < 4 or parts[0] != "shard":
        # Check if comma or space separated format
        raise ShamirError(f"Invalid share string format: '{share_str}'")

    try:
        index = int(parts[1])
        x = int(parts[2], 16)
        y_parts_str = "-".join(parts[3:])  # in case y contained a dash
        y_parts = [int(p, 16) for p in y_parts_str.split(":")]
    except ValueError as err:
        raise ShamirError(f"Failed to parse numeric values from share: '{share_str}': {err}") from err

    if x == 0:
        raise ShamirError("Invalid share: x cannot be 0")

    for y in y_parts:
        if y < 0 or y >= PRIME_P:
            raise ShamirError(f"Share y coordinate out of field bounds [0, P-1]: {y}")

    return index, x, y_parts


def combine_shares(
    shares: Sequence[str],
    threshold: int | None = None,
    return_bytes: bool = False,
) -> str | bytes:
    """Reconstruct secret from at least k shares using Lagrange polynomial interpolation over F_P."""
    if not shares:
        raise ShamirError("No shares provided for combination")

    cleaned_shares = [s.strip() for s in shares if s.strip()]
    if len(cleaned_shares) < 2 and (threshold is None or threshold > 1):
        raise ShamirError(f"Insufficient shares provided: need at least 2, got {len(cleaned_shares)}")

    if threshold is not None and len(cleaned_shares) < threshold:
        raise ShamirError(f"Insufficient shares provided: threshold is {threshold}, got {len(cleaned_shares)}")

    parsed_shares: list[tuple[int, list[int]]] = []
    seen_x: set[int] = set()

    for s_str in cleaned_shares:
        _, x, y_list = _parse_share(s_str)
        if x in seen_x:
            raise ShamirError(f"Duplicate share index detected (x={x})")
        seen_x.add(x)
        parsed_shares.append((x, y_list))

    num_chunks = len(parsed_shares[0][1])
    for _, y_list in parsed_shares:
        if len(y_list) != num_chunks:
            raise ShamirError("Mismatched chunk count across provided shares")

    # Reconstruct each chunk via Lagrange interpolation at x = 0
    # S = sum_{j=1}^m y_j * prod_{l != j} (-x_l) / (x_j - x_l) mod P
    reconstructed_chunks: list[bytes] = []
    num_shares = len(parsed_shares)

    for chunk_idx in range(num_chunks):
        s_int = 0
        for j in range(num_shares):
            x_j, y_list_j = parsed_shares[j]
            y_j = y_list_j[chunk_idx]

            # Compute Lagrange basis polynomial L_j(0)
            num = 1
            den = 1
            for l in range(num_shares):
                if l == j:
                    continue
                x_l, _ = parsed_shares[l]
                num = (num * (-x_l)) % PRIME_P
                den = (den * (x_j - x_l)) % PRIME_P

            # Modular inverse of denominator in F_P
            inv_den = pow(den, -1, PRIME_P)
            lagrange_coeff = (num * inv_den) % PRIME_P
            term = (y_j * lagrange_coeff) % PRIME_P
            s_int = (s_int + term) % PRIME_P

        # Convert chunk back to bytes
        # Calculate byte length: 31 bytes unless the last chunk
        byte_len = 31
        chunk_bytes = s_int.to_bytes(byte_len, "big")
        reconstructed_chunks.append(chunk_bytes)

    # Reconstruct combined payload
    full_payload = b"".join(reconstructed_chunks)

    # Read 4-byte length prefix
    if len(full_payload) < 4:
        raise ShamirError("Corrupted secret payload: length header missing")

    secret_len = int.from_bytes(full_payload[:4], "big")
    secret_bytes = full_payload[4 : 4 + secret_len]

    if len(secret_bytes) != secret_len:
        # Fallback if raw bytes reconstruction was used without length prefix
        stripped = full_payload.lstrip(b"\x00")
        if return_bytes:
            return stripped
        try:
            return stripped.decode("utf-8")
        except UnicodeDecodeError:
            return stripped

    if return_bytes:
        return secret_bytes

    try:
        return secret_bytes.decode("utf-8")
    except UnicodeDecodeError:
        return secret_bytes
