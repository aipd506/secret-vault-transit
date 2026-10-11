# secret-vault-transit (`vaulttransit`)

Production-grade, zero-external-dependency authenticated envelope encryption, Shamir secret sharing, and cryptographic lease coordination engine engineered with pure Python standard library.

## Features

- **Authenticated Envelope Encryption**: Pure Python stdlib CTR stream cipher with HMAC-SHA256 Encrypt-then-MAC (EtM) and 256-bit CSPRNG ephemeral data encryption keys (DEK).
- **CSPRNG Data Key Generator**: On-demand generation of 128-bit and 256-bit data keys wrapped under master Key Encryption Keys (KEK).
- **Shamir $(k, n)$ Threshold Secret Sharing**: Lagrange polynomial interpolation over the 256-bit prime field $\mathbb{F}_P$ ($P = 2^{256} - 189$) using Python native modular inverse `pow(den, -1, P)`.
- **SQLite Lease Coordinator**: Stateful cryptographic lease tracking with TTL countdowns, atomic renewal, and instant revocation.
- **Dedicated CLI Binary**: Fully featured `vaulttransit` CLI supporting JSON input/output and POSIX exit codes.

## Installation

```bash
pip install -e .
```

## CLI Usage

### 1. Envelope Encryption
```bash
# Encrypt
vaulttransit encrypt --key "my-master-kek" --plaintext "top-secret-payload" --out envelope.json

# Decrypt
vaulttransit decrypt --key "my-master-kek" --in envelope.json
```

### 2. CSPRNG Data Key Generation
```bash
vaulttransit datakey --key "my-master-kek" --bits 256
```

### 3. Shamir Secret Sharing
```bash
# Split secret into 5 shares requiring 3 to reconstruct
vaulttransit shamir-split --secret "vault-master-recovery-password" -k 3 -n 5

# Combine shares to reconstruct secret
vaulttransit shamir-combine --shares "shard-1-1-..." "shard-2-2-..." "shard-3-3-..."
```

### 4. Lease Management
```bash
# Create a lease
vaulttransit lease --action create --key-id "kek-prod" --ttl 3600

# Inspect status
vaulttransit lease --action status --id "<lease-id>"

# Renew lease
vaulttransit lease --action renew --id "<lease-id>" --ttl 7200

# Revoke lease
vaulttransit lease --action revoke --id "<lease-id>"
```

## Exit Codes

- `0`: Operation succeeded.
- `1`: Authentication / MAC verification failed or decryption error.
- `2`: Invalid CLI arguments or syntax error.
- `3`: Lease expired or revoked.
- `4`: Shamir reconstruction error (insufficient shards or duplicate indices).

## License

MIT License. Copyright (c) 2026 aipd506.
