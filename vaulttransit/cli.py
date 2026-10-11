"""Command-line interface for secret-vault-transit (vaulttransit)."""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Sequence

from vaulttransit.envelope import (
    MACVerificationError,
    VaultTransitError,
    decrypt_envelope,
    encrypt_envelope,
    generate_datakey,
)
from vaulttransit.lease import (
    LeaseError,
    LeaseExpiredOrRevokedError,
    LeaseManager,
)
from vaulttransit.shamir import (
    ShamirError,
    combine_shares,
    split_secret,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vaulttransit",
        description="Zero-trust authenticated envelope encryption, Shamir secret sharing, and lease coordinator.",
    )
    parser.add_argument("--version", action="version", version="vaulttransit 0.1.0")

    subparsers = parser.add_subparsers(dest="subcommand", help="Subcommand to execute")

    # encrypt
    enc_parser = subparsers.add_parser("encrypt", help="Envelope-encrypt plaintext data")
    enc_parser.add_argument("-k", "--key", "--key-id", dest="key_id", required=True, help="KEK identifier or key string")
    enc_parser.add_argument("-p", "--plaintext", help="Plaintext string to encrypt")
    enc_parser.add_argument("-i", "--in", dest="input_file", help="Input file path containing plaintext")
    enc_parser.add_argument("-o", "--out", dest="output_file", help="Output file path for ciphertext envelope")
    enc_parser.add_argument("-c", "--context", help="Additional Authenticated Data (AAD) JSON or string")
    enc_parser.add_argument("--lease-id", help="Optional lease ID to validate before encryption")
    enc_parser.add_argument("--db", default="vault_leases.db", help="Path to SQLite lease database")
    enc_parser.add_argument("-j", "--json", action="store_true", default=True, help="Output JSON envelope")

    # decrypt
    dec_parser = subparsers.add_parser("decrypt", help="Decrypt ciphertext envelope with MAC verification")
    dec_parser.add_argument("-k", "--key", "--key-id", dest="key_id", required=True, help="KEK identifier or key string")
    dec_parser.add_argument("-e", "--envelope", "--ciphertext", dest="ciphertext", help="Ciphertext envelope JSON string")
    dec_parser.add_argument("-i", "--in", dest="input_file", help="Input file containing ciphertext envelope")
    dec_parser.add_argument("-o", "--out", dest="output_file", help="Output file path for decrypted plaintext")
    dec_parser.add_argument("-c", "--context", help="AAD context string or JSON")
    dec_parser.add_argument("--lease-id", help="Optional lease ID to validate before decryption")
    dec_parser.add_argument("--db", default="vault_leases.db", help="Path to SQLite lease database")

    # datakey
    dk_parser = subparsers.add_parser("datakey", help="Generate ephemeral CSPRNG data key (DEK)")
    dk_parser.add_argument("-k", "--key", "--key-id", dest="key_id", required=True, help="KEK under which to wrap the new DEK")
    dk_parser.add_argument("-b", "--bits", type=int, default=256, choices=[128, 256], help="Key entropy size (128 or 256 bits)")
    dk_parser.add_argument("-j", "--json", action="store_true", default=True, help="Output JSON format")

    # shamir-split
    split_parser = subparsers.add_parser("shamir-split", help="Split secret into (k, n) shards over prime field")
    split_parser.add_argument("-s", "--secret", required=True, help="Secret string to divide into shares")
    split_parser.add_argument("-k", type=int, default=3, help="Reconstruction threshold k (default: 3)")
    split_parser.add_argument("-n", type=int, default=5, help="Total number of shares n (default: 5)")
    split_parser.add_argument("-j", "--json", action="store_true", default=True, help="Output shares as JSON array")

    # shamir-combine
    comb_parser = subparsers.add_parser("shamir-combine", help="Combine shares to reconstruct secret")
    comb_parser.add_argument("--shares", nargs="*", help="List of share strings or comma-separated share strings")
    comb_parser.add_argument("-f", "--file", help="File containing shares (JSON array or newline-separated)")
    comb_parser.add_argument("-t", "--threshold", type=int, help="Expected threshold k")
    comb_parser.add_argument("-o", "--out", help="Output destination file")

    # lease
    lease_parser = subparsers.add_parser("lease", help="Manage cryptographic secret leases")
    lease_parser.add_argument(
        "-a", "--action",
        choices=["create", "renew", "revoke", "status", "reap", "list"],
        default="status",
        help="Lease action to perform",
    )
    lease_parser.add_argument("-l", "--id", "--lease-id", dest="lease_id", help="Lease ID identifier")
    lease_parser.add_argument("-k", "--key-id", help="Key ID for create action")
    lease_parser.add_argument("--ttl", type=int, default=3600, help="Lease TTL duration in seconds")
    lease_parser.add_argument("--db", default="vault_leases.db", help="Path to SQLite lease database")
    lease_parser.add_argument("-j", "--json", action="store_true", default=True, help="Output JSON format")

    return parser


def handle_encrypt(args: argparse.Namespace) -> int:
    # Check lease if specified
    if args.lease_id:
        mgr = LeaseManager(args.db)
        if not mgr.is_valid(args.lease_id):
            sys.stderr.write(f"Error: Lease '{args.lease_id}' is expired or revoked.\n")
            return 3

    plaintext = args.plaintext
    if plaintext is None and args.input_file:
        with open(args.input_file, "rb") as f:
            plaintext = f.read()
    elif plaintext is None:
        if not sys.stdin.isatty():
            plaintext = sys.stdin.read()
        else:
            sys.stderr.write("Error: Plaintext must be provided via -p, -i/--in, or stdin.\n")
            return 2

    try:
        envelope = encrypt_envelope(plaintext, kek=args.key_id, key_id=args.key_id, context=args.context)
    except Exception as err:
        sys.stderr.write(f"Encryption error: {err}\n")
        return 1

    out_str = json.dumps(envelope, indent=2)
    if args.output_file:
        with open(args.output_file, "w", encoding="utf-8") as f:
            f.write(out_str)
    else:
        print(out_str)
    return 0


def handle_decrypt(args: argparse.Namespace) -> int:
    # Check lease if specified
    if args.lease_id:
        mgr = LeaseManager(args.db)
        if not mgr.is_valid(args.lease_id):
            sys.stderr.write(f"Error: Lease '{args.lease_id}' is expired or revoked.\n")
            return 3

    envelope_data = args.ciphertext
    if envelope_data is None and args.input_file:
        with open(args.input_file, "r", encoding="utf-8") as f:
            envelope_data = f.read()
    elif envelope_data is None:
        if not sys.stdin.isatty():
            envelope_data = sys.stdin.read()
        else:
            sys.stderr.write("Error: Envelope ciphertext must be provided via -e, -i/--in, or stdin.\n")
            return 2

    try:
        plaintext = decrypt_envelope(envelope_data, kek=args.key_id, context=args.context)
    except MACVerificationError as err:
        sys.stderr.write(f"Authentication/MAC verification failed: {err}\n")
        return 1
    except Exception as err:
        sys.stderr.write(f"Decryption error: {err}\n")
        return 1

    if args.output_file:
        if isinstance(plaintext, bytes):
            with open(args.output_file, "wb") as f:
                f.write(plaintext)
        else:
            with open(args.output_file, "w", encoding="utf-8") as f:
                f.write(plaintext)
    else:
        if isinstance(plaintext, bytes):
            sys.stdout.buffer.write(plaintext)
        else:
            print(plaintext)
    return 0


def handle_datakey(args: argparse.Namespace) -> int:
    try:
        res = generate_datakey(kek=args.key_id, key_id=args.key_id, bits=args.bits)
        print(json.dumps(res, indent=2))
        return 0
    except Exception as err:
        sys.stderr.write(f"Data key generation error: {err}\n")
        return 1


def handle_shamir_split(args: argparse.Namespace) -> int:
    try:
        shares = split_secret(args.secret, k=args.k, n=args.n)
        output = {
            "threshold": args.k,
            "total_shares": args.n,
            "shares": shares,
        }
        if args.json:
            print(json.dumps(output, indent=2))
        else:
            for s in shares:
                print(s)
        return 0
    except ShamirError as err:
        sys.stderr.write(f"Shamir split error: {err}\n")
        return 4
    except Exception as err:
        sys.stderr.write(f"Unexpected error: {err}\n")
        return 1


def handle_shamir_combine(args: argparse.Namespace) -> int:
    share_list: list[str] = []
    if args.shares:
        for s in args.shares:
            if "," in s:
                share_list.extend(part.strip() for part in s.split(",") if part.strip())
            else:
                share_list.append(s.strip())
    elif args.file:
        with open(args.file, "r", encoding="utf-8") as f:
            content = f.read().strip()
            if content.startswith("["):
                try:
                    data = json.loads(content)
                    if isinstance(data, list):
                        share_list.extend(str(item) for item in data)
                except json.JSONDecodeError:
                    share_list.extend(content.splitlines())
            elif content.startswith("{"):
                try:
                    data = json.loads(content)
                    if "shares" in data and isinstance(data["shares"], list):
                        share_list.extend(str(item) for item in data["shares"])
                except json.JSONDecodeError:
                    share_list.extend(content.splitlines())
            else:
                share_list.extend(content.splitlines())
    else:
        if not sys.stdin.isatty():
            content = sys.stdin.read().strip()
            share_list.extend(content.splitlines())
        else:
            sys.stderr.write("Error: Shares must be provided via --shares, -f/--file, or stdin.\n")
            return 2

    try:
        recovered = combine_shares(share_list, threshold=args.threshold)
    except ShamirError as err:
        sys.stderr.write(f"Shamir combination error: {err}\n")
        return 4
    except Exception as err:
        sys.stderr.write(f"Reconstruction failed: {err}\n")
        return 4

    out_str = recovered if isinstance(recovered, str) else recovered.decode("utf-8", errors="replace")
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(out_str)
    else:
        print(out_str)
    return 0


def handle_lease(args: argparse.Namespace) -> int:
    mgr = LeaseManager(args.db)
    action = args.action

    try:
        if action == "create":
            key_id = args.key_id or "default-key"
            lease = mgr.create_lease(key_id=key_id, ttl_seconds=args.ttl, lease_id=args.lease_id)
            print(json.dumps(lease.to_dict(), indent=2))
            return 0

        elif action == "renew":
            if not args.lease_id:
                sys.stderr.write("Error: --id / --lease-id is required for renew action.\n")
                return 2
            lease = mgr.renew_lease(args.lease_id, increment_seconds=args.ttl)
            print(json.dumps(lease.to_dict(), indent=2))
            return 0

        elif action == "revoke":
            if not args.lease_id:
                sys.stderr.write("Error: --id / --lease-id is required for revoke action.\n")
                return 2
            revoked = mgr.revoke_lease(args.lease_id)
            print(json.dumps({"lease_id": args.lease_id, "revoked": revoked}, indent=2))
            return 0

        elif action == "status":
            if not args.lease_id:
                sys.stderr.write("Error: --id / --lease-id is required for status action.\n")
                return 2
            lease = mgr.get_lease(args.lease_id)
            if not lease:
                sys.stderr.write(f"Error: Lease '{args.lease_id}' not found.\n")
                return 1
            print(json.dumps(lease.to_dict(), indent=2))
            if not lease.is_active:
                return 3
            return 0

        elif action == "reap":
            count = mgr.reap_expired()
            print(json.dumps({"reaped_count": count}, indent=2))
            return 0

        elif action == "list":
            leases = mgr.list_leases(key_id=args.key_id)
            print(json.dumps([l.to_dict() for l in leases], indent=2))
            return 0

    except LeaseExpiredOrRevokedError as err:
        sys.stderr.write(f"Lease expired or revoked: {err}\n")
        return 3
    except LeaseError as err:
        sys.stderr.write(f"Lease error: {err}\n")
        return 1
    except Exception as err:
        sys.stderr.write(f"Unexpected error: {err}\n")
        return 1

    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.subcommand:
        parser.print_help()
        return 2

    if args.subcommand == "encrypt":
        return handle_encrypt(args)
    elif args.subcommand == "decrypt":
        return handle_decrypt(args)
    elif args.subcommand == "datakey":
        return handle_datakey(args)
    elif args.subcommand == "shamir-split":
        return handle_shamir_split(args)
    elif args.subcommand == "shamir-combine":
        return handle_shamir_combine(args)
    elif args.subcommand == "lease":
        return handle_lease(args)

    return 2


if __name__ == "__main__":
    sys.exit(main())
