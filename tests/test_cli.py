"""Tests for secret-vault-transit CLI subcommands and exit codes."""

import json
from io import StringIO
import pytest
from unittest.mock import patch

from vaulttransit.cli import main


def test_cli_help_and_version():
    with pytest.raises(SystemExit) as exc:
        main(["--help"])
    assert exc.value.code == 0

    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0

    # No subcommand returns 2
    assert main([]) == 2


def test_cli_encrypt_decrypt_roundtrip(capsys, tmp_path):
    kek = "cli-kek-test-key-2026"
    plaintext = "Sensitive database connection string"
    out_enc = tmp_path / "enc.json"
    out_dec = tmp_path / "dec.txt"

    # Encrypt
    rc = main(["encrypt", "-k", kek, "-p", plaintext, "-o", str(out_enc)])
    assert rc == 0
    assert out_enc.exists()

    with open(out_enc, "r", encoding="utf-8") as f:
        env_data = json.load(f)
    assert env_data["vault_version"] == 1

    # Decrypt from file
    rc = main(["decrypt", "-k", kek, "-i", str(out_enc), "-o", str(out_dec)])
    assert rc == 0
    with open(out_dec, "r", encoding="utf-8") as f:
        assert f.read() == plaintext


def test_cli_decrypt_wrong_key(capsys, tmp_path):
    kek = "cli-kek-correct"
    plaintext = "Classified intelligence"
    out_enc = tmp_path / "enc.json"

    rc = main(["encrypt", "-k", kek, "-p", plaintext, "-o", str(out_enc)])
    assert rc == 0

    # Decrypt with incorrect key must fail with exit code 1
    rc = main(["decrypt", "-k", "cli-kek-WRONG", "-i", str(out_enc)])
    assert rc == 1


def test_cli_datakey(capsys):
    kek = "kek-datakey-cli"
    with patch("sys.stdout", new_callable=StringIO) as fake_out:
        rc = main(["datakey", "-k", kek, "-b", "256"])
        assert rc == 0
        output = json.loads(fake_out.getvalue())
        assert output["bits"] == 256
        assert "plaintext" in output
        assert "wrapped_dek" in output


def test_cli_shamir_split_combine(capsys, tmp_path):
    secret = "classified-nuclear-launch-codes-1234"
    shares_file = tmp_path / "shares.json"

    with patch("sys.stdout", new_callable=StringIO) as fake_out:
        rc = main(["shamir-split", "-s", secret, "-k", "3", "-n", "5"])
        assert rc == 0
        split_res = json.loads(fake_out.getvalue())
        shares = split_res["shares"]

    with open(shares_file, "w", encoding="utf-8") as f:
        json.dump(shares[:3], f)

    out_secret = tmp_path / "recovered.txt"
    rc = main(["shamir-combine", "-f", str(shares_file), "-o", str(out_secret)])
    assert rc == 0
    with open(out_secret, "r", encoding="utf-8") as f:
        assert f.read() == secret

    # Combine with invalid format or duplicate fails with exit code 4
    rc = main(["shamir-combine", "--shares", shares[0], shares[0]])
    assert rc == 4


def test_cli_lease_lifecycle(tmp_path):
    db_file = str(tmp_path / "cli_leases.db")

    # Create lease
    with patch("sys.stdout", new_callable=StringIO) as fake_out:
        rc = main(["lease", "-a", "create", "-k", "key-123", "--ttl", "100", "--db", db_file])
        assert rc == 0
        res = json.loads(fake_out.getvalue())
        lease_id = res["lease_id"]

    # Status active
    with patch("sys.stdout", new_callable=StringIO) as fake_out:
        rc = main(["lease", "-a", "status", "-l", lease_id, "--db", db_file])
        assert rc == 0
        res = json.loads(fake_out.getvalue())
        assert res["is_active"] is True

    # Renew lease
    rc = main(["lease", "-a", "renew", "-l", lease_id, "--ttl", "200", "--db", db_file])
    assert rc == 0

    # Revoke lease
    rc = main(["lease", "-a", "revoke", "-l", lease_id, "--db", db_file])
    assert rc == 0

    # Status of revoked lease returns 3
    rc = main(["lease", "-a", "status", "-l", lease_id, "--db", db_file])
    assert rc == 3
