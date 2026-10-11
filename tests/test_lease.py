"""Tests for secret-vault-transit SQLite lease manager module."""

import time
import pytest

from vaulttransit.lease import (
    LeaseError,
    LeaseExpiredOrRevokedError,
    LeaseManager,
)


def test_lease_lifecycle(tmp_path):
    db_file = str(tmp_path / "leases.db")
    mgr = LeaseManager(db_file)

    # 1. Create lease
    lease = mgr.create_lease(key_id="kek-test-01", ttl_seconds=10, renewable=True)
    assert lease.key_id == "kek-test-01"
    assert lease.is_active is True
    assert lease.revoked is False
    assert mgr.is_valid(lease.lease_id) is True

    # 2. Get lease
    fetched = mgr.get_lease(lease.lease_id)
    assert fetched is not None
    assert fetched.lease_id == lease.lease_id

    # 3. Renew lease
    renewed = mgr.renew_lease(lease.lease_id, increment_seconds=30)
    assert renewed.ttl_seconds == 30
    assert renewed.expires_at > lease.expires_at

    # 4. Revoke lease
    revoked = mgr.revoke_lease(lease.lease_id)
    assert revoked is True
    assert mgr.is_valid(lease.lease_id) is False

    # 5. Renewal on revoked lease fails
    with pytest.raises(LeaseExpiredOrRevokedError):
        mgr.renew_lease(lease.lease_id)


def test_lease_expiration_and_reap(tmp_path):
    db_file = str(tmp_path / "leases_expire.db")
    mgr = LeaseManager(db_file)

    # Create very short lease
    lease = mgr.create_lease(key_id="kek-short", ttl_seconds=1, renewable=True)
    time.sleep(1.1)

    assert lease.is_active is False
    assert mgr.is_valid(lease.lease_id) is False

    with pytest.raises(LeaseExpiredOrRevokedError):
        mgr.renew_lease(lease.lease_id)

    # Reap expired leases
    reaped = mgr.reap_expired()
    assert reaped >= 1
    assert mgr.get_lease(lease.lease_id) is None


def test_non_renewable_lease(tmp_path):
    db_file = str(tmp_path / "leases_norenew.db")
    mgr = LeaseManager(db_file)

    lease = mgr.create_lease(key_id="kek-fixed", ttl_seconds=60, renewable=False)
    with pytest.raises(LeaseError, match="non-renewable"):
        mgr.renew_lease(lease.lease_id)
