"""SQLite-backed cryptographic lease manager with TTL tracking, renewal, and revocation."""

from __future__ import annotations

import dataclasses
import json
import sqlite3
import time
import uuid
from typing import Any


class LeaseError(Exception):
    """Raised for lease operation failures."""
    pass


class LeaseExpiredOrRevokedError(LeaseError):
    """Raised when an operation is attempted on an expired or revoked lease."""
    pass


@dataclasses.dataclass
class Lease:
    lease_id: str
    key_id: str
    created_at: float
    ttl_seconds: int
    expires_at: float
    renewable: bool
    revoked: bool
    metadata: dict[str, Any] = dataclasses.field(default_factory=dict)

    @property
    def is_active(self) -> bool:
        """A lease is active if not revoked and current epoch is before expiration."""
        return not self.revoked and time.time() < self.expires_at

    def to_dict(self) -> dict[str, Any]:
        return {
            "lease_id": self.lease_id,
            "key_id": self.key_id,
            "created_at": self.created_at,
            "ttl_seconds": self.ttl_seconds,
            "expires_at": self.expires_at,
            "renewable": self.renewable,
            "revoked": self.revoked,
            "is_active": self.is_active,
            "metadata": self.metadata,
        }


class LeaseManager:
    """Manages secret leases backed by SQLite."""

    def __init__(self, db_path: str = "vault_leases.db") -> None:
        self.db_path = db_path
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._get_connection() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS leases (
                    lease_id TEXT PRIMARY KEY,
                    key_id TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    ttl_seconds INTEGER NOT NULL,
                    expires_at REAL NOT NULL,
                    renewable INTEGER NOT NULL,
                    revoked INTEGER NOT NULL,
                    metadata TEXT
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_leases_key_id ON leases(key_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_leases_expires_at ON leases(expires_at)")
            conn.commit()

    def create_lease(
        self,
        key_id: str,
        ttl_seconds: int = 3600,
        renewable: bool = True,
        metadata: dict[str, Any] | None = None,
        lease_id: str | None = None,
    ) -> Lease:
        """Create and persist a new lease."""
        lid = lease_id or str(uuid.uuid4())
        now = time.time()
        expires = now + ttl_seconds
        meta_json = json.dumps(metadata or {})

        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO leases (lease_id, key_id, created_at, ttl_seconds, expires_at, renewable, revoked, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (lid, key_id, now, ttl_seconds, expires, 1 if renewable else 0, 0, meta_json),
            )
            conn.commit()

        return Lease(
            lease_id=lid,
            key_id=key_id,
            created_at=now,
            ttl_seconds=ttl_seconds,
            expires_at=expires,
            renewable=renewable,
            revoked=False,
            metadata=metadata or {},
        )

    def get_lease(self, lease_id: str) -> Lease | None:
        """Retrieve lease by ID."""
        with self._get_connection() as conn:
            cursor = conn.execute("SELECT * FROM leases WHERE lease_id = ?", (lease_id,))
            row = cursor.fetchone()
            if not row:
                return None
            return self._row_to_lease(row)

    def is_valid(self, lease_id: str) -> bool:
        """Check if lease exists and is currently active."""
        lease = self.get_lease(lease_id)
        if not lease:
            return False
        return lease.is_active

    def renew_lease(self, lease_id: str, increment_seconds: int | None = None) -> Lease:
        """Extend the expiration time of an active, renewable lease."""
        lease = self.get_lease(lease_id)
        if not lease:
            raise LeaseError(f"Lease not found: {lease_id}")
        if lease.revoked:
            raise LeaseExpiredOrRevokedError(f"Cannot renew revoked lease: {lease_id}")
        if not lease.is_active:
            raise LeaseExpiredOrRevokedError(f"Cannot renew expired lease: {lease_id}")
        if not lease.renewable:
            raise LeaseError(f"Lease {lease_id} is marked as non-renewable")

        inc = increment_seconds if increment_seconds is not None else lease.ttl_seconds
        new_expires = time.time() + inc

        with self._get_connection() as conn:
            conn.execute(
                "UPDATE leases SET expires_at = ?, ttl_seconds = ? WHERE lease_id = ?",
                (new_expires, inc, lease_id),
            )
            conn.commit()

        lease.expires_at = new_expires
        lease.ttl_seconds = inc
        return lease

    def revoke_lease(self, lease_id: str) -> bool:
        """Mark a lease as revoked."""
        lease = self.get_lease(lease_id)
        if not lease:
            raise LeaseError(f"Lease not found: {lease_id}")

        with self._get_connection() as conn:
            cursor = conn.execute("UPDATE leases SET revoked = 1 WHERE lease_id = ?", (lease_id,))
            conn.commit()
            return cursor.rowcount > 0

    def reap_expired(self) -> int:
        """Delete leases that have expired or have been revoked."""
        now = time.time()
        with self._get_connection() as conn:
            cursor = conn.execute(
                "DELETE FROM leases WHERE expires_at < ? OR revoked = 1",
                (now,),
            )
            conn.commit()
            return cursor.rowcount

    def list_leases(self, key_id: str | None = None, active_only: bool = False) -> list[Lease]:
        """List all leases, optionally filtered by key_id or active status."""
        query = "SELECT * FROM leases WHERE 1=1"
        params: list[Any] = []
        if key_id:
            query += " AND key_id = ?"
            params.append(key_id)

        with self._get_connection() as conn:
            cursor = conn.execute(query, params)
            leases = [self._row_to_lease(row) for row in cursor.fetchall()]

        if active_only:
            leases = [l for l in leases if l.is_active]
        return leases

    @staticmethod
    def _row_to_lease(row: sqlite3.Row) -> Lease:
        meta = {}
        if row["metadata"]:
            try:
                meta = json.loads(row["metadata"])
            except json.JSONDecodeError:
                pass
        return Lease(
            lease_id=row["lease_id"],
            key_id=row["key_id"],
            created_at=float(row["created_at"]),
            ttl_seconds=int(row["ttl_seconds"]),
            expires_at=float(row["expires_at"]),
            renewable=bool(row["renewable"]),
            revoked=bool(row["revoked"]),
            metadata=meta,
        )
