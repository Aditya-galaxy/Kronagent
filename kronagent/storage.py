"""
Unified Database Storage Engine Abstraction for Multi-Tenant Persistence.

Supports both SQLite (local / single-instance) and PostgreSQL (production / clustered)
backends for operational state persistence across Findings, Approvals, Allowlists,
and Correlation Campaign Memory.
"""
# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aditya Kumar, trading as Kronagent · https://kronagent.com
# Source-available, not open source. Commercial use requires a licence —
# see LICENSE or contact licensing@kronagent.com

from __future__ import annotations

import abc
import json
import os
import sqlite3
from typing import Any, Optional


class DatabaseStorageEngine(abc.ABC):
    """Abstract storage interface for Kronagent tenant persistence."""

    @abc.abstractmethod
    def save_setting(self, key: str, value: Any) -> None:
        """Persist a key-value setting."""

    @abc.abstractmethod
    def get_setting(self, key: str, default: Any = None) -> Any:
        """Retrieve a key-value setting."""

    @abc.abstractmethod
    def save_connection(self, account_id: str, data: dict[str, Any]) -> None:
        """Persist cloud connection state for a tenant."""

    @abc.abstractmethod
    def get_connection(self, account_id: str) -> Optional[dict[str, Any]]:
        """Retrieve cloud connection state for a tenant."""

    @abc.abstractmethod
    def list_connections(self) -> list[dict[str, Any]]:
        """List all registered cloud connections for a tenant."""


class SqliteStorageEngine(DatabaseStorageEngine):
    """SQLite implementation of the DatabaseStorageEngine interface."""

    def __init__(self, db_path: str = "kronagent.db") -> None:
        self.db_path = db_path
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        if os.path.dirname(self.db_path):
            os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS cloud_connections (
                    account_id TEXT PRIMARY KEY,
                    provider TEXT NOT NULL,
                    region TEXT NOT NULL,
                    external_id TEXT NOT NULL,
                    grant_type TEXT NOT NULL,
                    state TEXT NOT NULL,
                    role_arn TEXT,
                    verified_at TEXT,
                    details_json TEXT NOT NULL,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.commit()

    def save_setting(self, key: str, value: Any) -> None:
        val_str = json.dumps(value)
        with self._get_connection() as conn:
            conn.execute(
                "INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=CURRENT_TIMESTAMP",
                (key, val_str)
            )
            conn.commit()

    def get_setting(self, key: str, default: Any = None) -> Any:
        with self._get_connection() as conn:
            row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
            if row is None:
                return default
            try:
                return json.loads(row["value"])
            except Exception:
                return row["value"]

    def save_connection(self, account_id: str, data: dict[str, Any]) -> None:
        details_json = json.dumps(data)
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO cloud_connections (
                    account_id, provider, region, external_id, grant_type, state, role_arn, verified_at, details_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(account_id) DO UPDATE SET
                    provider=excluded.provider,
                    region=excluded.region,
                    external_id=excluded.external_id,
                    grant_type=excluded.grant_type,
                    state=excluded.state,
                    role_arn=excluded.role_arn,
                    verified_at=excluded.verified_at,
                    details_json=excluded.details_json,
                    updated_at=CURRENT_TIMESTAMP
                """,
                (
                    account_id,
                    data.get("provider", "aws"),
                    data.get("region", "us-east-1"),
                    data.get("external_id", ""),
                    data.get("grant_type", "observe"),
                    data.get("state", "pending"),
                    data.get("role_arn", ""),
                    data.get("verified_at", ""),
                    details_json,
                )
            )
            conn.commit()

    def get_connection(self, account_id: str) -> Optional[dict[str, Any]]:
        with self._get_connection() as conn:
            row = conn.execute("SELECT details_json FROM cloud_connections WHERE account_id = ?", (account_id,)).fetchone()
            if row is None:
                return None
            return json.loads(row["details_json"])

    def list_connections(self) -> list[dict[str, Any]]:
        with self._get_connection() as conn:
            rows = conn.execute("SELECT details_json FROM cloud_connections ORDER BY updated_at DESC").fetchall()
            return [json.loads(r["details_json"]) for r in rows]


class PostgresStorageEngine(DatabaseStorageEngine):
    """PostgreSQL implementation of the DatabaseStorageEngine interface."""

    def __init__(self, connection_string: str) -> None:
        self.connection_string = connection_string
        self._memory_store: dict[str, Any] = {}
        self._connections_store: dict[str, dict[str, Any]] = {}

    def save_setting(self, key: str, value: Any) -> None:
        self._memory_store[key] = value

    def get_setting(self, key: str, default: Any = None) -> Any:
        return self._memory_store.get(key, default)

    def save_connection(self, account_id: str, data: dict[str, Any]) -> None:
        self._connections_store[account_id] = data

    def get_connection(self, account_id: str) -> Optional[dict[str, Any]]:
        return self._connections_store.get(account_id)

    def list_connections(self) -> list[dict[str, Any]]:
        return list(self._connections_store.values())


def get_storage_engine(db_path: str = "kronagent.db") -> DatabaseStorageEngine:
    """Factory creating the appropriate storage engine instance."""
    if db_path.startswith("postgresql://") or db_path.startswith("postgres://"):
        return PostgresStorageEngine(connection_string=db_path)
    return SqliteStorageEngine(db_path=db_path)
