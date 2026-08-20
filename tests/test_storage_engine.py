"""
Unit tests for the Database Storage Engine Abstraction in kronagent/storage.py.
"""

from __future__ import annotations

import os
import tempfile

from kronagent.storage import SqliteStorageEngine, get_storage_engine


def test_sqlite_storage_settings_crud():
    with tempfile.TemporaryDirectory() as tmp_dir:
        db_path = os.path.join(tmp_dir, "test.db")
        engine = SqliteStorageEngine(db_path=db_path)

        assert engine.get_setting("non_existent", "default_val") == "default_val"

        engine.save_setting("test_key", {"active": True, "count": 42})
        retrieved = engine.get_setting("test_key")
        assert retrieved == {"active": True, "count": 42}


def test_sqlite_storage_cloud_connections():
    with tempfile.TemporaryDirectory() as tmp_dir:
        db_path = os.path.join(tmp_dir, "test.db")
        engine = get_storage_engine(db_path=db_path)

        conn_data = {
            "account_id": "123456789012",
            "provider": "aws",
            "region": "us-east-1",
            "external_id": "kronagent-secret-id",
            "grant_type": "observe",
            "state": "pending",
            "role_arn": "arn:aws:iam::123456789012:role/KronagentObserveRole"
        }

        assert engine.get_connection("123456789012") is None
        engine.save_connection("123456789012", conn_data)

        fetched = engine.get_connection("123456789012")
        assert fetched is not None
        assert fetched["account_id"] == "123456789012"
        assert fetched["external_id"] == "kronagent-secret-id"

        all_conns = engine.list_connections()
        assert len(all_conns) == 1
        assert all_conns[0]["account_id"] == "123456789012"


def test_postgres_storage_engine_factory():
    pg_engine = get_storage_engine("postgresql://user:pass@localhost:5432/kronagent")
    assert pg_engine.__class__.__name__ == "PostgresStorageEngine"
    pg_engine.save_setting("key1", "val1")
    assert pg_engine.get_setting("key1") == "val1"
