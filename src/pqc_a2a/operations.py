"""Operational building blocks for deployments.

The interfaces are deliberately small so applications can replace SQLite,
logging, metrics, or the secret provider with their own infrastructure.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import sqlite3
import threading
import time
import secrets
from pathlib import Path
from typing import Protocol


class SecretProvider(Protocol):
    def get(self, name: str) -> bytes: ...
    def put(self, name: str, value: bytes) -> None: ...
    def destroy(self, name: str) -> None: ...


class FileSecretProvider:
    """Filesystem secret provider with explicit plaintext-at-rest semantics.

    This class is intentionally not marketed as encrypted storage. Production
    deployments should provide a KMS/HSM-backed implementation of
    :class:`SecretProvider`; this provider is suitable only for controlled
    development or hosts where the filesystem itself is trusted.
    """
    def __init__(self, root: str | os.PathLike[str]):
        self.root = Path(root); self.root.mkdir(parents=True, exist_ok=True)
        os.chmod(self.root, 0o700)
        self._lock = threading.RLock()

    def _path(self, name: str) -> Path:
        if not name or "/" in name or "\\" in name or name in {".", ".."}:
            raise ValueError("invalid secret name")
        return self.root / f"{hashlib.sha256(name.encode()).hexdigest()}.secret"

    def get(self, name: str) -> bytes:
        with self._lock:
            return self._path(name).read_bytes()

    def put(self, name: str, value: bytes) -> None:
        if not isinstance(value, bytes) or not value:
            raise ValueError("secret must be non-empty bytes")
        path = self._path(name)
        temporary = path.with_name(f".{path.name}.tmp")
        with self._lock:
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            fd = os.open(temporary, flags, 0o600)
            try:
                with os.fdopen(fd, "wb") as handle:
                    handle.write(value)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(temporary, path)
                directory_fd = os.open(self.root, os.O_RDONLY)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
            finally:
                try:
                    temporary.unlink()
                except FileNotFoundError:
                    pass

    def destroy(self, name: str) -> None:
        with self._lock:
            try: self._path(name).unlink()
            except FileNotFoundError: pass


def best_effort_zeroize(buffer: bytearray) -> None:
    """Overwrite mutable secret storage; Python immutable bytes cannot be guaranteed cleared."""
    if not isinstance(buffer, bytearray):
        raise TypeError("zeroization requires bytearray")
    for index in range(len(buffer)):
        buffer[index] = 0


class DurableReplayCache:
    """SQLite-backed replay cache with atomic insert-and-expiry cleanup."""
    def __init__(self, path: str | os.PathLike[str], ttl_seconds: float = 300.0, max_entries: int = 100_000):
        if ttl_seconds <= 0 or max_entries < 1: raise ValueError("invalid replay limits")
        self.path, self.ttl_seconds, self.max_entries = str(path), ttl_seconds, max_entries
        self._lock = threading.RLock()
        self._memory_db = self.path == ":memory:"
        self._db = sqlite3.connect(":memory:", timeout=5, isolation_level="IMMEDIATE") if self._memory_db else None
        with self._connect() as db:
            db.execute("CREATE TABLE IF NOT EXISTS replay (message_id TEXT PRIMARY KEY, seen_at REAL NOT NULL)")
            db.commit()

    def _connect(self):
        if self._db is not None:
            return self._db
        db = sqlite3.connect(self.path, timeout=5, isolation_level="IMMEDIATE")
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=FULL")
        return db

    def accept(self, message_id: str, now: float | None = None) -> bool:
        if not isinstance(message_id, str) or not message_id: raise ValueError("message_id required")
        now = time.time() if now is None else now
        cutoff = now - self.ttl_seconds
        with self._lock, self._connect() as db:
            db.execute("DELETE FROM replay WHERE seen_at < ?", (cutoff,))
            if db.execute("SELECT 1 FROM replay WHERE message_id = ?", (message_id,)).fetchone(): return False
            if db.execute("SELECT COUNT(*) FROM replay").fetchone()[0] >= self.max_entries:
                raise RuntimeError("durable replay cache capacity exceeded")
            db.execute("INSERT INTO replay VALUES (?, ?)", (message_id, now)); db.commit(); return True


class AuditLogger:
    def __init__(self, logger: logging.Logger | None = None): self.logger = logger or logging.getLogger("pqc_a2a.audit")
    def event(self, name: str, **fields: object) -> None:
        record = {"event": name, "timestamp": time.time(), **fields}
        self.logger.info(json.dumps(record, sort_keys=True, separators=(",", ":")))


class Metrics:
    def __init__(self): self._values: dict[str, int] = {}; self._lock = threading.Lock()
    def inc(self, name: str, value: int = 1) -> None:
        if value < 0: raise ValueError("metric increment must be non-negative")
        with self._lock: self._values[name] = self._values.get(name, 0) + value
    def snapshot(self) -> dict[str, int]:
        with self._lock: return dict(self._values)


def redact_metadata(value: object, *, sensitive_keys: tuple[str, ...] = ("agent_id", "sender", "recipient", "ip", "url", "endpoint")) -> object:
    if isinstance(value, dict):
        return {key: "[redacted]" if key.lower() in sensitive_keys else redact_metadata(item, sensitive_keys=sensitive_keys) for key, item in value.items()}
    if isinstance(value, list): return [redact_metadata(item, sensitive_keys=sensitive_keys) for item in value]
    return value


def padding_bucket(size: int, buckets: tuple[int, ...] = (256, 1024, 4096, 16384, 65536)) -> int:
    if size < 0 or not buckets or any(item <= 0 for item in buckets): raise ValueError("invalid padding size")
    for bucket in buckets:
        if size <= bucket: return bucket
    raise ValueError("message exceeds largest padding bucket")


def dummy_payload(size: int = 256) -> bytes:
    if size < 1 or size > 1 << 20: raise ValueError("invalid dummy payload size")
    return secrets.token_bytes(size)


class SkippedKeyStore:
    """Bounded key store for loss/out-of-order session protocols."""
    def __init__(self, max_keys: int = 256, max_bytes: int = 1 << 20):
        if max_keys < 1 or max_bytes < 32: raise ValueError("invalid skipped-key limits")
        self.max_keys, self.max_bytes, self._keys, self._bytes, self._lock = max_keys, max_bytes, {}, 0, threading.RLock()

    def put(self, key_id: str, key: bytes) -> None:
        if not key_id or not isinstance(key, bytes) or not key: raise ValueError("invalid skipped key")
        with self._lock:
            if key_id in self._keys: return
            if len(self._keys) >= self.max_keys or self._bytes + len(key) > self.max_bytes:
                raise RuntimeError("skipped-key store capacity exceeded")
            self._keys[key_id], self._bytes = key, self._bytes + len(key)

    def pop(self, key_id: str) -> bytes | None:
        with self._lock:
            value = self._keys.pop(key_id, None)
            if value is not None: self._bytes -= len(value)
            return value

    def __len__(self) -> int: return len(self._keys)


__all__ = ["SecretProvider", "FileSecretProvider", "best_effort_zeroize", "DurableReplayCache", "AuditLogger", "Metrics", "redact_metadata", "padding_bucket", "SkippedKeyStore"]
