"""On-disk cache of provider results, so repeat lookups don't re-spend quota.

The motivating case is the one the README pitches: a cron job or CI pipeline
re-checking the same indicators daily. Without a cache, every run burns the
whole free-tier allowance (AbuseIPDB is 1000 checks/day) re-asking questions it
already has answers to.

Two design choices are load-bearing:

**Per-provider grain.** Entries are keyed by (ioc_type, ioc, provider), not by
report. If a user adds an AbuseIPDB key, that provider was previously *skipped*
and must now actually run — a whole-report cache would keep serving the stale
skip. Same for retrying a single provider that errored while others succeeded.

**Only successful answers are cached.** Errors, skips, and rate-limit responses
are deliberately never stored. An error is transient: caching a 500 for a day
means one upstream blip silently degrades every lookup until it expires. A skip
is *configuration* state, not data: caching "no API key configured" would mean
adding the key appears to do nothing. Both would be failures of a security
control, so the cache stores only results that genuinely answered.

The cache records every indicator the operator has investigated, which is
sensitive in itself, so the file is created 0600 in a 0700 directory and the
tool refuses to use a symlinked cache path.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from pathlib import Path
from typing import TypedDict

from iocvet.config import PERMISSIONS_ENFORCED
from iocvet.core.models import IOCType, ProviderResult

CACHE_DIR = Path(
    os.environ.get("IOCVET_CACHE_DIR", Path.home() / ".cache" / "iocvet")
)
CACHE_PATH = CACHE_DIR / "cache.db"

#: Default entry lifetime. Threat intel goes stale in both directions — a host
#: that was clean yesterday can be compromised today — so this is deliberately
#: short enough that a daily run re-checks everything, while still collapsing
#: the repeated lookups within a single investigation. Override with
#: --cache-ttl when a workflow needs something different.
DEFAULT_TTL_SECONDS = 24 * 60 * 60

#: Hard ceiling on stored entries. A large feed (50k+ indicators) would
#: otherwise grow the file without bound — roughly 4 KB per entry, so 100k
#: entries is ~390 MB sitting in a user's home directory forever. When the cap
#: is exceeded the oldest entries are evicted first: they are closest to
#: expiring anyway, and everything here is re-fetchable.
MAX_ENTRIES = 50_000

#: Bumped whenever the table layout changes. An older cache file is discarded
#: and rebuilt rather than queried with a mismatched schema, so upgrading the
#: tool can never fail against a stale database.
_SCHEMA_VERSION = 1

_SCHEMA = """
CREATE TABLE IF NOT EXISTS provider_results (
    ioc_type  TEXT NOT NULL,
    ioc       TEXT NOT NULL,
    provider  TEXT NOT NULL,
    payload   TEXT NOT NULL,
    cached_at REAL NOT NULL,
    PRIMARY KEY (ioc_type, ioc, provider)
);
CREATE INDEX IF NOT EXISTS idx_provider_results_cached_at
    ON provider_results (cached_at);
"""


class CacheStats(TypedDict):
    """Shape returned by :meth:`ResultCache.stats`, kept explicit so callers
    can do arithmetic on the numeric fields without casting."""

    available: bool
    path: str
    entries: int
    expired: int
    size_bytes: int


class CacheError(Exception):
    """Raised for cache problems the user should know about (e.g. a symlinked
    cache path). Ordinary unavailability is handled by degrading silently
    instead — a broken cache must never stop a lookup from working.
    """


class ResultCache:
    """A small SQLite-backed store of provider results.

    Every method is failure-tolerant by design: if the database can't be opened,
    is corrupt, or a query fails, the cache reports a miss and the caller simply
    queries the provider. A cache is an optimisation, and an optimisation that
    can break the tool is worse than no cache at all.
    """

    def __init__(
        self,
        path: Path | None = None,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
    ) -> None:
        self.path = path if path is not None else CACHE_PATH
        self.ttl_seconds = ttl_seconds
        # sqlite3 connections are not safe to share across threads by default.
        # enrich_many runs providers concurrently, so guard the single
        # connection with a lock. Local-file reads are sub-millisecond against
        # 100-700ms of network latency, so this costs nothing measurable.
        self._lock = threading.Lock()
        self._conn: sqlite3.Connection | None = None
        self._disabled = False
        #: Set when the cache had to be switched off mid-run, so the CLI can
        #: tell the user once rather than silently degrading.
        self.degraded_reason: str | None = None

    # -- lifecycle ---------------------------------------------------------

    def _connect(self) -> sqlite3.Connection | None:
        if self._disabled:
            return None
        if self._conn is not None:
            return self._conn

        try:
            self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            # mkdir(mode=) is a no-op on an existing directory, so tighten it
            # unconditionally — same reasoning as the config directory. Skipped
            # where the OS ignores the bits anyway (Windows).
            if PERMISSIONS_ENFORCED:
                self.path.parent.chmod(0o700)

            # A pre-planted symlink here would let a local attacker on a shared
            # host redirect our writes (and our chmod) onto a file of their
            # choosing. Refuse rather than follow it.
            if self.path.is_symlink():
                raise CacheError(
                    f"{self.path} is a symlink; refusing to use it as a cache. "
                    "Remove it and re-run."
                )

            conn = sqlite3.connect(self.path, check_same_thread=False)
            if PERMISSIONS_ENFORCED:
                # The cache records which indicators were investigated, which is
                # sensitive on a shared machine.
                self.path.chmod(0o600)

            self._prepare(conn)
            self._conn = conn
            return conn
        except CacheError:
            raise
        except (sqlite3.Error, OSError) as exc:
            self._disable(f"cache unavailable ({exc})")
            return None

    def _prepare(self, conn: sqlite3.Connection) -> None:
        # Concurrency settings first — they matter before any write is attempted.
        #
        # iocvet is a CLI, so several copies genuinely do run at once: a nightly
        # cron job while an analyst runs an ad-hoc batch, or a CI pipeline with
        # parallel jobs. Under SQLite's default "delete" journal, every writer
        # takes an exclusive lock on the whole database and the losers get
        # "database is locked" — measured at 8 of 12 concurrent processes losing
        # their cache outright. WAL lets readers proceed during a write and
        # shortens the exclusive window enormously.
        conn.execute("PRAGMA journal_mode=WAL")
        # Wait rather than fail instantly when another process holds the write
        # lock. These are millisecond-scale transactions, so a generous timeout
        # costs nothing and removes the remaining contention failures.
        conn.execute("PRAGMA busy_timeout=10000")
        # Safe to relax with WAL: a crash can lose the most recent transactions
        # but cannot corrupt the database. Losing a few cache rows is harmless —
        # they are re-fetched — and this avoids an fsync per write.
        conn.execute("PRAGMA synchronous=NORMAL")

        version = conn.execute("PRAGMA user_version").fetchone()[0]
        if version and version != _SCHEMA_VERSION:
            # Written by a different version of iocvet. Rebuilding is safe —
            # the cache holds nothing that can't be re-fetched — and far better
            # than querying an unknown layout.
            conn.executescript("DROP TABLE IF EXISTS provider_results;")
            version = 0
        conn.executescript(_SCHEMA)
        if version != _SCHEMA_VERSION:
            conn.execute(f"PRAGMA user_version = {_SCHEMA_VERSION}")
        conn.commit()
        # WAL adds -wal and -shm sidecars holding the same investigative data as
        # the main file, so they need the same restrictive permissions.
        self._secure_sidecars()

    def _secure_sidecars(self) -> None:
        """Tighten permissions on the WAL sidecar files if they exist."""
        if not PERMISSIONS_ENFORCED:
            return
        for suffix in ("-wal", "-shm"):
            sidecar = self.path.with_name(self.path.name + suffix)
            try:
                if sidecar.exists():
                    sidecar.chmod(0o600)
            except OSError:
                # Best effort: a permissions failure here must not break a lookup.
                pass

    def _disable(self, reason: str) -> None:
        self._disabled = True
        self.degraded_reason = reason
        if self._conn is not None:
            try:
                self._conn.close()
            except sqlite3.Error:
                pass
            self._conn = None

    def close(self) -> None:
        with self._lock:
            if self._conn is not None:
                try:
                    self._conn.close()
                except sqlite3.Error:
                    pass
                self._conn = None

    # -- reads / writes ----------------------------------------------------

    def get(
        self, ioc_type: IOCType, ioc: str, provider: str
    ) -> ProviderResult | None:
        """Return a cached result, or None on a miss/expiry/any failure."""
        with self._lock:
            conn = self._connect()
            if conn is None:
                return None
            try:
                row = conn.execute(
                    "SELECT payload, cached_at FROM provider_results "
                    "WHERE ioc_type = ? AND ioc = ? AND provider = ?",
                    (ioc_type.value, ioc, provider),
                ).fetchone()
            except sqlite3.Error as exc:
                self._disable(f"cache read failed ({exc})")
                return None

        if row is None:
            return None
        payload, cached_at = row
        age = time.time() - cached_at
        # A negative age means the row is stamped in the future — a clock jump,
        # a restored backup, or a tampered database. Such an entry would never
        # expire under a plain age check, leaving a stale verdict cached
        # permanently. Treat anything from the future as unusable.
        if age < 0 or age > self.ttl_seconds:
            return None
        try:
            # Pydantic ignores unknown keys and fills missing ones from
            # defaults, so an entry written by a slightly different version of
            # the model still loads rather than breaking the run.
            return ProviderResult.model_validate(json.loads(payload))
        except (ValueError, TypeError):
            # A single unreadable row is a miss, not an error.
            return None

    def put(
        self, ioc_type: IOCType, ioc: str, result: ProviderResult
    ) -> None:
        """Store a result. Errors and skips are ignored by design."""
        if not result.ok:
            # Transient failures and configuration-dependent skips must never
            # be cached — see the module docstring.
            return
        with self._lock:
            conn = self._connect()
            if conn is None:
                return
            try:
                conn.execute(
                    "INSERT OR REPLACE INTO provider_results "
                    "(ioc_type, ioc, provider, payload, cached_at) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (
                        ioc_type.value,
                        ioc,
                        result.provider,
                        result.model_dump_json(),
                        time.time(),
                    ),
                )
                conn.commit()
                self._secure_sidecars()
            except sqlite3.Error as exc:
                self._disable(f"cache write failed ({exc})")

    # -- maintenance -------------------------------------------------------

    def stats(self) -> CacheStats:
        """Counts for `iocvet cache stats`. Never raises."""
        with self._lock:
            conn = self._connect()
            if conn is None:
                return {
                    "available": False,
                    "path": str(self.path),
                    "entries": 0,
                    "expired": 0,
                    "size_bytes": 0,
                }
            try:
                total = conn.execute(
                    "SELECT COUNT(*) FROM provider_results"
                ).fetchone()[0]
                cutoff = time.time() - self.ttl_seconds
                expired = conn.execute(
                    "SELECT COUNT(*) FROM provider_results WHERE cached_at < ?",
                    (cutoff,),
                ).fetchone()[0]
            except sqlite3.Error as exc:
                self._disable(f"cache stats failed ({exc})")
                return {
                    "available": False,
                    "path": str(self.path),
                    "entries": 0,
                    "expired": 0,
                    "size_bytes": 0,
                }
        size = self.path.stat().st_size if self.path.exists() else 0
        return {
            "available": True,
            "path": str(self.path),
            "entries": total,
            "expired": expired,
            "size_bytes": size,
        }

    def clear(self) -> int:
        """Delete every entry. Returns how many were removed."""
        with self._lock:
            conn = self._connect()
            if conn is None:
                return 0
            try:
                count = conn.execute(
                    "SELECT COUNT(*) FROM provider_results"
                ).fetchone()[0]
                conn.execute("DELETE FROM provider_results")
                conn.commit()
                conn.execute("VACUUM")
                return int(count)
            except sqlite3.Error as exc:
                self._disable(f"cache clear failed ({exc})")
                return 0

    def purge_expired(self) -> int:
        """Drop unusable entries and enforce the size ceiling.

        Removes three things: entries past their TTL, entries stamped in the
        future (which a plain age check would keep forever), and — once the
        table exceeds MAX_ENTRIES — the oldest rows, so the file cannot grow
        without bound after a very large batch run.
        """
        with self._lock:
            conn = self._connect()
            if conn is None:
                return 0
            try:
                now = time.time()
                cutoff = now - self.ttl_seconds
                cur = conn.execute(
                    "DELETE FROM provider_results WHERE cached_at < ? OR cached_at > ?",
                    (cutoff, now),
                )
                removed = cur.rowcount or 0

                total = conn.execute(
                    "SELECT COUNT(*) FROM provider_results"
                ).fetchone()[0]
                if total > MAX_ENTRIES:
                    overflow = total - MAX_ENTRIES
                    cur = conn.execute(
                        "DELETE FROM provider_results WHERE rowid IN ("
                        "  SELECT rowid FROM provider_results "
                        "  ORDER BY cached_at ASC LIMIT ?"
                        ")",
                        (overflow,),
                    )
                    removed += cur.rowcount or 0

                conn.commit()
                return removed
            except sqlite3.Error as exc:
                self._disable(f"cache purge failed ({exc})")
                return 0
