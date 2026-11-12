"""Apply Alembic migrations (and one-time legacy handoff from create_all)."""

from __future__ import annotations

import asyncio
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

from app.config import get_settings

_SERVER_ROOT = Path(__file__).resolve().parents[2]
_ALEMBIC_INI = _SERVER_ROOT / "alembic.ini"
_ALEMBIC_SCRIPT = _SERVER_ROOT / "alembic"

# Additive column repairs for older create_all schemas.
_SCHEMA_REPAIRS = (
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS public_key VARCHAR",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS encrypted_private_key VARCHAR",
    "ALTER TABLE collections ADD COLUMN IF NOT EXISTS parent_uuid VARCHAR(64)",
    "ALTER TABLE collections ALTER COLUMN icon TYPE VARCHAR(255)",
    "ALTER TABLE collections ALTER COLUMN icon SET DEFAULT 'material:folder'",
)


def _alembic_config() -> Config:
    cfg = Config(str(_ALEMBIC_INI))
    cfg.set_main_option("script_location", str(_ALEMBIC_SCRIPT))
    return cfg


async def _db_flags() -> tuple[bool, bool, bool]:
    """Return (has_users, has_alembic_version, has_refresh_tokens)."""
    engine = create_async_engine(get_settings().database_url, pool_pre_ping=True)
    try:
        async with engine.connect() as conn:
            async def _has_table(name: str) -> bool:
                return bool(
                    await conn.scalar(
                        text(
                            "SELECT EXISTS ("
                            "  SELECT 1 FROM information_schema.tables"
                            "  WHERE table_schema = 'public' AND table_name = :name"
                            ")"
                        ),
                        {"name": name},
                    )
                )

            return (
                await _has_table("users"),
                await _has_table("alembic_version"),
                await _has_table("refresh_tokens"),
            )
    finally:
        await engine.dispose()


async def _apply_schema_repairs() -> None:
    engine = create_async_engine(get_settings().database_url, pool_pre_ping=True)
    try:
        async with engine.begin() as conn:
            for stmt in _SCHEMA_REPAIRS:
                await conn.execute(text(stmt))
    finally:
        await engine.dispose()


async def _migrate_legacy_auth_hashes() -> None:
    """Hash reusable auth_hash values in pre-Alembic databases before serving."""
    from app.services.auth_service import hash_auth_hash

    engine = create_async_engine(get_settings().database_url, pool_pre_ping=True)
    try:
        async with engine.begin() as conn:
            rows = (
                await conn.execute(text("SELECT id, auth_hash FROM users"))
            ).fetchall()
            for user_id, stored in rows:
                if not isinstance(stored, str) or stored.startswith("hmac-sha256-v1:"):
                    continue
                await conn.execute(
                    text("UPDATE users SET auth_hash = :verifier WHERE id = :user_id"),
                    {"verifier": hash_auth_hash(stored), "user_id": user_id},
                )
    finally:
        await engine.dispose()


async def _create_missing_tables() -> None:
    """Create any tables defined on models that are still absent (non-destructive)."""
    # Import models so metadata is fully populated.
    import app.models  # noqa: F401
    from app.db.base import Base

    engine = create_async_engine(get_settings().database_url, pool_pre_ping=True)
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
    finally:
        await engine.dispose()


def run_migrations() -> None:
    """Upgrade to head. Repair / stamp legacy create_all databases safely."""
    cfg = _alembic_config()
    has_users, has_version, has_refresh = asyncio.run(_db_flags())

    if has_users and not has_version:
        # Pre-Alembic DB: add missing columns/tables, then record head.
        asyncio.run(_apply_schema_repairs())
        asyncio.run(_create_missing_tables())
        command.stamp(cfg, "head")
        # Legacy create_all databases are stamped rather than replaying Alembic
        # revisions; explicitly apply the auth verifier data migration here.
        asyncio.run(_migrate_legacy_auth_hashes())
        return

    command.upgrade(cfg, "head")

    # Recover from a bad stamp that skipped creating later tables/columns.
    if has_users and has_version and not has_refresh:
        asyncio.run(_apply_schema_repairs())
        asyncio.run(_create_missing_tables())
