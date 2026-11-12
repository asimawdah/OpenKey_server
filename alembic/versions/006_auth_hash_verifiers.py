"""Replace reusable plaintext auth_hash values with keyed one-way verifiers.

Revision ID: 006_auth_hash_verifiers
Revises: 005_collection_icon_color

The migration is intentionally data-only: API request/response contracts and
client-side vault encryption remain unchanged.
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

from app.config import get_settings

revision: str = "006_auth_hash_verifiers"
down_revision: Union[str, Sequence[str], None] = "005_collection_icon_color"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_PREFIX = "hmac-sha256-v1:"


def _pepper_key() -> bytes:
    settings = get_settings()
    if settings.auth_hash_pepper:
        return settings.auth_hash_pepper.encode("utf-8")
    return hmac.new(
        settings.jwt_secret.encode("utf-8"),
        b"OpenKey/auth-hash-pepper/v1",
        hashlib.sha256,
    ).digest()


def _verifier(value: str, key: bytes) -> str:
    normalized = value.strip().rstrip("=")
    digest = hmac.new(key, normalized.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{_PREFIX}{digest}"


def upgrade() -> None:
    bind = op.get_bind()
    key = _pepper_key()
    rows = bind.execute(
        sa.text("SELECT id, auth_hash FROM users")
    ).fetchall()

    for user_id, stored in rows:
        if not isinstance(stored, str) or stored.startswith(_PREFIX):
            continue
        bind.execute(
            sa.text("UPDATE users SET auth_hash = :verifier WHERE id = :user_id"),
            {"verifier": _verifier(stored, key), "user_id": user_id},
        )


def downgrade() -> None:
    raise RuntimeError(
        "006_auth_hash_verifiers is irreversible: original auth_hash values "
        "cannot be recovered from keyed one-way verifiers. Restore a pre-migration "
        "database backup only if a rollback is absolutely required."
    )
