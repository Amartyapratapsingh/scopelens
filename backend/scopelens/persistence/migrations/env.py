"""Alembic environment.

The database URL comes from ``scopelens.config`` rather than ``alembic.ini`` so the
connection string exists in exactly one place and no credential is written into a
tracked file (Build Plan §0.7).
"""

from __future__ import annotations

from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

from scopelens.config import get_settings

# Import models so that Base.metadata is fully populated for autogenerate.
from scopelens.persistence import models  # noqa: F401
from scopelens.persistence.base import Base

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata

_settings = get_settings()

# An explicitly supplied URL wins — the test suite points migrations at its own
# database this way. Otherwise fall back to application settings, which is the path
# `scopelens migrate` and the container entrypoint take. alembic.ini deliberately
# leaves sqlalchemy.url empty so the connection string lives in exactly one place.
_configured_url = config.get_main_option("sqlalchemy.url") or ""
_database_url = _configured_url or _settings.database_url
config.set_main_option("sqlalchemy.url", _database_url)


def run_migrations_offline() -> None:
    context.configure(
        url=_database_url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
