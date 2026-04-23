import asyncio
import sys
import os
from logging.config import fileConfig
from sqlalchemy.ext.asyncio import create_async_engine
from alembic import context

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.database import Base
from app.models import User  # noqa: F401 — registers model

config = context.config

db_url = os.getenv("DATABASE_URL")
if db_url:
    config.set_main_option("sqlalchemy.url", db_url)

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def run_migrations_offline():
    context.configure(url=config.get_main_option("sqlalchemy.url"), target_metadata=target_metadata, literal_binds=True)
    with context.begin_transaction():
        context.run_migrations()


async def run_migrations_online():
    engine = create_async_engine(config.get_main_option("sqlalchemy.url"))
    async with engine.begin() as conn:
        await conn.run_sync(lambda sync_conn: context.configure(connection=sync_conn, target_metadata=target_metadata))
        await conn.run_sync(lambda _: context.run_migrations())
    await engine.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    asyncio.run(run_migrations_online())
