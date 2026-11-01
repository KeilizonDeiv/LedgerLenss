from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine


def create_engine_and_sessionmaker(url: str) -> tuple[AsyncEngine, async_sessionmaker[AsyncSession]]:
    engine = create_async_engine(url, pool_pre_ping=True)
    # expire_on_commit=False: objects stay readable after commit (needed to return them from routes).
    return engine, async_sessionmaker(engine, expire_on_commit=False)
