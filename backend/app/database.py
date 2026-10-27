import os
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker


class Base(DeclarativeBase):
    pass


DEFAULT_DB = Path(__file__).resolve().parents[1] / "flowtwin.db"
DATABASE_URL = os.getenv("FLOWTWIN_DATABASE_URL", f"sqlite:///{DEFAULT_DB.as_posix()}")
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine)


def get_db():
    with SessionLocal() as session:
        yield session
