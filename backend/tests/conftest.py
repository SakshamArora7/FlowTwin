import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.database import Base, get_db
from backend.app.demo import seed_demo
from backend.app.main import app


@pytest.fixture
def client():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    with factory() as db:
        seed_demo(db)
    def override():
        with factory() as db:
            yield db
    app.dependency_overrides[get_db] = override
    test_client = TestClient(app, raise_server_exceptions=True)
    yield test_client, factory
    test_client.close()
    app.dependency_overrides.clear()
    engine.dispose()
