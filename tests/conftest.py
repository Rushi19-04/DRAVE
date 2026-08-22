import pytest
from freezegun import freeze_time
from fastapi.testclient import TestClient
from sqlmodel import SQLModel, Session, create_engine
from sqlalchemy.pool import StaticPool
from typing import Generator

from saas.backend.api.main import app
from saas.backend.database import get_session

@pytest.fixture(autouse=True)
def freeze_time_fixture():
    """Globally freeze time for all tests to ensure deterministic output."""
    with freeze_time("2025-01-01T00:00:00Z"):
        yield

# Create in-memory SQLite for testing to avoid contaminating Postgres
engine = create_engine(
    "sqlite://", 
    connect_args={"check_same_thread": False},
    poolclass=StaticPool
)

def get_session_override() -> Generator[Session, None, None]:
    with Session(engine) as session:
        yield session

app.dependency_overrides[get_session] = get_session_override

@pytest.fixture(autouse=True)
def setup_db():
    SQLModel.metadata.create_all(engine)
    yield
    SQLModel.metadata.drop_all(engine)

@pytest.fixture
def client():
    return TestClient(app)

@pytest.fixture
def sample_rule():
    return {
        "id": "11111111-1111-1111-1111-111111111111",
        "version": 1,
        "name": "Test Rule",
        "description": "Desc",
        "language": "sigma",
        "platform": "windows",
        "query": "title: Test Rule\nid: 11111111-1111-1111-1111-111111111111\nstatus: test\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    selection:\n        CommandLine|contains: 'mock_pattern'\n    condition: selection\nlevel: high",
        "severity": "high",
        "author": "Author",
        "created_at": "2025-01-01T00:00:00Z",
        "updated_at": "2025-01-01T00:00:00Z"
    }
