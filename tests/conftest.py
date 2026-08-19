import pytest
from freezegun import freeze_time

@pytest.fixture(autouse=True)
def freeze_time_fixture():
    """Globally freeze time for all tests to ensure deterministic output."""
    with freeze_time("2025-01-01T00:00:00Z"):
        yield
