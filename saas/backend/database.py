"""Database connection (Step 68)."""

from sqlmodel import SQLModel, create_engine, Session

# Using Docker Postgres as requested
DATABASE_URL = "postgresql://drave:password@localhost:5432/drave_db"

engine = create_engine(DATABASE_URL, echo=False)

def init_db():
    """Create tables."""
    SQLModel.metadata.create_all(engine)

def get_session():
    """Dependency for FastAPI."""
    with Session(engine) as session:
        yield session
