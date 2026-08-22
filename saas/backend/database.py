"""Database connection (Step 68)."""

from sqlmodel import SQLModel, create_engine, Session
from sqlalchemy import event
from sqlalchemy.orm import Session as SASession

from saas.backend.config import settings

# Load securely from environment
DATABASE_URL = settings.database_url

engine = create_engine(DATABASE_URL, echo=False)

@event.listens_for(SASession, "do_orm_execute")
def _add_tenant_filter(orm_execute_state):
    """Automatically append tenant_id where clause to all queries."""
    tenant_id = orm_execute_state.session.info.get("tenant_id")
    
    if tenant_id and (orm_execute_state.is_select or orm_execute_state.is_update or orm_execute_state.is_delete):
        # Apply to all entities in the query that have a tenant_id
        for cd in orm_execute_state.statement.column_descriptions:
            entity = cd.get("entity")
            if entity and hasattr(entity, "tenant_id"):
                orm_execute_state.statement = orm_execute_state.statement.where(
                    entity.tenant_id == tenant_id
                )

def init_db():
    """Create tables."""
    SQLModel.metadata.create_all(engine)

def get_session():
    """Dependency for FastAPI."""
    with Session(engine) as session:
        yield session
