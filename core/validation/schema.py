"""Schema loading and validation — Step 15 of the Build Blueprint.

Loads JSON schema definitions for telemetry sources and extracts available fields.
"""

import json
from pathlib import Path


class SchemaProvider:
    """Loads and provides field definitions from JSON schemas."""

    def __init__(self, schemas_dir: str = "schemas/telemetry"):
        self.schemas_dir = Path(schemas_dir)

    def get_schema_fields(self, logsource_id: str) -> set[str]:
        """Return the set of all available fields for a log source.

        If the schema does not exist, returns an empty set.
        """
        schema_path = self.schemas_dir / f"{logsource_id}.json"

        if not schema_path.exists():
            # In a real system we might raise, but for MVP returning empty
            # means "we don't know the schema, assume 0% compatibility".
            return set()

        try:
            with open(schema_path, "r", encoding="utf-8") as f:
                schema_def = json.load(f)
        except Exception:
            return set()

        # Extract fields from the 'properties' block of the JSON schema
        properties = schema_def.get("properties", {})
        return set(properties.keys())

    def schema_exists(self, logsource_id: str) -> bool:
        """Check if a schema exists for this log source."""
        return (self.schemas_dir / f"{logsource_id}.json").exists()
