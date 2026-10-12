"""Write schema.sql (PostgreSQL DDL) from the models. Reference only: the app creates its tables at startup.

    python -m scripts.export_schema
"""
from __future__ import annotations

from pathlib import Path

from sqlalchemy.dialects import postgresql
from sqlalchemy.schema import CreateIndex, CreateTable

import threatdesk.models  # noqa: F401  (registers tables)
from threatdesk.db import Base

OUT = Path(__file__).resolve().parent.parent / "schema.sql"


def main() -> None:
    dialect = postgresql.dialect()
    parts = ["-- Generated from threatdesk/models by scripts/export_schema.py. Tables are also created at startup.\n"]
    for table in Base.metadata.sorted_tables:
        parts.append(str(CreateTable(table).compile(dialect=dialect)).strip() + ";\n")
        for idx in sorted(table.indexes, key=lambda i: i.name or ""):
            parts.append(str(CreateIndex(idx).compile(dialect=dialect)).strip() + ";\n")
    OUT.write_text("\n".join(parts), encoding="utf-8")
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
