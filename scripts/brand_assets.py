"""Brand asset tables: create and migrate (up), report (status), or fold back into the JSON lists and drop (down).

    python -m scripts.brand_assets up | status | down
"""
from __future__ import annotations

import sys

from sqlalchemy import inspect, select

from threatdesk.assets import store
from threatdesk.db import create_all, get_engine, session_scope
from threatdesk.models import Brand, BrandApp, BrandSocialAccount, BrandWebsite

TABLES = (BrandWebsite, BrandSocialAccount, BrandApp)


def main(argv: list[str]) -> int:
    cmd = argv[0] if argv else "status"
    if cmd == "up":
        create_all()
        with session_scope() as s:
            print(f"migrated {store.migrate_all(s)} asset rows")
    elif cmd == "status":
        names = set(inspect(get_engine()).get_table_names())
        for m in TABLES:
            if m.__tablename__ in names:
                with session_scope() as s:
                    print(f"{m.__tablename__}: {len(s.scalars(select(m.id)).all())} rows")
            else:
                print(f"{m.__tablename__}: missing")
    elif cmd == "down":
        with session_scope() as s:
            for b in s.scalars(select(Brand)).all():
                store.sync_index(s, b)               # the JSON lists keep working without the tables
        for m in reversed(TABLES):
            m.__table__.drop(get_engine(), checkfirst=True)
        print("asset tables dropped; brands keep their official lists")
    else:
        print(__doc__)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
