"""Demo seed: a demo organisation, the "Acme Bank" brand with many official assets, and pre-recorded
investigations replayed from the offline test fixtures (no network needed).

Every seeded finding has source "demo-fixture" (shown as "Demo fixture" in the app), so it can never be mistaken
for a live result.

    python -m scripts.seed_demo

Needs DATABASE_URL, DEMO_EMAIL and DEMO_PASSWORD in .env. Idempotent: does nothing if "Demo Org" already exists.
"""
from __future__ import annotations

import asyncio
from datetime import timedelta
import os
import sys

from sqlalchemy import select

from threatdesk import campaigns, cases
from threatdesk.assets import store
from threatdesk.assets.forms import parse_app_listing, parse_social, parse_website
from threatdesk.brands import BrandContext, new_report_token
from threatdesk.db import create_all, session_scope, utcnow
from threatdesk.intake import analyze_text
from threatdesk.investigator import investigate
from threatdesk.models import Brand, Org, User
from threatdesk.persistence import save_report
from threatdesk.security import hash_password

ORG = "Demo Org"
SOURCE = "demo-fixture"
SITES = ["acmebank.com", "acmebank.in"]
PROFILES = ["https://www.instagram.com/acmebank", "https://www.instagram.com/acmebank.help",
            "https://www.instagram.com/acmebank_in", "https://www.youtube.com/@AcmeBank", "https://t.me/acmebank"]
APPS = [("android", "com.acme.bank"), ("ios", "1234567890")]
FIXTURES = ["https://acmebank-kyc.xyz/login", "https://acme-support-help.online/", "https://acmebank-rewards.xyz/",
            "https://old-bakery.com/"]
MESSAGE = ("Dear customer, your Acme Bank account will be blocked today. Update KYC immediately: call or WhatsApp "
           "+91 98765 43210 and share the OTP you receive.")


def _setup(email: str, password: str) -> tuple[int, int, int] | None:
    with session_scope() as db:
        if db.scalar(select(Org).where(Org.name == ORG)):
            return None
        if db.scalar(select(User).where(User.email == email)):
            raise SystemExit(f"{email} already belongs to another organisation; set a different DEMO_EMAIL.")
        org = Org(name=ORG)
        db.add(org)
        db.flush()
        user = User(org_id=org.id, email=email, password_hash=hash_password(password), role="admin")
        brand = Brand(org_id=org.id, name="Acme Bank", report_token=new_report_token(), keywords=["acme"],
                      official_domains=[], official_handles={}, official_apps={}, scan_interval_hours=0)
        db.add_all([user, brand])
        db.flush()
        for i, site in enumerate(SITES):
            store.add(db, brand, "website", parse_website({"url": site, "kind": "main" if i == 0 else "regional",
                                                           "is_primary": "1" if i == 0 else ""}))
        for link in PROFILES:
            store.add(db, brand, "social", parse_social({"handle": link}))
        for platform, ref in APPS:
            store.add(db, brand, "app", parse_app_listing(platform, ref, {"name": "Acme Mobile Banking",
                                                                           "product": "Acme Mobile Banking"}))
        return org.id, user.id, brand.id


async def _replay(brand: BrandContext) -> list:
    from tests.netfixtures import offline_patches
    reports = []
    with offline_patches() as make_client:
        for url in FIXTURES:
            async with make_client() as client:
                reports.append(await investigate(url, brand=brand, client=client, use_ai=False))
    return reports


def main() -> int:
    email, password = os.getenv("DEMO_EMAIL", "").strip(), os.getenv("DEMO_PASSWORD", "")
    if not email or len(password) < 10:
        print("Set DEMO_EMAIL and DEMO_PASSWORD (10+ characters) in .env first.", file=sys.stderr)
        return 2
    create_all()
    ids = _setup(email, password)
    if ids is None:
        print(f"'{ORG}' already exists; nothing to do.")
        return 0
    org_id, user_id, brand_id = ids
    with session_scope() as db:
        ctx = BrandContext.from_models(db.get(Brand, brand_id))
    reports = asyncio.run(_replay(ctx))
    reports.append(analyze_text(MESSAGE, ctx, None))
    with session_scope() as db:
        user = db.get(User, user_id)
        now = utcnow()
        saved = []
        for r in reports:
            f, _ = save_report(db, org_id, brand_id, r, SOURCE, in_triage=True, user_submitted=r.kind == "other")
            saved.append(f)

        # Staggered relative timestamps for realistic demo triage freshness
        offsets = [
            (timedelta(hours=4), timedelta(minutes=15)),      # phish: first seen 4h ago, last seen 15m ago
            (timedelta(hours=6), timedelta(hours=1)),         # support: first seen 6h ago, last seen 1h ago
            (timedelta(days=1, hours=2), timedelta(hours=2)),  # rewards: first seen 26h ago, last seen 2h ago
            (timedelta(days=3), timedelta(hours=8)),          # bakery: first seen 3d ago, last seen 8h ago
            (timedelta(minutes=45), timedelta(minutes=45)),   # user report: first seen 45m ago, last seen 45m ago
        ]
        for i, f in enumerate(saved):
            if i < len(offsets):
                first_delta, last_delta = offsets[i]
                f.first_seen = now - first_delta
                f.last_seen = now - last_delta

        phish = saved[0]
        ev_inv = cases.change_status(db, phish, user, "investigating", "Demo: credential form and KYC lure on a 5-day-old domain")
        ev_inv.at = now - timedelta(hours=2, minutes=30)
        ev_conf = cases.change_status(db, phish, user, "confirmed", "Demo: impersonates Acme Bank, asks for password and OTP")
        ev_conf.at = now - timedelta(hours=1, minutes=15)
        ev_comm = cases.comment(db, phish, user, "Demo: takedown packet ready to send to the registrar's abuse desk.")
        ev_comm.at = now - timedelta(minutes=30)
        db.commit()
        info = campaigns.rebuild(db, org_id)
    print(f"Seeded '{ORG}' with brand Acme Bank, {len(reports)} demo-fixture findings, "
          f"{info['campaigns']} campaign(s). Log in as {email}.")
    for r in reports:
        print(f"  {r.verdict:18} {r.score:3}  {r.display_name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
