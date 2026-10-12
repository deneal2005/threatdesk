from sqlalchemy import select

from scripts import seed_demo
from threatdesk import config, db
from threatdesk.models import Campaign, Finding, User


def test_seed_is_labelled_offline_and_idempotent(monkeypatch, capsys):
    config.override(scam_lists=False)
    monkeypatch.setenv("DEMO_EMAIL", "demo@example.com")
    monkeypatch.setenv("DEMO_PASSWORD", "demo password 123")
    assert seed_demo.main() == 0
    with db.session_scope() as s:
        rows = s.scalars(select(Finding)).all()
        assert len(rows) == 5 and {f.source for f in rows} == {"demo-fixture"}
        by_name = {f.display_name: f for f in rows}
        assert by_name["acmebank-kyc.xyz"].verdict == "High risk" and by_name["acmebank-kyc.xyz"].status == "confirmed"
        assert by_name["old-bakery.com"].verdict == "No strong signals"
        assert s.scalar(select(Campaign)) is not None                  # shared phone/UPI link the fake pages
        assert s.scalar(select(User).where(User.email == "demo@example.com")).role == "admin"
    assert seed_demo.main() == 0 and "already exists" in capsys.readouterr().out
    monkeypatch.setenv("DEMO_PASSWORD", "short")
    assert seed_demo.main() == 2
