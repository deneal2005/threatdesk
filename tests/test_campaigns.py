from sqlalchemy import select

from threatdesk import campaigns, db
from threatdesk.models import Campaign, CampaignFinding, CheckResult, Finding, Indicator, Org


def _org() -> int:
    with db.session_scope() as s:
        o = Org(name="O")
        s.add(o)
        s.flush()
        return o.id


def _f(oid: int, name: str, indicators=(), registrar=None, registered=None, status="new") -> int:
    with db.session_scope() as s:
        f = Finding(org_id=oid, source="x", kind="website", dedupe_key=f"host:{name}", scope_key=f"0:host:{name}",
                    display_name=name, url=f"https://{name}/", status=status, in_triage=True)
        s.add(f)
        s.flush()
        for t, v in indicators:
            s.add(Indicator(org_id=oid, finding_id=f.id, type=t, value=v))
        if registrar:
            s.add(CheckResult(org_id=oid, finding_id=f.id, check="rdap_domain", status="ran",
                              detail={"registrar": registrar, "registered": registered}))
        return f.id


def test_only_real_shared_values_link():
    oid = _org()
    a = _f(oid, "a.example", [("phone", "9876543210"), ("asn", "13335"), ("ip", "3.33.130.190")])
    b = _f(oid, "b.example", [("phone", "9876543210"), ("asn", "13335")])
    c = _f(oid, "c.example", [("asn", "13335"), ("ip", "3.33.130.190"), ("domain", "googleapis.com")])
    d = _f(oid, "d.example", [("domain", "googleapis.com")])
    with db.session_scope() as s:
        info = campaigns.rebuild(s, oid)
    assert info["campaigns"] == 1 and info["findings"] == 2
    assert {x["value"] for x in info["skipped"]} >= {"13335", "3.33.130.190", "googleapis.com"}
    with db.session_scope() as s:
        camp = s.scalar(select(Campaign))
        members = {cf.finding_id for cf in s.scalars(select(CampaignFinding))}
    assert members == {a, b} and camp.shared[0] == {"type": "phone", "value": "9876543210", "findings": [a, b]}
    assert c not in members and d not in members


def test_registrar_window_and_false_positives_ignored():
    oid = _org()
    a = _f(oid, "a.example", registrar="Cheap Names", registered="2026-10-01T00:00:00Z")
    b = _f(oid, "b.example", registrar="cheap names", registered="2026-10-03T00:00:00Z")
    _f(oid, "c.example", registrar="Cheap Names", registered="2026-12-01T00:00:00Z")
    _f(oid, "d.example", [("upi", "x@ybl")], status="false_positive")
    _f(oid, "e.example", [("upi", "x@ybl")])
    with db.session_scope() as s:
        info = campaigns.rebuild(s, oid)
        members = {cf.finding_id for cf in s.scalars(select(CampaignFinding))}
    assert info["campaigns"] == 1 and members == {a, b}


def test_too_common_values_and_zero_campaigns_and_rebuild_replaces():
    oid = _org()
    for i in range(campaigns.MAX_SHARED + 1):
        _f(oid, f"n{i}.example", [("email", "noreply@shared.example")])
    with db.session_scope() as s:
        info = campaigns.rebuild(s, oid)
        assert info["campaigns"] == 0 and "too common" in info["skipped"][0]["reason"]
        assert campaigns.rebuild(s, oid)["campaigns"] == 0
        assert s.scalar(select(Campaign)) is None
    assert campaigns.is_parking_ip("91.195.240.12") and not campaigns.is_parking_ip("8.8.8.8")


def test_campaigns_isolated_between_orgs():
    a, b = _org(), _org()
    _f(a, "a1.example", [("phone", "9000000001")])
    _f(b, "b1.example", [("phone", "9000000001")])
    with db.session_scope() as s:
        assert campaigns.rebuild(s, a)["campaigns"] == 0          # same phone in another org never links
