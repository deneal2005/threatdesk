from threatdesk import db
from threatdesk.models import Evidence, Finding, Signal
from threatdesk.takedown import build_packet, packet_text
from tests.brandhelp import org_of
from tests.helpers import csrf, make_client, signup


def _website_finding(oid: int, with_rdap: bool = True) -> int:
    with db.session_scope() as s:
        f = Finding(org_id=oid, source="investigate", kind="website", dedupe_key="host:evil.example",
                    scope_key="0:host:evil.example", display_name="evil.example", url="https://evil.example/login",
                    score=70, severity="High", verdict="High risk", in_triage=True)
        s.add(f)
        s.flush()
        s.add(Signal(org_id=oid, finding_id=f.id, code="domain_has_brand", points=20, evidence="evil.example has it"))
        if with_rdap:
            s.add(Evidence(org_id=oid, finding_id=f.id, kind="rdap_domain", sha256="a" * 64, content_json={
                "parsed": {"domain": "evil.example", "registrar": "Cheap Names", "abuse_email": "abuse@cheap.example",
                           "registered": "2026-10-01T00:00:00Z", "redacted": True}}))
        return f.id


def test_contacts_only_from_rdap_and_nothing_invented():
    c = make_client()
    signup(c)
    oid = org_of("a@example.com")
    fid = _website_finding(oid)
    with db.session_scope() as s:
        p = build_packet(s, s.get(Finding, fid), contacts={})
    reg, host = p["recipients"]
    assert reg["email"] == "abuse@cheap.example" and not reg["missing"]
    assert host["missing"] and host["email"] is None                     # no IP RDAP captured: nothing made up
    text = packet_text(p)
    assert "abuse@cheap.example" in text and "NO CONTACT AVAILABLE" in text and "evil[.]example" in text
    for n in range(1, 11):
        assert f"\n{n}. " in "\n" + text


def test_platform_section_from_contacts_or_missing():
    c = make_client()
    signup(c)
    oid = org_of("a@example.com")
    with db.session_scope() as s:
        f = Finding(org_id=oid, source="investigate", kind="android_app", dedupe_key="android:com.fake.app",
                    scope_key="0:android:com.fake.app", display_name="Fake (com.fake.app)", url="https://play/x")
        s.add(f)
        s.flush()
        p1 = build_packet(s, f, contacts={})
        p2 = build_packet(s, f, contacts={"play": {"report_url": "https://support.google.com/report", "email": ""}})
    assert p1["recipients"][0]["missing"] and p1["recipients"][0]["title"].startswith("Google Play")
    assert not p2["recipients"][0]["missing"]


def test_routes_and_sent_log():
    c = make_client()
    signup(c)
    fid = _website_finding(org_of("a@example.com"))
    page = c.get(f"/findings/{fid}/takedown").text
    assert "Send to" in page and "ThreatDesk never invents contacts" in page
    r = c.get(f"/findings/{fid}/takedown.txt")
    assert r.status_code == 200 and "attachment" in r.headers["content-disposition"]
    tok = csrf(c, f"/findings/{fid}/takedown")
    r = c.post(f"/findings/{fid}/takedown/sent", data={"recipient": "abuse@cheap.example", "note": "sent form",
                                                       "csrf_token": tok})
    assert r.status_code == 303
    assert "takedown request sent to abuse@cheap[.]example: sent form" in c.get(f"/findings/{fid}").text
    assert c.post(f"/findings/{fid}/screenshot", data={"csrf_token": tok}).status_code == 400
