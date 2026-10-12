import csv
import io
import re

from sqlalchemy import select

from threatdesk import db
from threatdesk.models import Finding, Job
from tests.brandhelp import make_brand, org_of
from tests.helpers import make_client, post, signup


def _finding(oid: int, name: str, brand_id=None, **kw) -> int:
    with db.session_scope() as s:
        f = Finding(org_id=oid, brand_id=brand_id, source="discovery:domains", kind="website",
                    dedupe_key=f"host:{name}", scope_key=f"{brand_id or 0}:host:{name}", display_name=name,
                    url=f"https://{name}/x", score=80, severity="High", verdict="High risk", in_triage=True, **kw)
        s.add(f)
        s.flush()
        return f.id


def _key(c) -> str:
    r = post(c, "/settings/api-keys", {"label": "SIEM"})
    assert r.status_code == 200 and "shown once" in r.text
    return re.search(r"<code>(td_[^<]+)</code>", r.text).group(1)


def test_api_auth_scoping_investigate_and_revoke():
    a, b = make_client(), make_client()
    signup(a, "a@example.com", "A")
    signup(b, "b@example.com", "B")
    mine = _finding(org_of("a@example.com"), "evil.example")
    theirs = _finding(org_of("b@example.com"), "other.example")
    key = _key(a)
    h = {"Authorization": f"Bearer {key}"}
    assert a.get("/api/v1/findings").status_code == 401                     # cookies are ignored
    r = a.get("/api/v1/findings", headers=h)
    assert r.status_code == 200 and [f["id"] for f in r.json()["findings"]] == [mine]
    assert r.json()["findings"][0]["url_defanged"] == "hxxps://evil[.]example/x"
    assert a.get(f"/api/v1/findings/{theirs}", headers=h).status_code == 404
    r = a.post("/api/v1/investigate", json={"url": "hxxps://new-evil[.]example"}, headers=h)
    assert r.status_code == 202 and r.json()["poll"].startswith("/api/v1/jobs/")
    job = a.get(r.json()["poll"], headers=h).json()
    assert job["status"] == "queued" and job["type"] == "investigate"
    with db.session_scope() as s:
        assert s.get(Job, job["job_id"]).payload["source"] == "api"
    assert a.post("/api/v1/investigate", json={"url": "not a url"}, headers=h).status_code == 400
    key_id = re.search(r'/settings/api-keys/(\d+)/revoke', a.get("/settings").text).group(1)
    post(a, f"/settings/api-keys/{key_id}/revoke")
    assert a.get("/api/v1/findings", headers=h).status_code == 401


def test_api_lists_brand_assets_scoped():
    c = make_client()
    signup(c)
    bid = make_brand(org_of("a@example.com"))
    h = {"Authorization": f"Bearer {_key(c)}"}
    c.get(f"/brands/{bid}")                                                   # migrates the legacy lists
    r = c.get(f"/api/v1/brands/{bid}/assets", headers=h).json()
    assert [w["domain"] for w in r["websites"]] == ["acmebank.com"] and r["apps"][0]["store_id"] == "com.acme.bank"
    assert c.get("/api/v1/brands", headers=h).json()["brands"][0]["assets"] == {"website": 1, "social": 2, "app": 1}
    assert c.get("/api/v1/brands/9999/assets", headers=h).status_code == 404


def test_csv_defanged_formula_safe_and_scoped():
    c = make_client()
    signup(c)
    oid = org_of("a@example.com")
    bid = make_brand(oid)
    _finding(oid, "evil.example", bid)
    _finding(oid, "=cmd|calc.example")
    _finding(oid, "other.example")
    rows = list(csv.reader(io.StringIO(c.get("/reports/findings.csv").text)))
    assert rows[0][:4] == ["id", "brand_id", "kind", "display_name"]
    names = {r[3] for r in rows[1:]}
    assert "evil[.]example" in names and "'=cmd|calc[.]example" in names
    only = list(csv.reader(io.StringIO(c.get(f"/reports/findings.csv?brand_id={bid}").text)))
    assert len(only) == 2
    assert "Brand protection summary" in c.get(f"/reports/brand/{bid}").text
    signup(other := make_client(), "z@example.com", "Z")
    assert other.get(f"/reports/brand/{bid}").status_code == 404
    with db.session_scope() as s:
        assert s.scalar(select(Finding.id).where(Finding.org_id == org_of("z@example.com"))) is None
