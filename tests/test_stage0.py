import os

import pytest

from threatdesk import config, db
from threatdesk.config import normalize_db_url
from threatdesk.jsonutil import canonical_sha256, jsonable
from threatdesk.models import Evidence, EvidenceIsAppendOnly, Finding, Org
from tests.helpers import make_client


def test_health_reports_db():
    r = make_client().get("/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok", "db": True}


def test_db_url_normalised_and_postgres_only(monkeypatch):
    assert normalize_db_url("postgres://u:p@h/d") == "postgresql+psycopg://u:p@h/d"
    assert normalize_db_url("postgresql://u:p@h/d") == "postgresql+psycopg://u:p@h/d"
    monkeypatch.setenv("THREATDESK_TESTING", "0")
    monkeypatch.setenv("DATABASE_URL", "sqlite:///x.db")
    with pytest.raises(RuntimeError, match="PostgreSQL"):
        config.load_settings()
    monkeypatch.setenv("DATABASE_URL", "postgres://u:p@localhost/d")
    assert config.load_settings().database_url.startswith("postgresql+psycopg://")


def test_prod_requires_secret_key(monkeypatch):
    monkeypatch.setenv("ENV", "prod")
    monkeypatch.delenv("SECRET_KEY", raising=False)
    monkeypatch.setenv("SECRET_KEY", "")
    with pytest.raises(RuntimeError, match="SECRET_KEY"):
        config.load_settings()
    monkeypatch.setenv("SECRET_KEY", "x" * 40)
    s = config.load_settings()
    assert s.is_prod and s.secret_key == "x" * 40
    assert "x" * 40 not in repr(s)


def test_evidence_is_append_only():
    with db.session_scope() as s:
        org = Org(name="O")
        s.add(org)
        s.flush()
        f = Finding(org_id=org.id, source="investigate", kind="website", dedupe_key="host:a.com",
                    scope_key="0:host:a.com", display_name="a.com", url="https://a.com/")
        s.add(f)
        s.flush()
        ev = Evidence(org_id=org.id, finding_id=f.id, kind="page_capture", sha256="0" * 64, content_json={"a": 1})
        s.add(ev)
        s.flush()
        ev_id = ev.id
    with pytest.raises(EvidenceIsAppendOnly):
        with db.session_scope() as s:
            row = s.get(Evidence, ev_id)
            row.kind = "changed"
            s.flush()
    with pytest.raises(EvidenceIsAppendOnly):
        with db.session_scope() as s:
            s.delete(s.get(Evidence, ev_id))
            s.flush()


def test_numpy_values_hash_like_plain_json():
    np = pytest.importorskip("numpy")
    content = {"distance": np.int64(4), "items": {"a"}, "t": (1, 2)}
    plain = jsonable(content)
    assert plain == {"distance": 4, "items": ["a"], "t": [1, 2]}
    assert canonical_sha256(content) == canonical_sha256(plain)
    assert os.environ["THREATDESK_TESTING"] == "1"
