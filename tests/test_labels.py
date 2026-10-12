"""Analyst decisions as labels: export, replay with today's rules, noisy-rule report, and the CLI."""
import json

from threatdesk import labels
from threatdesk.db import session_scope
from threatdesk.models import Evidence, Finding, Org, Signal
from scripts import label_report
from tests.test_profile_model import THROWAWAY


def _finding(db, org, n, status, kind, codes, verdict="Medium risk", raw=None):
    f = Finding(org_id=org.id, source="test", kind=kind, dedupe_key=f"k{n}", scope_key=f"0:k{n}",
                display_name=f"asset {n}", url=f"https://example.com/{n}", status=status, verdict=verdict,
                checks_ran=5, score=50)
    db.add(f)
    db.flush()
    from threatdesk.scoring import RULES
    for c in codes:
        db.add(Signal(org_id=org.id, finding_id=f.id, code=c, points=RULES[c][0], evidence=""))
    if raw:
        db.add(Evidence(org_id=org.id, finding_id=f.id, kind="social_profile", sha256="x" * 64,
                        content_json={"platform": "instagram", "profile": {}, "raw": raw}))
    return f


def _seed():
    with session_scope() as db:
        a, b = Org(name="A"), Org(name="B")
        db.add_all([a, b])
        db.flush()
        _finding(db, a, 1, "confirmed", "website", ["domain_lookalike", "asks_credentials", "domain_age_lt_30d"])
        _finding(db, a, 2, "taken_down", "social_profile", ["handle_similar", "contact_bait", "claims_official"],
                 raw=THROWAWAY)
        for i in range(3, 9):          # six false positives that only carry "urgency" + a name match
            _finding(db, a, i, "false_positive", "website", ["urgency", "domain_has_brand", "missing_policy_pages",
                                                             "registrant_redacted"])
        _finding(db, a, 9, "new", "website", ["urgency"])                          # undecided: left out
        _finding(db, b, 10, "confirmed", "website", ["scam_list_hit"], verdict="High risk")
        return a.id, b.id


def test_export_labels_and_scopes_by_org():
    a, b = _seed()
    with session_scope() as db:
        rows = labels.export(db, a)
        everyone = labels.export(db, None)
    assert len(rows) == 8 and len(everyone) == 9
    assert {r["label"] for r in rows} == {"scam", "legit"}
    assert all("url" not in r and "display_name" not in r for r in rows)          # no identifying data exported
    prof = next(r for r in rows if r["kind"] == "social_profile")["profile_features"]
    assert prof and prof["log_followers"] > 0


def test_report_measures_rules_and_flags_noisy_ones():
    a, _ = _seed()
    with session_scope() as db:
        rep = labels.report(labels.export(db, a))
    assert rep["scam"] == 2 and rep["legit"] == 6
    assert rep["stored_verdicts"]["fp"] == 6 and rep["stored_verdicts"]["precision"] == 0.25
    assert "urgency" in rep["noisy_rules"] and rep["rules"]["urgency"]["on_legit"] == 6
    assert "asks_credentials" not in rep["noisy_rules"]
    assert rep["current_rules"]["n"] == 8


def test_replay_uses_current_weights():
    row = {"verdict": "Medium risk", "kind": "website", "checks_ran": 5, "signals": ["scam_list_hit", "urgency",
                                                                                      "retired_rule_code"]}
    assert labels.replay(row) == "Medium risk"                 # 40 + 10; unknown codes are ignored
    assert labels.replay({**row, "verdict": "Official/whitelisted asset"}) == "Official/whitelisted asset"


def test_cli_writes_jsonl_and_requires_scope(tmp_path, capsys):
    a, _ = _seed()
    out = tmp_path / "labels.jsonl"
    assert label_report.main(["--org", str(a), "--out", str(out)]) == 0
    lines = [json.loads(x) for x in out.read_text(encoding="utf-8").splitlines()]
    assert len(lines) == 8
    assert "rules that fire mostly on false positives" in capsys.readouterr().out
    try:
        label_report.main(["--out", str(out)])
        raise AssertionError("expected argparse to refuse a run without --org/--all-orgs")
    except SystemExit as e:
        assert e.code == 2
