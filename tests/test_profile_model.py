"""Fake-profile model (plain-Python inference) and the credential-form rules adapted from LegitURL's ideas."""
import json

import httpx
import pytest

from threatdesk import config, profile_model as pm
from threatdesk.brands import BrandContext
from threatdesk.checks import apify
from threatdesk.checks.base import Ctx
from threatdesk.checks.generic import form_signals, page_signals
from threatdesk.linkdetect import detect
from threatdesk.pageparse import parse
from threatdesk.scoring import Scorecard, assess

ACME = BrandContext(name="Acme Bank", official_domains=["acmebank.com"], keywords=["acme"],
                    official_handles={"instagram": ["acmebank"]})
THROWAWAY = {"username": "acmebank_help8812", "fullName": "Acme Bank Help", "biography": "", "postsCount": 0,
             "followersCount": 3, "followsCount": 900, "profilePicUrl": "", "private": False}
FAN_PAGE = {"username": "acmebank_fans", "fullName": "Acme Bank Fans", "biography": "Unofficial fan page, news",
            "postsCount": 340, "followersCount": 5200, "followsCount": 300, "profilePicUrl": "https://cdn/p.jpg",
            "externalUrl": "https://fans.example", "private": False}


def test_model_file_loads_and_is_data_only():
    m = pm.load()
    assert m is not None and m["features"] == list(pm.FEATURES)
    assert m["metrics"]["held_out"]["precision"] >= 0.9          # the shipped model met the precision target
    assert pm.load.__wrapped__("does-not-exist.json") is None


def test_predictions_and_drivers():
    fake = pm.predict(pm.instagram_features(THROWAWAY))
    real = pm.predict(pm.instagram_features(FAN_PAGE))
    assert fake["fake"] and fake["probability"] > 0.9 and "few followers" in fake["drivers"]
    assert not real["fake"] and real["probability"] < 0.2


def test_features_need_every_field():
    assert pm.instagram_features({**THROWAWAY, "followsCount": None}) is None
    assert pm.instagram_features({k: v for k, v in THROWAWAY.items() if k != "profilePicUrl"}) is None
    assert pm.instagram_features("not a dict") is None
    assert pm.predict(None) is None


def test_matches_training_csv_encoding():
    row = {"profile pic": "0", "nums/length username": "0.33", "fullname words": "1", "nums/length fullname": "0",
           "name==username": "0", "description length": "0", "external URL": "0", "private": "0", "#posts": "0",
           "#followers": "3", "#follows": "900"}
    assert pm.predict(pm.dataset_features(row))["fake"]


def _ctx(item: dict) -> Ctx:
    def handler(req):
        return httpx.Response(201, json=[item])
    return Ctx(client=httpx.AsyncClient(transport=httpx.MockTransport(handler)), link=detect(
        f"https://www.instagram.com/{item['username']}/"), brand=ACME, settings=config.get_settings())


async def test_signal_on_throwaway_lookalike_only():
    config.override(apify_token="t")
    apify._cache.clear()
    ctx = _ctx(THROWAWAY)
    out = await apify.check_apify_profile(ctx)
    assert out.detail["fake_profile_model"]["fake"] and ctx.card.has("profile_model_fake")
    apify._cache.clear()
    ctx = _ctx(FAN_PAGE)
    out = await apify.check_apify_profile(ctx)
    assert not out.detail["fake_profile_model"]["fake"] and not ctx.card.has("profile_model_fake")


async def test_signal_off_by_setting_and_skipped_for_unrelated_accounts():
    config.override(apify_token="t", profile_model=False)
    apify._cache.clear()
    ctx = _ctx(THROWAWAY)
    out = await apify.check_apify_profile(ctx)
    assert "fake_profile_model" not in out.detail and not ctx.card.has("profile_model_fake")
    config.override(apify_token="t", profile_model=True)
    apify._cache.clear()
    ctx = _ctx({**THROWAWAY, "username": "gardening_daily8812", "fullName": "Garden tips"})
    out = await apify.check_apify_profile(ctx)
    assert "fake_profile_model" not in out.detail


def test_model_signal_never_lifts_a_name_only_match():
    c = Scorecard()
    c.add("handle_similar"), c.add("name_similar"), c.add("profile_model_fake"), c.add("low_followers")
    a = assess(c.signals, "social_profile")
    assert a.capped and a.score == 35


def _forms(html: str, url: str = "https://acme-login.xyz/signin") -> list:
    p = parse(html, url)
    return {"final_url": url, "forms": p["forms"], "title": "Sign in", "text": "Sign in", "status": 200}


PW = '<input type="password" name="pass">'


@pytest.mark.parametrize("html,url,codes", [
    (f'<form action="https://collector.top/save.php" method="post">{PW}</form>', None, {"credential_form_offsite"}),
    (f'<form action="mailto:drop@mail.ru">{PW}</form>', None, {"credential_form_offsite"}),
    (f'<form action="/login" method="post">{PW}</form>', "http://acme-login.xyz/", {"credential_form_insecure"}),
    (f'<form action="http://collector.top/s">{PW}</form>', None, {"credential_form_offsite", "credential_form_insecure"}),
])
def test_credential_form_rules_fire(html, url, codes):
    c = Scorecard()
    form_signals(c, _forms(html, url or "https://acme-login.xyz/signin"), ACME)
    assert {s.code for s in c.signals} == codes


@pytest.mark.parametrize("html", [
    f'<form action="/login" method="post">{PW}</form>',                                    # same site
    f'<form action="https://auth.acme-login.xyz/s">{PW}</form>',                           # own subdomain
    f'<form action="https://acmebank.com/login">{PW}</form>',                              # brand's official site
    f'<form action="https://dev-123.okta.com/login">{PW}</form>',                          # single sign-on provider
    '<form action="https://secure.ccavenue.com/pay"><input name="card_number" placeholder="Card number"></form>',
    '<form action="https://other.example/search"><input name="q"></form>',                 # nothing secret
])
def test_credential_form_rules_quiet(html):
    c = Scorecard()
    form_signals(c, _forms(html), ACME)
    assert not c.signals


def test_official_hosts_skip_form_rules():
    c = Scorecard()
    page = _forms(f'<form action="https://collector.top/x">{PW}</form>', "https://acmebank.com/login")
    page_signals(c, {**page, "final_host": "acmebank.com"}, "acmebank.com", ACME, parked=False)
    assert not c.has("credential_form_offsite")


def test_shipped_model_json_is_plain_json():
    raw = pm.MODEL_PATH.read_text(encoding="utf-8")
    assert json.loads(raw)["training"]["dataset_sha256"]


def _csv(path):
    import random
    rnd = random.Random(1)
    head = ("profile pic,nums/length username,fullname words,nums/length fullname,name==username,description length,"
            "external URL,private,#posts,#followers,#follows,fake")
    rows = [head]
    for i in range(160):
        fake = i % 2
        rows.append(",".join(str(v) for v in (
            0 if fake else 1, round(rnd.uniform(0.2, 0.6) if fake else rnd.uniform(0, 0.1), 2), rnd.randint(0, 3), 0,
            0, rnd.randint(0, 10) if fake else rnd.randint(20, 150), 0 if fake else rnd.randint(0, 1), 0,
            rnd.randint(0, 3) if fake else rnd.randint(20, 900), rnd.randint(0, 40) if fake else rnd.randint(300, 9000),
            rnd.randint(300, 2000) if fake else rnd.randint(50, 600), fake)))
    path.write_text("\n".join(rows) + "\n", encoding="utf-8")
    return path


def test_training_writes_model_and_refuses_a_worse_one(tmp_path):
    pytest.importorskip("sklearn")
    from scripts import train_profile_model as tr
    out = tmp_path / "model.json"
    assert tr.main([str(_csv(tmp_path / "good.csv")), "--out", str(out)]) == 0
    good = out.read_text(encoding="utf-8")
    assert pm.load.__wrapped__(str(out))["metrics"]["held_out"]["f1"] > 0.9
    # 400 mislabeled "analyst" rows: healthy-looking profiles marked scam. Judged on the untouched held-out rows,
    # the poisoned model is worse, so it is refused and the current model stays.
    real = pm.instagram_features(FAN_PAGE)
    bad = tmp_path / "labels.jsonl"
    bad.write_text("".join(json.dumps({"label": "scam", "profile_features": real}) + "\n" for _ in range(400)),
                   encoding="utf-8")
    assert tr.main([str(tmp_path / "good.csv"), "--extra", str(bad), "--out", str(out)]) == 1
    assert out.read_text(encoding="utf-8") == good
    ok = tmp_path / "ok.jsonl"
    ok.write_text(json.dumps({"label": "scam", "profile_features": pm.instagram_features(THROWAWAY)}) + "\n",
                  encoding="utf-8")
    assert tr.main([str(tmp_path / "good.csv"), "--extra", str(ok), "--out", str(out)]) == 0
    assert pm.load.__wrapped__(str(out))["training"]["analyst_rows"] == 1
