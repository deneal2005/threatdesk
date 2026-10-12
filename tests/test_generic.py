import pytest

from threatdesk.brands import BrandContext
from threatdesk.checks.generic import free_hosting_suffix, host_signals, is_restricted, known_official, page_signals
from threatdesk.scoring import Scorecard

NO_BRAND = BrandContext()


def codes(host: str, brand: BrandContext = NO_BRAND) -> set[str]:
    c = Scorecard()
    host_signals(c, host, brand)
    return {s.code for s in c.signals}


@pytest.mark.parametrize("host,expected", [
    ("paypal-login.xyz", {"known_brand_unofficial", "phishing_words_in_domain"}),
    ("paypa1-secure.com", {"known_brand_unofficial", "phishing_words_in_domain"}),       # confusable 1 -> l
    ("rnetamask-wallet.io", {"known_brand_unofficial", "phishing_words_in_domain"}),     # rn -> m
    ("ledgrl-live.com", {"known_brand_unofficial"}),                                     # typo window (loose brand)
    ("paypal.com-login.xyz", {"brand_domain_embedded", "phishing_words_in_domain"}),
    ("roblox.com.bi", {"brand_domain_embedded"}),
    ("verify-account.vercel.app", {"free_hosting", "phishing_words_in_domain"}),
    ("1.2.3.4", {"server_hostname"}),
    ("vmi12345.contaboserver.net", {"server_hostname"}),
    ("bit.ly", {"url_shortener"}),
    ("signinpage-help.com", {"phishing_words_in_domain"}),                               # glued stem
])
def test_rules_fire_on_phishing_patterns(host, expected):
    assert expected <= codes(host)


@pytest.mark.parametrize("host", ["www.paypal.com", "login.microsoftonline.com", "accounts.google.com",
                                  "hdfc.bank.in", "steamcommunity.com", "support.apple.com", "news.example.org",
                                  "upsidedown.com"])
def test_quiet_on_legit_hosts(host):
    assert codes(host) == set()


def test_known_false_positive_loose_brand_inside_a_word():
    # Documented limitation (blueprint 11 #6/#7): loose brands match inside longer words.
    assert codes("theledger.com") == {"known_brand_unofficial"}


def test_org_namespace_and_selected_brand_exclusion():
    acme = BrandContext(name="Acme", official_domains=["acme.com"], keywords=["acme"])
    assert codes("acme.github.io", acme) == set()                                         # the brand's own org
    assert "free_hosting" in codes("acme-login.github.io", acme)
    paypal_owner = BrandContext(name="PayPal", official_domains=["paypal.com"])
    assert "known_brand_unofficial" not in codes("paypal-login.xyz", paypal_owner)       # brand rules handle it


def test_helpers():
    assert free_hosting_suffix("x.y.pages.dev") == "pages.dev" and free_hosting_suffix("pages.dev") is None
    assert is_restricted("hdfc.bank.in") and not is_restricted("bank-in.com")
    assert known_official("mail.google.com") == "Google" and known_official("google.com.evil.xyz") is None


def _page(title: str, text: str = "Welcome", status: int = 200, host: str = "x.example") -> dict:
    return {"final_host": host, "title": title, "text": text, "status": status}


@pytest.mark.parametrize("title,code", [
    ("Voice Mail - listen now", "lure_title"), ("Verification", "lure_title"), ("Connect Wallet", "lure_title"),
    ("PayPal | Log in", "known_brand_unofficial"), ("Official Netflix", "known_brand_unofficial"),
])
def test_title_rules(title, code):
    c = Scorecard()
    page_signals(c, _page(title), "x.example", NO_BRAND, parked=False)
    assert code in {s.code for s in c.signals}


def test_title_rules_quiet_and_abuse_block():
    c = Scorecard()
    page_signals(c, _page("My cooking blog: verification of recipes"), "x.example", NO_BRAND, parked=False)
    page_signals(c, _page("PayPal | Log in"), "x.example", NO_BRAND, parked=True)        # parked: no title rules
    assert not c.signals
    page_signals(c, _page("Site disabled", "This site has been suspended for phishing.", 403), "x.example",
                 NO_BRAND, parked=False)
    assert {s.code for s in c.signals} == {"hosting_abuse_block"}
