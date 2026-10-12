"""Text/content signals (pure functions over page facts) and domain-name signals (lookalike, homograph)."""
from __future__ import annotations

import re

from rapidfuzz import fuzz

from threatdesk import constants as C
from threatdesk.brands import BrandContext
from threatdesk.checks import generic
from threatdesk.checks.base import Ctx
from threatdesk.checks.domain import registrable_domain
from threatdesk.db import utcnow
from threatdesk.indicators import extract, is_shortener
from threatdesk.linkdetect import homograph
from threatdesk.scoring import Scorecard
from threatdesk.scoring_helpers import parse_date

DISCOUNT_RE = re.compile(r"(?:flat|upto|up to|get)?\s*(\d{2,3})\s*%\s*(?:off|discount)", re.I)
ASK_RE = re.compile(r"\b(enter|share|send|provide|submit|confirm|tell|type|give|bhejein|batayein|bataye)\b", re.I)
PARKED_RE = re.compile(r"parked domain|domain .{0,40}for sale|buy this domain|domain parking|"
                       r"this domain (has been|is) (registered|parked)|sedoparking|parkingcrew|bodis\.com", re.I)
NEG_RE = re.compile(r"\b(never|do not|don't|dont|not|kabhi na|mat)\b", re.I)


def _near(text: str, word: str, width: int = 40) -> str:
    i = text.find(word)
    return text[max(0, i - width): i + len(word) + width].strip() if i >= 0 else ""


def phrases_in(text: str, phrases: list[str]) -> list[str]:
    t = (text or "").lower()
    return [p for p in phrases if re.search(rf"(?<![a-z]){re.escape(p)}(?![a-z])", t)]


def _negated(t: str, phrase: str) -> bool:
    for m in re.finditer(rf"(?<![a-z]){re.escape(phrase)}(?![a-z])", t):
        if not NEG_RE.search(t[max(0, m.start() - 30): m.start()]):
            return False
    return True


def text_signals(card: Scorecard, text: str, brand: BrandContext, *, official_context: bool = False,
                 sensitive_inputs: set[str] | None = None, links: list[dict] | None = None,
                 brand_mentions: bool = True) -> dict:
    t = " ".join((text or "").lower().split())
    found: dict[str, str] = {}

    def hit(code: str, evidence: str) -> None:
        if card.add(code, evidence):
            found[code] = evidence

    if not official_context:
        kinds = sorted((sensitive_inputs or set()) & {"password", "otp", "card", "cvv", "pin", "aadhaar"})
        if kinds:
            hit("asks_credentials", f"a form asks for: {', '.join(kinds)}")
        else:
            for w in C.CREDENTIAL_WORDS:
                for m in re.finditer(rf"(?<![a-z]){re.escape(w)}(?![a-z])", t):
                    window = t[max(0, m.start() - 40): m.end() + 40]
                    if ASK_RE.search(window) and not NEG_RE.search(t[max(0, m.start() - 30): m.start()]):
                        hit("asks_credentials", f"text asks for {w}: '…{window}…'")
                        break
                if "asks_credentials" in found:
                    break
    if pay := phrases_in(t, C.PAYMENT_ONLY):
        hit("payment_only_risky", ", ".join(pay[:4]))
    if urg := phrases_in(t, C.URGENCY_WORDS):
        hit("urgency", ", ".join(urg[:4]))
    big = [int(m.group(1)) for m in DISCOUNT_RE.finditer(t) if 70 < int(m.group(1)) <= 100]
    if big:
        hit("big_discount", f"{max(big)}% off")
    earn = phrases_in(t, C.EARN_LOAN_CLAIMS)
    if earn:
        hit("earn_loan_claims", ", ".join(earn[:4]))
    scam = [p for p in phrases_in(t, C.SCAM_PHRASES) if p not in earn and not _negated(t, p)]
    if scam:
        hit("scam_phrases", ", ".join(scam[:5]))
    if not official_context:
        if claims := phrases_in(t, C.OFFICIAL_CLAIMS):
            hit("claims_official", ", ".join(claims[:4]))
        ind = extract(text or "")
        hrefs = [ln.get("href", "") for ln in (links or [])]
        bait = ind["messaging"] + [h for h in hrefs if re.search(r"wa\.me/|api\.whatsapp\.com|t\.me/|telegram\.me/", h)]
        bait += ind["upi"] + ind["phone"][:3] + [u for u in ind["url"] + hrefs if is_shortener(u)]
        if bait:
            hit("contact_bait", ", ".join(dict.fromkeys(b[:80] for b in bait[:5])))
        if brand_mentions and brand.name:
            for term in (x for x in brand.terms() if len(x) >= 3):
                if re.search(rf"(?<![a-z0-9]){re.escape(term)}(?![a-z0-9])", t):
                    hit("brand_mention_unofficial", f"page mentions '{term}'")
                    break
    return found


def missing_policy_pages(links: list[dict]) -> list[str]:
    blob = " ".join(f"{ln.get('href', '')} {ln.get('text', '')}" for ln in links or []).lower()
    return [kind for kind, hints in C.POLICY_PAGE_HINTS.items() if not any(h in blob for h in hints)]


async def check_content(ctx: Ctx):
    page = ctx.facts.get("page")
    if not page:
        return ctx.not_possible("content_signals", "page could not be fetched")
    final_host = page.get("final_host") or ctx.link.host
    official = ctx.brand.is_official_host(final_host) or generic.is_restricted(final_host)
    text = " ".join([page.get("title") or "", (page.get("meta") or {}).get("description", ""), page.get("text") or ""])
    parked = bool(PARKED_RE.search(text[:3000]))
    ctx.facts["parked"] = parked
    before = {s.code for s in ctx.card.signals}
    text_signals(ctx.card, text, ctx.brand, official_context=official,
                 sensitive_inputs=set(page.get("sensitive_inputs") or []), links=page.get("links"),
                 brand_mentions=not parked)
    gen = generic.page_signals(ctx.card, page, ctx.link.host, ctx.brand, parked)
    missing = missing_policy_pages(page.get("links") or [])
    if not official and not parked and (page.get("text") or "").strip() and not page.get("truncated") \
            and len(missing) == len(C.POLICY_PAGE_HINTS):
        ctx.card.add("missing_policy_pages", "no link to a contact, privacy or refund page")
    new = [s.code for s in ctx.card.signals if s.code not in before]
    return ctx.ran("content_signals", signals=new, parked=parked, official_page=official, missing_pages=missing,
                   generic=gen)


INDEPENDENT_MIN_DAYS = 730
STRONG_RISK = {"safe_browsing_hit", "virustotal_malicious", "virustotal_suspicious", "urlhaus_listed",
               "phishtank_verified", "scam_list_hit", "hosting_abuse_block", "idn_homograph", "brand_domain_embedded",
               "brand_mention_unofficial", "claims_official", "known_brand_unofficial", "scam_phrases", "lure_title"}


def independent_site(ctx: Ctx) -> None:
    """Counter-evidence: an old site that never mentions the brand is probably someone else's business."""
    page = ctx.facts.get("page")
    if not ctx.brand.name or not page or not page.get("title") or ctx.facts.get("parked") is not False:
        return
    if not any(o.check == "content_signals" and o.status == "ran" for o in ctx.outcomes):
        return
    if {s.code for s in ctx.card.signals} & STRONG_RISK:
        return
    text = f"{page.get('title', '')} {page.get('text', '')}".lower()
    if any(re.search(rf"(?<![a-z0-9]){re.escape(t)}(?![a-z0-9])", text) for t in ctx.brand.terms() if len(t) >= 3):
        return
    dates = [parse_date((ctx.facts.get("ct") or {}).get("earliest")),
             parse_date((ctx.facts.get("rdap_domain") or {}).get("registered"))]
    dates = [d for d in dates if d]
    if dates and (utcnow() - min(dates)).days >= INDEPENDENT_MIN_DAYS:
        ctx.card.add("independent_site", f"site since {min(dates).date().isoformat()}, page '{page['title'][:60]}' "
                                         f"never mentions {ctx.brand.name}")


def domain_name_signals(card: Scorecard, host: str, brand: BrandContext) -> dict:
    out: dict = {}
    if not brand.name:
        out["note"] = "No brand selected: general rules only, no brand look-alike check"
    elif brand.is_official_host(host):
        out["official"] = True
    else:
        reg = registrable_domain(host)
        label = reg.split(".")[0]
        for off in brand.official_domains:
            oreg = registrable_domain(off)
            olabel = oreg.split(".")[0]
            if reg == oreg:
                continue
            ratio = fuzz.ratio(label, olabel)
            contains = len(olabel) >= 3 and olabel in label and label != olabel
            if ratio >= 80 or contains:
                why = f"similarity {int(ratio)}%" if ratio >= 80 else f"contains the official label '{olabel}'"
                card.add("domain_lookalike", f"{reg} resembles official {oreg} ({why})")
                out["lookalike_of"] = oreg
                break
        flat = host.replace("-", "").replace(".", "")
        for term in brand.terms():
            tt = term.replace(" ", "")
            if len(tt) >= 4 and tt in flat:
                card.add("domain_has_brand", f"{host} contains the brand name")
                out["has_brand"] = term
                break
        hg = homograph(host, brand.official_domains, brand.terms())
        if hg["is_idn"]:
            out["homograph"] = hg
        if hg["suspicious"]:
            card.add("idn_homograph", f"{host} displays as {hg['unicode']} (skeleton {hg['skeleton']})")
    out["generic"] = generic.host_signals(card, host, brand)
    return out


async def check_domain_name(ctx: Ctx):
    before = {s.code for s in ctx.card.signals}
    detail = domain_name_signals(ctx.card, ctx.link.host, ctx.brand)
    detail["signals"] = [s.code for s in ctx.card.signals if s.code not in before]
    return ctx.ran("domain_name", **detail)
