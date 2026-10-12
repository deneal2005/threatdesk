"""Brand-independent website rules: they work without a selected brand and never fire on an official host."""
from __future__ import annotations

import ipaddress
import re

from rapidfuzz import fuzz

from threatdesk import constants as C
from threatdesk.brands import BrandContext, domain_matches
from threatdesk.indicators import is_shortener
from threatdesk.scoring import Scorecard

_PIECE_SPLIT = re.compile(r"[.\-_]+")
_TITLE_SEP = re.compile(r"\s+[|\-–—:·•»]\s+")
_TITLE_LEAD = re.compile(r"^(official|the|welcome to)\s+", re.I)
_SERVER = [re.compile(p, re.I) for p in C.SERVER_HOST_PATTERNS]
_LURE_ANY = [re.compile(p, re.I) for p in C.LURE_TITLE_ANYWHERE]
_LURE_EXACT = [re.compile(rf"^\s*{p}\s*$", re.I) for p in C.LURE_TITLE_EXACT]
_ABUSE = [re.compile(p, re.I) for p in C.ABUSE_BLOCK_PATTERNS]
_PHISH_WORDS = set(C.HOST_PHISH_WORDS)


def free_hosting_suffix(host: str) -> str | None:
    host = (host or "").lower()
    hits = [s for s in C.FREE_HOSTING_SUFFIXES if host.endswith("." + s)]
    return max(hits, key=len) if hits else None


def is_server_host(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return any(p.search(host or "") for p in _SERVER)


def _chosen_part(host: str) -> tuple[str, str]:
    """The part of the hostname an attacker chose: the subdomain on free hosting, else the registered label."""
    from threatdesk.checks.domain import registrable_domain
    suffix = free_hosting_suffix(host)
    if suffix:
        return host[: -len(suffix) - 1], "free_hosting"
    return registrable_domain(host).split(".")[0], "label"


def _pieces(text: str) -> list[str]:
    return [p for p in _PIECE_SPLIT.split((text or "").lower()) if p]


_CONFUSABLE = [("rn", "m"), ("vv", "w"), ("1", "l"), ("i", "l"), ("|", "l"), ("0", "o"), ("3", "e"), ("5", "s")]


def _skeleton(s: str) -> str:
    s = (s or "").lower()
    for a, b in _CONFUSABLE:
        s = s.replace(a, b)
    return s


def _host_has(token: str, pieces: list[str], loose: bool) -> bool:
    t = token.replace(" ", "").lower()
    if len(t) < 4:
        return t in pieces
    st = _skeleton(t)
    for piece in pieces:
        if piece == t or _skeleton(piece) == st:
            return True
        if loose and (st in _skeleton(piece) or _typo_in(t, piece)):
            return True
    return False


def _typo_in(t: str, piece: str) -> bool:
    """A near-miss of t starting at the same 3 letters somewhere in piece ("ledgrl", "exods")."""
    for i in range(len(piece)):
        if piece[i:i + 3] != t[:3]:
            continue
        for n in (len(t) - 1, len(t), len(t) + 1):
            w = piece[i:i + n]
            if len(w) >= 4 and fuzz.ratio(w, t) >= 88:
                return True
    return False


def _embedded_domain(host: str, domains: list[str]) -> str | None:
    sk = _skeleton(host)
    for d in domains:
        if "." in d and re.search(rf"(^|\.){re.escape(_skeleton(d))}[.-]", sk):
            return d
    return None


def _title_has(token: str, title: str) -> bool:
    return re.search(rf"(?<![a-z0-9]){re.escape(token.lower())}(?![a-z0-9])", (title or "").lower()) is not None


def _norm_title(title: str) -> str:
    return " ".join((title or "").lower().split())


def _brand_is_official(host: str, domains: list[str], tokens: list[str]) -> bool:
    if any(domain_matches(host, d) for d in domains):
        return True
    for ns in C.ORG_NAMESPACE_HOSTS:                 # acme.github.io is the acme org's own site
        if host.endswith("." + ns) and host[: -len(ns) - 1].split(".")[-1] in [t.replace(" ", "") for t in tokens]:
            return True
    return False


def is_restricted(host: str) -> bool:
    host = (host or "").lower()
    return any(host == s or host.endswith("." + s) for s in C.RESTRICTED_SUFFIXES)


def known_official(host: str) -> str | None:
    for name, domains, _tokens, _loose in C.KNOWN_BRANDS:
        if any(domain_matches(host, d) for d in domains):
            return name
    return None


def _candidate_brands(brand: BrandContext):
    """Well-known brands, minus the one being protected (its own rules live in content.domain_name_signals)."""
    mine = {t.replace(" ", "") for t in brand.terms()}
    for name, domains, tokens, loose in C.KNOWN_BRANDS:
        if name.lower().replace(" ", "") in mine or any(d in brand.official_domains for d in domains):
            continue
        yield name, domains, tokens, loose


def host_signals(card: Scorecard, host: str, brand: BrandContext) -> dict:
    host = (host or "").lower()
    if brand.is_official_host(host) or is_restricted(host):
        return {"skipped": "official host or restricted registry"}
    if ko := known_official(host):
        return {"known_official": ko}
    part, where = _chosen_part(host)
    if where == "free_hosting" and free_hosting_suffix(host) in C.ORG_NAMESPACE_HOSTS and \
            part.split(".")[-1] in [t.replace(" ", "") for t in brand.terms()]:
        return {"official_namespace": host}
    out: dict = {"chosen_part": part}
    pieces = _pieces(part)
    for name, domains, tokens, loose in _candidate_brands(brand):
        if _brand_is_official(host, domains, tokens):
            continue
        hit = next((t for t in tokens if _host_has(t, pieces, loose)), None)
        if hit:
            card.add("known_brand_unofficial", f"{host} uses the name {name} ('{hit}') but is not on {name}'s domains")
            out["known_brand"] = name
            break
    embed_sets = [(n, d) for n, d, _t, _l in _candidate_brands(brand)] + [(brand.name, brand.official_domains)]
    for name, domains in embed_sets:
        if d := _embedded_domain(host, domains):
            card.add("brand_domain_embedded", f"{host} embeds {name}'s domain {d}")
            out["embedded"] = d
            break
    if is_shortener(f"https://{host}/"):
        card.add("url_shortener", f"{host} is a link shortener")
        out["shortener"] = True
    elif suffix := free_hosting_suffix(host):
        card.add("free_hosting", f"{host} is on {suffix}, where anyone can create a site in seconds")
        out["free_hosting"] = suffix
    elif is_server_host(host):
        card.add("server_hostname", f"{host} is a bare IP address or a hosting provider's default name")
        out["server_host"] = True
    words = [p for p in pieces if p in _PHISH_WORDS]
    words += [s for s in C.HOST_PHISH_STEMS if any(s in p and p not in words for p in pieces) and s not in words]
    words = list(dict.fromkeys(words))
    if words:
        card.add("phishing_words_in_domain", f"{host}: {', '.join(words[:5])}")
        out["phish_words"] = words
    return out


def page_signals(card: Scorecard, page: dict, link_host: str, brand: BrandContext, parked: bool) -> dict:
    final_host = (page.get("final_host") or link_host or "").lower()
    if brand.is_official_host(final_host) or known_official(final_host) or is_restricted(final_host):
        return {}
    out: dict = {}
    if final_host and final_host != link_host:
        out["final"] = host_signals(card, final_host, brand)
    title = page.get("title") or ""
    text = page.get("text") or ""
    head = f"{title} {text[:800]}"
    if any(p.search(head) for p in _ABUSE) and (int(page.get("status") or 200) >= 400 or len(text) < 1500):
        card.add("hosting_abuse_block", f"page says: '{title[:80] or text[:80]}'")
        out["abuse_block"] = True
    if parked or not title:
        return out
    t = _norm_title(title)
    lead = _TITLE_LEAD.sub("", t)
    last = _TITLE_SEP.split(t)[-1].strip()
    for name, domains, tokens, _loose in _candidate_brands(brand):
        if _brand_is_official(final_host, domains, tokens):
            continue
        for tok in tokens:
            first_word = lead.startswith(tok) and (len(lead) == len(tok) or not lead[len(tok)].isalnum())
            if first_word or (_title_has(tok, last) and len(last) <= len(tok) + 10):
                card.add("known_brand_unofficial", f"page title '{title[:80]}' presents as {name}")
                out["title_brand"] = name
                break
        if "title_brand" in out:
            break
    if any(p.search(title) for p in _LURE_ANY) or any(p.match(t) for p in _LURE_EXACT):
        card.add("lure_title", f"page title '{title[:80]}'")
        out["lure_title"] = True
    return out
