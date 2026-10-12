"""Presentation helpers: turn system codes into words people use, and build the score rail."""
from __future__ import annotations

STATUS = {
    "new": "New", "investigating": "Investigating", "confirmed": "Confirmed",
    "takedown_requested": "Takedown requested", "taken_down": "Taken down", "false_positive": "False positive",
    "monitoring": "Monitoring",
}
STATUS_HELP = {
    "new": "Not looked at yet.",
    "investigating": "Someone is checking it.",
    "confirmed": "It impersonates the brand. Next: request a takedown.",
    "takedown_requested": "A takedown request was sent to the registrar, host or platform.",
    "taken_down": "It is offline or was removed.",
    "false_positive": "Not a threat. It leaves the open queue.",
    "monitoring": "Not actionable now; keep an eye on it.",
}
KIND = {
    "website": "Website", "domain": "Domain", "android_app": "Android app", "ios_app": "iOS app",
    "youtube": "YouTube channel", "telegram": "Telegram", "bluesky": "Bluesky", "social_profile": "Social profile",
    "other": "Reported message",
}
CHECK = {
    "dns": "DNS", "domain_name": "Domain name", "rdap_domain": "Registration", "rdap_ip": "Hosting",
    "tls": "Certificate", "wayback": "Web archive", "page_fetch": "Page", "content_signals": "Page content",
    "safe_browsing": "Google Safe Browsing", "virustotal": "VirusTotal", "urlhaus": "URLhaus",
    "scam_lists": "Scam lists", "phishtank": "PhishTank", "ct_history": "Certificate history",
    "play_details": "Google Play listing", "play_permissions": "App permissions", "ios_details": "App Store listing",
    "icon_vs_logo": "Icon vs logo", "developer_website": "Developer website", "description_signals": "App description",
    "youtube_channel": "YouTube channel", "telegram_page": "Telegram page", "bluesky_profile": "Bluesky profile",
    "public_og_tags": "Public page tags", "social_profile": "Profile data", "user_profile_details": "Profile details",
    "photo_vs_logo": "Photo vs logo", "text_rules": "Message text", "ai_text": "AI classification",
    "handle_similarity": "Handle similarity",
}
CHECK_STATUS = {"ran": "Ran", "not_possible": "Couldn't run", "not_configured": "Not configured"}
EVIDENCE = {
    "page_capture": "Page capture", "rdap_domain": "Registration record", "rdap_ip": "Hosting record",
    "tls_certificate": "Certificate", "ct_certs": "Certificate history", "investigation_facts": "Investigation facts",
    "play_listing": "Google Play listing", "appstore_listing": "App Store listing", "youtube_channel": "YouTube channel",
    "telegram_page": "Telegram page", "bluesky_profile": "Bluesky profile", "public_og_tags": "Public page tags",
    "social_profile": "Profile data", "user_supplied_profile": "Profile details (user-supplied)",
    "reported_text": "Reported message", "screenshot": "Screenshot",
}
INDICATOR = {
    "phone": "Phone", "upi": "UPI id", "email": "Email", "domain": "Domain", "handle": "Handle",
    "developer": "Developer", "icon_hash": "Icon hash", "ip": "IP address", "asn": "Network (ASN)", "url": "Link",
}
SOURCE = {
    "investigate": "Manual", "api": "API", "intake": "Customer report", "link_in_bio": "Link in bio",
    "demo-fixture": "Demo fixture",
}


def status_label(s: str | None) -> str:
    return STATUS.get(s or "", (s or "").replace("_", " ").capitalize())


def kind_label(k: str | None) -> str:
    return KIND.get(k or "", (k or "").replace("_", " ").capitalize())


def check_label(c: str | None) -> str:
    return CHECK.get(c or "", (c or "").replace("_", " ").capitalize())


def check_status_label(s: str | None) -> str:
    return CHECK_STATUS.get(s or "", s or "")


def evidence_label(k: str | None) -> str:
    return EVIDENCE.get(k or "", (k or "").replace("_", " ").capitalize())


def indicator_label(t: str | None) -> str:
    return INDICATOR.get(t or "", (t or "").replace("_", " ").capitalize())


def source_label(s: str | None) -> str:
    s = s or ""
    if s.startswith("discovery:"):
        return "Scan · " + scan_source(s.split(":", 1)[1])
    return SOURCE.get(s, s.replace("_", " ").capitalize())


def _short(v, n: int = 60) -> str:
    s = str(v or "")
    return s if len(s) <= n else s[:n - 1] + "…"


def _signals_line(d: dict, empty: str) -> str:
    codes = d.get("signals") or []
    if not codes:
        return empty
    from threatdesk.scoring import RULES
    return "Found: " + "; ".join(RULES[c][1] if c in RULES else c for c in codes[:4])


def _date(v) -> str:
    return str(v)[:10] if v else ""


def check_summary(check: str, status: str, d: dict) -> str:
    """One plain sentence per check result (the raw data stays one click away)."""
    d = d or {}
    if status != "ran":
        return d.get("reason") or check_status_label(status)
    if d.get("official"):
        return "Official asset of the brand"
    if check == "dns":
        state = d.get("state")
        if state == "resolved":
            return "Resolves to " + ", ".join(d.get("ips", [])[:4])
        return {"nxdomain": "Domain does not exist (NXDOMAIN)", "noanswer": "No address records"}.get(state, state or "")
    if check == "domain_name":
        if d.get("lookalike_of"):
            return f"Resembles {d['lookalike_of']}"
        return _signals_line(d, d.get("note") or "No look-alike pattern in the name")
    if check == "rdap_domain":
        line = f"Registered {_date(d['registered'])}" if d.get("registered") else "No registration date"
        if d.get("age_days") is not None:
            line += f" ({d['age_days']} days ago)"
        if d.get("registrar"):
            line += f" via {_short(d['registrar'], 40)}"
        if d.get("redacted"):
            line += " · registrant redacted"
        return line
    if check == "rdap_ip":
        name = d.get("org") or d.get("name") or d.get("ip") or ""
        asn = (d.get("asn") or {}).get("asn")
        return _short(name, 50) + (f" · AS{asn}" if asn else "")
    if check == "tls":
        if d.get("verified"):
            return f"Valid, issued by {_short(d.get('issuer'), 70)} on {_date(d.get('not_before'))}"
        return f"Not valid: {_short(d.get('error'), 80)}"
    if check == "wayback":
        if d.get("first_snapshot"):
            return f"First archived {_date(d['first_snapshot'])}"
        return "No archive history"
    if check == "page_fetch":
        line = f"HTTP {d.get('status')} · “{_short(d.get('title') or 'no title', 50)}”"
        if d.get("final_host") and d.get("final_host") != d.get("host"):
            line += f" · ends at {d['final_host']}"
        return line
    if check in ("content_signals", "description_signals", "text_rules"):
        if d.get("parked"):
            return "Parked domain page"
        return _signals_line(d, "Nothing suspicious in the text")
    if check in ("safe_browsing", "urlhaus"):
        return ("Listed: " + ", ".join(d.get("threats") or ["yes"])) if d.get("listed") else "Not listed"
    if check == "virustotal":
        if not d.get("known"):
            return "Not known to VirusTotal"
        return f"{d.get('malicious', 0)} malicious, {d.get('suspicious', 0)} suspicious of {d.get('engines', 0)} engines"
    if check == "scam_lists":
        if d.get("hit"):
            return f"{d['hit']} is on: {', '.join(d.get('sources', []))}"
        return f"Not on any list ({d.get('total', 0):,} known scam domains checked)"
    if check == "phishtank":
        if d.get("verified_phish"):
            return "Verified phish, still online"
        return "Reported, not verified" if d.get("in_database") else "Not in PhishTank"
    if check == "ct_history":
        n = d.get("certs", 0)
        if d.get("earliest"):
            return f"{n} certificate(s), first issued {_date(d['earliest'])}"
        return f"{n} certificate(s), no history (current certificates only)"
    if check in ("play_details", "ios_details"):
        who = d.get("developer") or d.get("seller") or "unknown developer"
        extra = f" · {d['installs']} installs" if d.get("installs") else ""
        return f"“{_short(d.get('title'), 50)}” by {_short(who, 40)}{extra}"
    if check == "play_permissions":
        dang = d.get("dangerous") or []
        return ("Asks for: " + ", ".join(dang[:4])) if dang else "No high-risk permissions"
    if check in ("icon_vs_logo", "photo_vs_logo"):
        if d.get("distance") is None:
            return d.get("note") or "Compared"
        return ("Matches the brand logo" if d.get("match") else "Does not match the brand logo") + \
            f" (distance {d['distance']})"
    if check == "developer_website":
        if d.get("registered"):
            return f"{d.get('domain')} registered {_date(d['registered'])}"
        return d.get("note") or str(d.get("domain") or "")
    if check in ("youtube_channel", "bluesky_profile", "social_profile", "telegram_page", "public_og_tags",
                 "user_profile_details"):
        name = d.get("title") or d.get("name") or d.get("display_name") or d.get("handle") or ""
        bits = [f"“{_short(name, 50)}”"] if name else []
        if d.get("followers") is not None:
            bits.append(f"{d['followers']:,} followers" if isinstance(d["followers"], int) else f"{d['followers']} followers")
        if d.get("created"):
            bits.append(f"since {_date(d['created'])}")
        if d.get("heuristic"):
            bits.append("heuristic, unverified")
        if d.get("user_supplied"):
            bits.append("user-supplied, unverified")
        return " · ".join(bits) or "Read"
    if check == "ai_text":
        return f"{(d.get('category') or '').replace('_', ' ')} · likelihood {d.get('likelihood')}"
    if check == "handle_similarity":
        return f"Similar to official @{d['similar_to']}" if d.get("similar_to") else "No similar official handle"
    return d.get("note") or "Ran"


RAIL_TONES = ["t1", "t2", "t3", "t4"]


def rail(signals: list, score: int) -> list[dict]:
    """Segments for the score rail: one per positive signal, widths in whole percent, clipped at 100."""
    segs, used = [], 0
    for i, s in enumerate(sorted((s for s in signals if s.points > 0), key=lambda s: -s.points)):
        w = max(0, min(s.points, 100 - used))
        if w:
            segs.append({"w": w, "tone": RAIL_TONES[i % 4], "code": s.code, "points": s.points})
            used += w
    # Negative signals (e.g. redirects to an official domain) pull the score back below the stacked total.
    if used > score:
        excess = used - score
        for seg in reversed(segs):
            cut = min(seg["w"], excess)
            seg["w"] -= cut
            excess -= cut
            if not excess:
                break
        segs = [s for s in segs if s["w"]]
    return segs


SCAN_SOURCES = {
    "domains": "Look-alike domains", "certificate_transparency": "Certificate logs", "ios": "App Store",
    "android": "Google Play", "youtube": "YouTube", "bluesky": "Bluesky", "telegram": "Telegram",
    "websearch": "Web search",
}


def scan_source(name: str | None) -> str:
    return SCAN_SOURCES.get(name or "", (name or "").replace("_", " ").capitalize())


def scan_status(text: str | None) -> str:
    """CSS state for a source status line: ok (ran), bad (failed), off (not configured / not possible)."""
    t = (text or "").lower()
    if t.startswith("ok"):
        return "ok"
    if t.startswith("failed") or t.startswith("error"):
        return "bad"
    return "off"


def scan_source_badge(text: str | None, candidates: int = 0) -> dict[str, str]:
    """Structured status badge for discovery adapter outcomes: outcome, icon, label, safe summary."""
    t = (text or "").lower()
    if t.startswith("ok"):
        if candidates > 0:
            return {"class": "ok", "icon": "✓", "label": "Found candidates", "summary": text or ""}
        return {"class": "clean", "icon": "○", "label": "No threats found", "summary": text or ""}
    if "ran out of time" in t or "timeout" in t:
        return {"class": "timeout", "icon": "⏱", "label": "Timed out", "summary": "Adapter timed out"}
    if t.startswith("failed") or t.startswith("error"):
        safe_msg = "Adapter request failed"
        for w in t.split():
            if w.isdigit() and len(w) == 3:
                safe_msg = f"HTTP {w}"
                break
        return {"class": "bad", "icon": "⚠", "label": "Failed", "summary": safe_msg}
    if t.startswith("not configured"):
        return {"class": "off", "icon": "⚙", "label": "Not configured", "summary": "Optional adapter not configured"}
    if t.startswith("not possible") or t.startswith("skipped"):
        return {"class": "off", "icon": "⊘", "label": "Skipped", "summary": text or "Target assets not configured"}
    return {"class": "off", "icon": "•", "label": "Pending", "summary": text or ""}


from threatdesk.web.explain_data import sev_badge, status_icon

FILTERS = {
    "scan_source": scan_source, "scan_status": scan_status, "scan_source_badge": scan_source_badge,
    "status": status_label, "status_icon": status_icon, "kind": kind_label,
    "check": check_label, "check_status": check_status_label, "evidence_kind": evidence_label,
    "indicator": indicator_label, "source": source_label, "sev_badge": sev_badge,
}
