"""Parse fetched HTML as inert text (html.parser only; nothing is executed or rendered)."""
from __future__ import annotations

import re
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

SKIP = {"script", "style", "noscript", "template", "svg", "head", "iframe", "object"}
TEXT_LIMIT = 5000
META_KEEP = re.compile(r"^(description|keywords|generator|og:.+|twitter:.+)$", re.I)


class _Parser(HTMLParser):
    def __init__(self, base_url: str):
        super().__init__(convert_charrefs=True)
        self.base = base_url
        self.title = ""
        self.meta: dict[str, str] = {}
        self.text: list[str] = []
        self.text_len = 0
        self.forms: list[dict] = []
        self.links: list[dict] = []
        self._skip = 0
        self._in_title = False
        self._in_a: dict | None = None
        self._form: dict | None = None
        self._labels: list[str] = []

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag in SKIP and tag != "head":
            self._skip += 1
        if tag == "title":
            self._in_title = True
        elif tag == "meta":
            key = a.get("name") or a.get("property") or ""
            if META_KEEP.match(key) and a.get("content") and key.lower() not in self.meta:
                self.meta[key.lower()] = a["content"][:500]
        elif tag == "a" and a.get("href") and len(self.links) < 300:
            self._in_a = {"href": self._abs(a["href"]), "text": ""}
            self.links.append(self._in_a)
        elif tag == "form" and len(self.forms) < 20:
            self._form = {"action": self._abs(a.get("action", "")), "method": (a.get("method") or "get").lower(),
                          "inputs": []}
            self.forms.append(self._form)
        elif tag in ("input", "select", "textarea"):
            field = {"tag": tag, "type": (a.get("type") or ("text" if tag == "input" else tag)).lower(),
                     "name": a.get("name", "")[:80], "id": a.get("id", "")[:80],
                     "placeholder": a.get("placeholder", "")[:120], "autocomplete": a.get("autocomplete", "")[:40],
                     "label": " ".join(self._labels[-2:])[:120], "aria": a.get("aria-label", "")[:120]}
            target = self._form if self._form is not None else (self.forms[-1] if self.forms else None)
            if target is None and field["type"] not in ("hidden", "submit", "button"):
                target = {"action": "", "method": "", "inputs": [], "formless": True}
                self.forms.append(target)
                self._form = target
            if target is not None and len(target["inputs"]) < 40:
                target["inputs"].append(field)

    def handle_endtag(self, tag):
        if tag in SKIP and tag != "head" and self._skip:
            self._skip -= 1
        if tag == "title":
            self._in_title = False
        elif tag == "a":
            self._in_a = None
        elif tag == "form":
            self._form = None

    def handle_data(self, data):
        if self._in_title:
            self.title = (self.title + data)[:200]
            return
        if self._skip:
            return
        s = " ".join(data.split())
        if not s:
            return
        if self._in_a is not None:
            self._in_a["text"] = (self._in_a["text"] + " " + s).strip()[:120]
        self._labels.append(s[:80])
        self._labels = self._labels[-4:]
        if self.text_len < TEXT_LIMIT:
            self.text.append(s)
            self.text_len += len(s) + 1

    def _abs(self, href: str) -> str:
        href = (href or "").strip()
        if href.lower().startswith(("javascript:", "data:", "mailto:", "tel:")):
            return href[:300]
        try:
            return urljoin(self.base, href)[:500]
        except ValueError:
            return href[:500]


def parse(html: str, base_url: str) -> dict:
    p = _Parser(base_url)
    try:
        p.feed(html or "")
        p.close()
    except Exception:  # noqa: BLE001 - broken markup still yields whatever was parsed
        pass
    base_host = (urlsplit(base_url).hostname or "").lower()
    outbound: list[str] = []
    for ln in p.links:
        h = (urlsplit(ln["href"]).hostname or "").lower() if ln["href"].startswith("http") else ""
        if h and h != base_host and h not in outbound and len(outbound) < 100:
            outbound.append(h)
    return {"title": " ".join(p.title.split())[:200], "meta": p.meta, "text": " ".join(p.text)[:TEXT_LIMIT],
            "forms": p.forms[:20], "links": p.links[:300], "outbound_domains": outbound}


def input_kinds(forms: list[dict]) -> set[str]:
    """Sensitive things a page's forms ask for: password, otp, card, cvv, pin, aadhaar."""
    kinds: set[str] = set()
    for f in forms or []:
        for i in f.get("inputs", []):
            if i.get("type") in ("hidden", "submit", "button", "checkbox", "radio"):
                continue
            blob = " ".join(str(i.get(k, "")) for k in ("name", "id", "placeholder", "autocomplete", "label",
                                                        "aria")).lower()
            if i.get("type") == "password" or "password" in blob or "passcode" in blob:
                kinds.add("password")
            if re.search(r"\botp\b|one-time-code|one time|verification code|otp_|_otp", blob):
                kinds.add("otp")
            if re.search(r"cc-number|card ?(number|no)|cardnumber|debit card|credit card", blob):
                kinds.add("card")
            if re.search(r"\bcvv|\bcvc|\bcsc\b|cc-csc", blob):
                kinds.add("cvv")
            if re.search(r"\bm?pin\b|atm ?pin|upi ?pin", blob):
                kinds.add("pin")
            if re.search(r"aadhaa?r", blob):
                kinds.add("aadhaar")
    return kinds
