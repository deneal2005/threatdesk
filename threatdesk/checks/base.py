"""Check contract: every check returns a CheckOutcome with status ran|not_possible|not_configured."""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Awaitable, Callable

import httpx

from threatdesk.brands import BrandContext
from threatdesk.config import Settings
from threatdesk.jsonutil import canonical_sha256, jsonable
from threatdesk.linkdetect import Link
from threatdesk.scoring import Scorecard

log = logging.getLogger("threatdesk.checks")
RAN, NOT_POSSIBLE, NOT_CONFIGURED = "ran", "not_possible", "not_configured"
API_TIMEOUT = 8.0


@dataclass
class EvidenceItem:
    kind: str
    content: dict
    sha256: str = ""

    def __post_init__(self):
        self.content = jsonable(self.content)
        if not self.sha256:                 # page captures pass the SHA-256 of the raw body instead
            self.sha256 = canonical_sha256(self.content)


@dataclass
class CheckOutcome:
    check: str
    status: str
    detail: dict = field(default_factory=dict)


@dataclass
class Ctx:
    """Shared state for one investigation. Checks read facts written by earlier checks."""
    client: httpx.AsyncClient
    link: Link
    brand: BrandContext
    settings: Settings
    card: Scorecard = field(default_factory=Scorecard)
    facts: dict = field(default_factory=dict)
    indicators: set = field(default_factory=set)          # {(type, value)}
    evidence: list[EvidenceItem] = field(default_factory=list)
    outcomes: list[CheckOutcome] = field(default_factory=list)

    def indicator(self, type_: str, value) -> None:
        if value not in (None, "", []):
            self.indicators.add((type_, str(value)[:300]))

    def ran(self, check: str, **detail) -> CheckOutcome:
        return CheckOutcome(check, RAN, detail)

    @staticmethod
    def not_possible(check: str, reason: str, **detail) -> CheckOutcome:
        return CheckOutcome(check, NOT_POSSIBLE, {"reason": reason, **detail})

    @staticmethod
    def not_configured(check: str, what: str) -> CheckOutcome:
        return CheckOutcome(check, NOT_CONFIGURED, {"reason": f"{what} not set"})


CheckFn = Callable[[Ctx], Awaitable[CheckOutcome]]


async def run_check(name: str, fn: CheckFn, ctx: Ctx, timeout: float = 25.0) -> CheckOutcome:
    """Run one check; any exception or timeout becomes not_possible with a short reason (never a crash)."""
    try:
        out = await asyncio.wait_for(fn(ctx), timeout)
    except asyncio.TimeoutError:
        out = Ctx.not_possible(name, f"timed out after {int(timeout)}s")
    except httpx.HTTPError as e:
        out = Ctx.not_possible(name, f"network error ({type(e).__name__})")
    except Exception as e:  # noqa: BLE001 - checks must never take the investigation down
        log.warning("check crashed", extra={"fields": {"check": name, "error": type(e).__name__}})
        out = Ctx.not_possible(name, f"internal error ({type(e).__name__})")
    ctx.outcomes.append(out)
    return out


async def get_json(client: httpx.AsyncClient, url: str, *, params: dict | None = None, headers: dict | None = None,
                   method: str = "GET", json_body: dict | None = None, data: dict | None = None,
                   timeout: float = API_TIMEOUT, retries: int = 1) -> tuple[int, dict | list | None]:
    """Fixed-host API call (not user-derived URLs). 1 retry on network error/5xx. Returns (status, json|None)."""
    last: Exception | None = None
    for attempt in range(retries + 1):
        try:
            r = await client.request(method, url, params=params, headers=headers, json=json_body, data=data,
                                     timeout=timeout)
            if r.status_code >= 500 and attempt < retries:
                await asyncio.sleep(0.5)
                continue
            try:
                return r.status_code, r.json()
            except ValueError:
                return r.status_code, None
        except (httpx.TimeoutException, httpx.TransportError) as e:
            last = e
            if attempt < retries:
                await asyncio.sleep(0.5)
    raise last or httpx.TransportError("request failed")
