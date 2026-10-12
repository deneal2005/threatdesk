"""TLS certificate check: notBefore/notAfter, issuer, SAN, hostname match, verification result."""
from __future__ import annotations

import asyncio
import os
import ssl
import tempfile
from datetime import datetime, timezone

try:
    from datetime import UTC
except ImportError:
    UTC = timezone.utc

from threatdesk.checks.base import Ctx, EvidenceItem
from threatdesk.db import utcnow
from threatdesk.safety import UnsafeURL, resolve_public_ip


def _decode_der(der: bytes) -> dict:
    """Best-effort decode of a certificate that failed verification (CPython's private decoder needs a file)."""
    if not der:
        return {}
    path = None
    try:
        with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as f:
            f.write(ssl.DER_cert_to_PEM_cert(der))
            path = f.name
        return ssl._ssl._test_decode_cert(path)  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001
        return {}
    finally:
        if path:
            try:
                os.unlink(path)
            except OSError:
                pass


def _name(seq) -> str:
    """((('organizationName', 'X'),), (('commonName', 'Y'),)) -> 'X, Y' (organisation first)."""
    parts = {}
    for rdn in seq or ():
        for k, v in rdn:
            parts.setdefault(k, v)
    return ", ".join(v for v in (parts.get("organizationName"), parts.get("commonName")) if v)


def _cert_time(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        return datetime.fromtimestamp(ssl.cert_time_to_seconds(s), UTC).replace(tzinfo=None)
    except (ValueError, OverflowError):
        return None


def hostname_matches(host: str, sans: list[str]) -> bool:
    host = host.lower()
    for s in sans:
        s = s.lower()
        if s == host or (s.startswith("*.") and host.count(".") == s.count(".") and host.endswith(s[1:])):
            return True
    return False


async def _handshake(ip: str, host: str, verify: bool) -> tuple[dict, bytes | None]:
    if verify:
        sctx = ssl.create_default_context()
    else:
        sctx = ssl.create_default_context()
        sctx.check_hostname = False
        sctx.verify_mode = ssl.CERT_NONE
    reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, 443, ssl=sctx, server_hostname=host), 8)
    try:
        obj = writer.get_extra_info("ssl_object")
        return (obj.getpeercert() or {}), obj.getpeercert(binary_form=True)
    finally:
        writer.close()
        try:
            await asyncio.wait_for(writer.wait_closed(), 2)
        except Exception:  # noqa: BLE001
            pass


async def check_tls(ctx: Ctx):
    host = ctx.link.host
    try:
        ip = await resolve_public_ip(host)
    except UnsafeURL as e:
        return ctx.not_possible("tls", str(e))
    verified, error = True, None
    try:
        cert, _der = await _handshake(ip, host, True)
    except ssl.SSLCertVerificationError as e:
        verified, error = False, (e.verify_message or str(e))[:200]
        try:
            _, der = await _handshake(ip, host, False)
        except (OSError, ssl.SSLError, asyncio.TimeoutError):
            der = None
        cert = _decode_der(der)
    except (ConnectionRefusedError, asyncio.TimeoutError):
        return ctx.not_possible("tls", "no HTTPS service on port 443")
    except ssl.SSLError as e:
        return ctx.not_possible("tls", f"TLS handshake failed ({type(e).__name__})")
    except OSError:
        return ctx.not_possible("tls", "no HTTPS service on port 443")
    nb, na = _cert_time(cert.get("notBefore")), _cert_time(cert.get("notAfter"))
    san = [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"][:30]
    detail = {"ip": ip, "verified": verified, "error": error, "issuer": _name(cert.get("issuer")),
              "subject": _name(cert.get("subject")), "not_before": nb.isoformat() if nb else None,
              "not_after": na.isoformat() if na else None, "san": san, "hostname_match": hostname_matches(host, san)}
    ctx.facts["tls"] = detail
    if not ctx.brand.is_official_host(host):
        if not verified:
            ctx.card.add("tls_invalid", f"{host}: {error}")
        if nb and (utcnow() - nb).days < 14:
            ctx.card.add("tls_new_cert", f"certificate issued {nb.date().isoformat()}")
    ctx.evidence.append(EvidenceItem("tls_certificate", detail))
    return ctx.ran("tls", **detail)
