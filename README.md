# ThreatDesk

Brand-protection case desk. A company registers what is genuinely theirs (websites, social accounts, Android/iOS
apps, logo). ThreatDesk finds and investigates what pretends to be them: look-alike domains, phishing pages, copycat
apps, fake support accounts and scam messages reported by customers. Each one becomes an evidence-backed case that an
analyst can triage, confirm and send to a registrar, host or platform as a takedown packet.

`detect -> triage -> investigate with evidence -> case workflow -> takedown packet -> monitor again`

It never calls anything "safe". The lowest verdicts are **No strong signals** and **Insufficient data**. Every check
reports `ran`, `not_possible` (with the reason) or `not_configured` (key missing).

This repository is a from-scratch rebuild made from the ThreatDesk reconstruction blueprint (docs only; the original
source was not used).

## Run it locally

Needs Python 3.11+ (built and tested on 3.14) and PostgreSQL (any recent version).

```bash
python -m venv .venv
.venv/Scripts/python -m pip install -r requirements.txt      # Windows; use .venv/bin/python elsewhere
cp .env.example .env                                         # then set DATABASE_URL and SECRET_KEY
.venv/Scripts/python -m uvicorn threatdesk.main:app --port 8000 --workers 1
```

Open http://localhost:8000, create an organisation, add a brand, paste a suspicious link.
Run **one** process: the job worker, the 5-minute scheduler and the scam-list refresher live inside the app.
The first start downloads the public scam lists in the background (a few minutes; cached in `.cache/`).

**Demo data without the network**: set `DEMO_EMAIL` and `DEMO_PASSWORD` in `.env`, then

```bash
.venv/Scripts/python -m scripts.seed_demo
```

This creates "Demo Org" with the brand "Acme Bank" (2 websites, 5 accounts, 2 apps) and replays five recorded
investigations from the offline test fixtures, plus one confirmed case and a campaign. Every seeded finding shows the
source **Demo fixture** so it is never mistaken for a live result. It does nothing if Demo Org already exists.

## Tests

```bash
.venv/Scripts/python -m pytest
```

The suite uses in-memory SQLite and never touches the network (API keys are blanked; network calls go to
`httpx.MockTransport` and patched DNS). It also enforces CSRF on every POST route and keeps every module under 300 lines.

## Configuration

Everything is in `.env` (see `.env.example`). Only `DATABASE_URL` and `SECRET_KEY` are required. Each optional key
turns on one more check; a missing key shows that check as "Not configured", never as a fake result.

| Key | Adds |
|---|---|
| `GEMINI_API_KEY` | AI read of each report (labelled, capped at +15 points, never decides alone) |
| `SAFE_BROWSING_API_KEY`, `VT_API_KEY`, `URLHAUS_AUTH_KEY` | reputation checks |
| `YOUTUBE_API_KEY` | YouTube channel checks, discovery and verification |
| `BRAVE_API_KEY` or `GOOGLE_CSE_KEY` + `GOOGLE_CSE_CX` | web-search discovery of public profile pages |
| `APIFY_TOKEN` | Instagram/TikTok/Facebook profile reads (paid per profile, capped at $0.05 a run) |
| `CRON_SECRET` | `POST /cron/tick` for an external scheduler |
| `SMTP_*` | email alerts (webhooks are set per organisation in Settings) |

Keyless checks: DNS, domain-name rules, RDAP (domain + IP), TLS, Wayback, page fetch and content rules, public scam
lists, PhishTank, certificate transparency, App Store, Google Play, Bluesky, Telegram.

## How it fits together

* FastAPI + server-rendered Jinja2 + HTMX (polling only), no custom JavaScript, strict CSP.
* PostgreSQL via SQLAlchemy 2; tables are created at startup (no migrations).
* Jobs table as the queue; an in-process asyncio worker claims jobs atomically and retries with backoff.
* Outbound fetches go through an SSRF guard: public IPs only, pinned connections, re-validated redirects, size caps.
* 52 explainable scoring rules (`threatdesk/scoring.py`); score 0-100, High at 70, Medium at 40.
* Evidence rows are append-only and hashed; takedown contacts come only from RDAP and `contacts.yaml`.

`python evaluate.py testset.csv` measures precision and recall on a labelled list (`url,label,brand_optional`).

## Differences from the original (deliberate)

* Cosmetic bugs D1-D8 from the blueprint are fixed (rule names keep their capitals, real disclosure chevrons,
  labels for every evidence kind, flex section heads, no stacked-card offset in grids, 3-field app form on one row,
  every check in the display order, recent investigations kept after an input error).
* The worker claims only job types it knows (`claim_next(types=HANDLERS)`), so an older process sharing the database
  cannot fail newer jobs.
* Network-outage detection counts failures against the checks that were attempted (not-configured checks never touch
  the network), so an outage is still detected when few API keys are set.
* Phone numbers and handles inside WhatsApp/Telegram links on a page are extracted as indicators (they are what
  campaign correlation needs most).
* A demo seed script (`scripts/seed_demo.py`) replays offline fixtures, labelled "Demo fixture".

## Known limits

No user removal or password reset, no brand deletion, no migrations (column changes on an existing database need a
manual `ALTER TABLE`), findings list capped at 500, campaigns rebuilt on demand only, light theme only. Rate limits,
scam-list memory and VirusTotal spacing are per process (run one process). Docker/Render deployment files are included
but were not verified.
