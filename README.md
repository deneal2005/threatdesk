# ThreatDesk

Brand-protection case desk. A company registers what is genuinely theirs (websites, social accounts, Android/iOS
apps, logo, publishers). ThreatDesk finds and investigates what pretends to be them: look-alike domains, phishing pages,
copycat apps, fake support accounts and scam messages reported by customers. Each one becomes an evidence-backed case
that an analyst can triage, confirm and send to a registrar, host or platform as a takedown packet.

`brand profile -> discover -> investigate with evidence -> score and classify -> case workflow -> takedown -> monitor`

It never calls anything "safe". The lowest verdicts are **No strong signals** and **Insufficient data**. Every check
reports `ran`, `not_possible` (with the reason) or `not_configured` (key missing). Architecture, data flow and the
scoring model are in [ARCHITECTURE.md](ARCHITECTURE.md); test and requirement status in
[VERIFICATION.md](VERIFICATION.md).

## The three parts

| Part | What it does | Where |
|---|---|---|
| **Brand profile** | Name, keywords, official websites / social accounts / apps (each verifiable), official app publishers, logo, allow list, look-alike sensitivity. Every investigation and scan reads it; changing it changes results and closes findings it now covers. | `brands.py`, `assets/`, `web/brands.py`, `reconcile.py` |
| **Social-media monitoring** | Scans Bluesky, YouTube, Telegram and (with keys) web search of Instagram/Facebook/X pages; investigates any profile link. Handles, display names and bio links are compared with the shared look-alike engine; account age, audience, verified badge and bio text add context. | `checks/social.py`, `checks/apify.py`, `discovery/` |
| **App-store monitoring** | Searches Google Play and the App Store; investigates listings: title, developer, package/bundle id, permissions, icon vs logo, developer website, description. On Google Play the developer *account* must match an official app before a publisher counts as official. | `checks/apps.py`, `checks/app_common.py`, `discovery/sources.py` |

Monitoring is **scheduled, not real-time**: each brand is scanned every `scan_interval_hours` (default 24) by an
in-process scheduler that ticks every 5 minutes, or by an external caller of `POST /cron/tick`.

## Prerequisites

* Python 3.11 or newer (developed and tested on 3.14; the Docker image uses 3.11).
* PostgreSQL 13 or newer (developed on 16). SQLite is used only by the test suite.
* Outbound HTTPS for the live checks. Without it, checks report `not_possible` and nothing is fabricated.

## Run it locally

```bash
python -m venv .venv
.venv/Scripts/python -m pip install -r requirements.txt      # Windows; use .venv/bin/python elsewhere
cp .env.example .env                                         # then set DATABASE_URL and SECRET_KEY
.venv/Scripts/python -m uvicorn threatdesk.main:app --port 8000 --workers 1
```

Create the database first, for example `createdb threatdesk`. Then open http://localhost:8000, sign up (this creates
an organisation), add a brand and paste a suspicious link. Run **one** process: the job worker, the 5-minute scheduler
and the scam-list refresher run inside the app. The first start downloads the public scam lists in the background
(a few minutes; cached in `.cache/`).

**Database setup** is automatic: at startup the app creates missing tables and adds missing *nullable* columns (an
additive migration, logged as `added missing columns`). It never drops, renames or retypes columns; such changes need a
manual migration. `schema.sql` is the generated reference DDL (`python -m scripts.export_schema`).

**Demo data without the network**: set `DEMO_EMAIL` and `DEMO_PASSWORD` in `.env`, then

```bash
.venv/Scripts/python -m scripts.seed_demo
```

This creates "Demo Org" with the brand "Acme Bank" and replays recorded investigations from the offline test fixtures.
Every seeded finding shows the source **Demo fixture**, so it is never mistaken for a live result.

## Tests

```bash
.venv/Scripts/python -m pip install -r requirements-dev.txt
.venv/Scripts/python -m pytest
```

The suite uses in-memory SQLite and never touches the network: API keys are blanked, HTTP goes to
`httpx.MockTransport`, and the Google Play scraper and DNS are patched with synthetic data. It also enforces CSRF on
every POST route and keeps every module under 300 lines.

`python evaluate.py testset.csv` measures precision and recall on a labelled list (`url,label,brand_optional`). It
uses the live network.

## Configuration

Everything is in `.env` (see `.env.example`). Only `DATABASE_URL` and `SECRET_KEY` are required (`SECRET_KEY` is
mandatory when `ENV=prod`). Each optional key turns on one more source. A missing key shows that check as
"Not configured", never as a fake result. Secrets are read only in `config.py` and are never logged.

| Key | Needed for | Without it |
|---|---|---|
| `DATABASE_URL` | PostgreSQL (`postgresql://` or `postgres://`, Supabase pooler strings work) | the app refuses to start |
| `SECRET_KEY` | session and CSRF signing | dev: random per start (sessions reset); prod: refuses to start |
| `YOUTUBE_API_KEY` | YouTube channel checks, discovery and verification | YouTube shows "Not configured" |
| `APIFY_TOKEN` (+ `APIFY_INSTAGRAM_ABOUT`) | Instagram/TikTok/Facebook profile data (paid per profile, capped at $0.05 a run) | only public preview tags, often a login wall |
| `BRAVE_API_KEY` or `GOOGLE_CSE_KEY` + `GOOGLE_CSE_CX` | web-search discovery of public Instagram/Facebook/X pages | that scan source is "not configured" |
| `SAFE_BROWSING_API_KEY`, `VT_API_KEY`, `URLHAUS_AUTH_KEY` | website reputation checks | those checks are "Not configured" |
| `GEMINI_API_KEY` (`GEMINI_MODEL`) | AI read of each report (labelled; never decides alone, never counts as corroboration) | rules only |
| `PHISHTANK_APP_KEY` | higher PhishTank rate limit | keyless PhishTank |
| `CRON_SECRET` | `POST /cron/tick` for an external scheduler | endpoint answers 503 |
| `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD`, `SMTP_FROM` | email alerts (recipients per organisation in Settings) | in-app and webhook alerts only |
| `PUBLIC_BASE_URL` | absolute links in alerts | relative links |
| `SCAM_LISTS`, `SCAM_LIST_EXCLUDE`, `CACHE_DIR` | public scam lists (OpenPhish is non-commercial only) | on by default |
| `DNS_SERVERS` | resolvers for checks (`system` = OS resolver) | 1.1.1.1, 8.8.8.8 |
| `START_WORKER`, `WORKER_CONCURRENCY`, `JOB_TIMEOUT` | background worker | 3 concurrent jobs, 120 s each |
| `JOB_RETENTION_DAYS` | delete finished scan-lead jobs older than N days (findings and evidence stay; 0 keeps all) | 30 |
| `ENABLE_SCREENSHOTS` | Playwright page screenshots (not installed by default) | off |
| `FORWARDED_ALLOW_IPS` (Docker) | proxies trusted for `X-Forwarded-For` | `*` (suits Render; narrow it elsewhere) |
| `DEMO_EMAIL`, `DEMO_PASSWORD` | demo seed only | seed refuses to run |

Keyless sources: DNS, domain-name rules, RDAP (domain + IP), TLS, Wayback, page fetch and content rules, public scam
lists, PhishTank, certificate transparency (crt.sh), App Store (iTunes API), Google Play (unofficial scraper),
Bluesky, Telegram public pages.

## Detection in brief

* **Look-alike engine** (`lookalike.py`), shared by social, app, discovery and intake code. It normalises names
  (case, Unicode NFKC, confusable and leet characters such as `0→o`, `4→a`, `rn→m` and Cyrillic `а`), strips words
  impersonators add (`support`, `official`, `help`, `kyc`, trailing digits and so on), allows small typos on longer
  names, and reports which technique was used. Short names (under 6 letters) must match exactly after normalisation.
  Sensitivity is set per brand: Strict 90, Balanced 80, Broad 70.
* **Scoring** (`scoring.py`): 60 fixed-point rules, each with evidence, grouped into categories. For websites,
  accounts and apps, **name similarity alone is capped at 35** (Low). It needs corroboration such as a new
  registration, phishing content, a reputation-list hit, a new account, copied logo, look-alike bio link, low ratings
  or dangerous permissions. Absence of data (no archive history, redacted registrant, no TLS) never corroborates, and
  a different publisher is never a signal on its own.
* **Defensive registrations** (`checks/ownership.py`): brands own many look-alikes of themselves (amazonlogin.com,
  amazon.xyz). These count as counter-evidence:
  * a redirect to an official site (the page fetch falls back to plain HTTP when HTTPS doesn't answer, because parked
    domains often only redirect there),
  * registration over a year ago through a corporate brand-protection registrar (MarkMonitor, CSC, Com Laude...),
  * a registrant organisation matching the brand,
  * private nameservers shared with an official domain.

  Such domains are classified *Likely brand-owned*. Scans don't open findings for leads with registration or DNS
  ownership evidence and nothing abusive, and they close earlier open ones. A manual investigation still shows the
  full report.
* **Well-known brands**: when a brand's name and one of its official domains match ThreatDesk's built-in list
  (`constants.KNOWN_BRANDS`, e.g. Amazon with amazon.com), the other domains on that list (amazon.in, amazon.co.uk...)
  count as official too.
* **Classification** (`riskview.py`): *Verified threat* (analyst confirmed), *Malicious indicators*, *Suspicious*,
  *Likely brand-owned*, *Look-alike, unconfirmed*, *No strong signals*, *Insufficient data*, *False positive* or *Official asset*. It comes
  with an evidence-confidence level and shows on the report page, findings list (with a filter), CSV and API.
* **Exclusions**: official assets and allow-list entries are scored 0. Google Play developer names are not verified,
  so a listed publisher name only counts as official when ThreatDesk cannot check the developer account. When it can,
  the account must match an official app's account. Adding an asset or allow-list entry closes the open findings it
  covers, never one an analyst confirmed.
* **Dedupe**: one finding per organisation, brand and asset key (`instagram:acmebank_help`, `android:com.x`,
  `host:x.com`). Re-investigation updates the finding and appends evidence.

## Deployment

`Dockerfile` (Python 3.11, non-root, `/health` healthcheck, single process) and `render.yaml` (Render web service with
a managed `SECRET_KEY` and `CRON_SECRET`) are included. Set `DATABASE_URL` to a PostgreSQL instance.

```bash
docker build -t threatdesk .
docker run -p 8000:8000 -e ENV=prod -e DATABASE_URL=postgresql://user:pass@host:5432/threatdesk -e SECRET_KEY=... threatdesk
```

The image was built and run locally against an empty PostgreSQL 16 container: the healthcheck reported healthy, it
runs as a non-root user on Python 3.11, and signup, brand creation and live Google Play / App Store / Bluesky
investigations worked. With `ENV=prod` the session and CSRF cookies are `Secure`, so the app must be served over
HTTPS (a TLS-terminating proxy such as Render's). Over plain `http://` forms are rejected with 403. Use `ENV=dev`
for local HTTP. **The Render deployment itself has not been run.**

## Known limits

* Google Play data comes from an unofficial scraper: it breaks when Play changes its pages (reported as
  `not_possible`), and search results sometimes lack app ids.
* Instagram, Facebook, X and TikTok profiles need the paid Apify integration or user-supplied details. Without them,
  only public preview tags are read, and those are often a login wall.
* Telegram handle existence is a heuristic (t.me serves a page for any name).
* Logo comparison is a perceptual hash (pHash) against one uploaded logo. It catches copied icons, not redrawn ones.
* Rate limits, scam-list memory, VirusTotal spacing and the Play developer-id cache are per process (run one process).
* No user removal or password reset, no brand deletion, findings list capped at 500, campaigns rebuilt on demand,
  light theme only.
