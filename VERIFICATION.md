# Verification report (rebuild from the blueprint, 2026-10-12)

Built from the blueprint documents only (the original source bundle was not used). Python 3.14, PostgreSQL 16 on
port 5434 for development, in-memory SQLite for tests.

Statuses: **Verified** = a test passed *and* it was exercised against the running app (browser or HTTP, live network
where relevant). **Tested** = automated tests pass (offline fixtures). **Implemented** = built, not separately tested.
**Not verified** = needs something not available here (keys, Docker, SMTP relay).

## Test results

`python -m pytest`: **180 passed** (about 30 s, offline). Every feature area of the original suite has tests; the
original's 313 individual tests were not available, so the coverage is equivalent by area, not test for test.

## Acceptance criteria (blueprint 09 §2)

| # | Criterion | Status | How |
|---|---|---|---|
| AC1 | Clean install, `/health` ok | Verified | fresh venv + empty database, `create_all` made the 19 tables; generated DDL identical to the original `schema.sql` |
| AC2 | Signup / login / wrong password / 6th login refused | Verified | browser + `test_auth` |
| AC3 | Other org gets 404 on every id | Tested | isolation tests for brands, assets, findings, jobs, API, keys, campaigns, reports |
| AC4 | POST without token 403, HTMX polling works | Verified | route enumeration test; HTMX polling seen live on the job page and asset list |
| AC5 | Brand quick start 3/4/2 records, first site primary | Verified | browser (3 sites, 10 accounts, 3 apps) + `test_assets` |
| AC6 | Duplicate account refused, same platform different handle added, edits isolated | Tested | `test_assets` |
| AC7 | Website investigation report with rail, ledger, checks, indicators, evidence | Verified | live: `acmebank.co` -> Medium risk, 9 of 14 checks ran (same failures as the original screenshot) |
| AC8 | Never "safe" | Tested | verdict set, rules text, CSV/API derive from verdicts |
| AC9 | Official domain -> "Official/whitelisted asset", score 0 | Tested | `test_investigator` |
| AC10 | Outage retries, no empty finding saved | Tested | `test_jobs::test_outage_retries_instead_of_saving` |
| AC11 | Save -> triage -> status changes with reasons -> timeline | Verified | browser save + case page; `test_cases` |
| AC12 | Bulk false positive + allow list | Tested | `test_cases` |
| AC13 | Scan lists every source with its own status | Verified | live scan: 8 sources, crt.sh 502 isolated, 103 leads queued, discovery findings + alerts created |
| AC14 | Public report without login -> receipt R-id, two jobs, "reported" finding | Verified / Tested | live receipt R-1 with both jobs queued; finding creation tested offline |
| AC15 | New Medium/High scan finding -> in-app alert + webhook, own org only | Tested | in-app alerts seen live; webhook delivery mocked (no Slack URL here) |
| AC16 | Takedown packet: RDAP contacts or "No contact available", `.txt` | Verified | browser packet (demo data) + `test_takedown` |
| AC17 | Shared phone forms a campaign; CDN/parking never do | Verified | demo campaign linked by phone + UPI; skip lists tested |
| AC18 | CSV defanged + formula-safe; API needs a key, org-scoped | Verified | live API call with a new key (200) and without (401); CSV tests |
| AC19 | TXT record -> Verified; bio link alone stays unverified | Tested | fake DNS/pages; live negative path shows the original's exact note |
| AC20 | Screens match the screenshots; 375 px without horizontal scroll | Verified | compared login, signup, overview, investigate, running job, report, case, brands, brand tabs, takedown, campaigns, settings, summary, public form; 375 px case page scroll width = 375 |

## Parity matrix (blueprint 09 §3)

| Feature | Status | Notes |
|---|---|---|
| Config + Postgres-only + health | Verified | |
| Security headers, CSP, 413 body limit | Tested | `test_auth`, `test_hardening` |
| Signup / login / logout / teammates | Verified | no user removal or password reset (as in the original) |
| CSRF on every POST | Tested | enumeration test |
| Tenant isolation | Tested | |
| Brands list / create / settings / logo | Verified | logo re-encoded, pHash stored |
| Websites / accounts / apps records | Verified | D6 form wrap fixed |
| Allow list | Tested | |
| Link detection + normalisation | Tested | |
| SSRF-safe fetch | Tested | pinning, redirect re-validation, size cap, private ranges |
| Website checks (DNS ... CT) | Verified | live runs on example.com, acmebank.co and 10+ scan leads |
| Brand-independent rules | Tested | `test_generic` (fewer cases than the original's 62) |
| Scoring + verdict + rail | Verified | D1 capitalisation fixed |
| AI layer | Tested | mocked only: no Gemini key here (Not verified live) |
| App checks (Play, App Store) | Implemented | live Play/App Store search seen in the scan; per-app investigation not run live |
| Social checks + Apify | Tested | Apify mocked; Telegram probing seen live in the scan |
| Job queue + worker + outage retry | Verified | live worker processed investigations, scans and verification jobs |
| Persistence / dedupe / append-only evidence | Tested | |
| Investigate UI + polling + save + delete | Verified | |
| Findings list / filters / bulk | Tested | list seen in the browser |
| Case workflow + timeline | Verified | |
| Overview metrics | Verified | D4 fixed |
| Discovery scan | Verified | |
| User-supplied profile details | Tested | |
| Public intake | Verified | |
| Monitoring / cron / alerts | Tested | cron endpoint and tick tested; SMTP Not verified (as in the original) |
| Takedown packet | Verified | screenshot route present (off by default); Playwright Not verified |
| Campaigns | Verified | manual rebuild only (as in the original) |
| Reports / CSV / brand summary | Verified | D5 fixed |
| API | Verified | |
| Settings page | Verified | |
| Asset verification | Tested | live negative path verified |
| Scam lists | Verified | downloaded and matching live (`scam_list_hit` on a scan lead) |
| Evaluation script | Tested | |
| Docker / Render | Not verified | files included; Docker Desktop is not running here (also never verified in the original) |
| Design system + pages | Verified | `app.css` copied verbatim plus a small, labelled fix block |

## Deliberate differences from the original

1. Cosmetic bugs D1-D8 fixed (blueprint 11 #2).
2. Worker claims only job types it knows (11 #3).
3. Outage detection counts failures against attempted checks (not-configured checks excluded), so it still works
   with few API keys.
4. Indicators are also taken from WhatsApp/Telegram links on a page (phones in `wa.me/...`).
5. YouTube video links dedupe as `youtube:video:<id>` instead of all collapsing into `host:youtube.com`.
6. A labelled demo seed (`scripts/seed_demo.py`, 11 #1 / playbook C1).

## Bugs found and fixed during the rebuild

* Legacy brand migration wiped the JSON handle lists before migrating them (first asset write rebuilt the index).
* Verification compared asset ids across tables, so website #1 was skipped when checking app #1 or account #1.
* Assignment events were defanged in the timeline (`a@example[.]com`).
* RDAP lookups refused by the SSRF guard showed as "internal error" instead of a plain reason.
* Certificate-history network failures were swallowed, hiding outages.

## Known gaps and what would close them

| Gap | To close it |
|---|---|
| AI read, Safe Browsing, VirusTotal, URLhaus, YouTube, web search, Apify never ran live | add the keys to `.env` (they are optional; each shows "Not configured" until then) |
| Slack/Discord alert and SMTP email not sent live | add a webhook in Settings -> Alerts and press "Send test alert"; set `SMTP_*` |
| Positive live verification of a website | add the TXT record shown on the Websites tab to a domain you control |
| Docker image | start Docker Desktop, `docker build .`, check `/health` |
| Original's 313 individual tests | not available; 180 tests cover the same areas |
| Known detection limits (blueprint 11 #6, #7) | e.g. loose brand names inside ordinary words (`theledger.com`); a test documents it |
