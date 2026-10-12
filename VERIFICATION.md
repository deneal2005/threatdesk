# Verification report

## Audit and detection upgrade (branch `dev`, 2026-10-12)

`python -m pytest`: **243 passed** (Python 3.14, offline). The suite before the icon test (232) also passed in a clean virtualenv built from
`requirements-dev.txt` in a fresh copy of the tree. Against PostgreSQL 16 the app was verified twice: on an **empty**
database (tables created, signup, brand creation, brand and findings pages) and on the existing development database
(the new `brands.detection` column was added at startup). The Docker image was built and run against an empty
PostgreSQL 16 container (details below). Render was **not** run.

Statuses as below: **Verified** = test passed and exercised against the running app; **Tested** = automated tests
with synthetic fixtures; **Not verified** = needs something unavailable here.

### Defects found and fixed

| # | Defect (observed, not inferred) | Fix | Test |
|---|---|---|---|
| 1 | A handle or display name resembling the brand reached **Medium risk on name similarity alone** (`acmeb4nk` + "Acme Bank" = 45) | Identity-only cap at 35 for accounts and apps (`scoring.assess`); the report says why | `test_social_detection::test_name_similarity_alone_is_not_medium_risk`, `test_app_detection::test_lookalike_title_alone_stays_low` |
| 2 | Common impersonation handles missed: `acme_bank_support`, `acmebankofficial`, `acmebank_`, `a_c_m_e_bank`, `acrnebank` | Shared look-alike engine (`lookalike.py`) | `test_lookalike` (21 cases) |
| 3 | Any app whose title contained a keyword got `app_impersonation` (+30): "ACME Anvil Game", "Acme Plumbing Calculator" | Title matching through the engine; a keyword inside other words is a recorded weak mention, not scored | `test_app_detection::test_unrelated_app_with_other_publisher_gets_no_identity_signal` |
| 4 | **A Play developer named exactly like a listed publisher was excluded as official.** Play developer names are not verified | The developer *account id* must match an official app's account; the same name on another account becomes evidence | `test_copied_publisher_name_on_another_account_is_not_official`, `test_same_developer_account_is_official_even_if_unlisted` |
| 5 | An asset added to the brand (or allow-listed) after its finding was opened **stayed open forever**: scans skipped it without updating it | `reconcile.py` closes covered open findings on asset/allow-list changes and on excluded scan leads; never one an analyst confirmed | `test_findings_lifecycle` (3 tests) |
| 6 | Most iOS listings were **"Insufficient data"**: apps needed 4 checks, an App Store listing without logo/website can run 2 | Apps need 2 checks (the listing read is the main evidence) | `test_ios_lookalike_and_official_seller` |
| 7 | Customer-reported messages with clear scam text (score 65) were **"Insufficient data"** without an AI key | Text reports need 1 check | `test_intake::test_text_report_with_signals_gets_a_verdict_without_ai`; seen live on the demo data |
| 8 | Official handles starting with "uc" were skipped by handle matching (meant to skip YouTube channel ids) | Platform ids are detected by pattern (`is_platform_id`) | `test_lookalike::test_platform_ids_are_not_names` |
| 9 | One failing Google Play or App Store search term failed the whole discovery source; Play scraper exceptions became "internal error" | Per-term isolation; failures are named; malformed or empty listings are reported plainly | `test_scraper_failures_do_not_crash`, `test_ios_store_errors_are_explicit` |
| 10 | The finished job queue grew without limit (~100 scan-lead jobs per brand per scan) | `JOB_RETENTION_DAYS` purge of finished scan-lead jobs (findings, evidence, scans and manual investigations kept) | `test_monitoring::test_old_background_jobs_are_purged_but_history_is_kept` |
| 11 | New columns needed a manual `ALTER TABLE` on existing databases | Additive migration of nullable columns at startup | `test_missing_nullable_columns_are_added`; Verified on PostgreSQL |
| 12 | Test-only packages (pytest) were installed in the production image | `requirements-dev.txt` | clean install |
| 13 | **Defensive registrations scored as scams**: `amazonlogin.com` = 75 (High). The page fetch tried HTTPS only, so its plain-HTTP redirect to www.amazon.com was never seen; "contains the brand" was counted twice; the AI scored the name alone | HTTP fallback; ownership counter-evidence (brand-protection registrar, registrant, shared nameservers); single count; AI points only with page content; name-only cap for websites; scans close brand-owned leads | `test_ownership` (10 tests); live re-run below |
| 14 | Absence of data (no archive, redacted registrant, no TLS, 1 VirusTotal engine) lifted name-only domains to Medium | these never corroborate a name match | `test_name_only_website_is_capped`, `test_one_virustotal_engine_does_not_corroborate_a_name` |
| 15 | Network outages made of timeouts were saved as degraded findings that overwrote good evidence | timeouts count towards outage detection (the job retries instead) | `test_timeouts_count_towards_a_network_outage` |
| 16 | A well-known brand's other official domains (amazon.in) were findings | built-in official domains when the brand's name and a listed domain match `KNOWN_BRANDS` | `test_well_known_brand_gets_its_built_in_official_domains` |

**Live re-run of the "amazon" brand** (60 domain findings from a discovery scan, re-investigated against the real
network on 2026-10-12): before, 26 were Medium or High (e.g. amazonlogin.com 75, amazon-login.com 100, amazon.shop
100). After: 49 closed automatically as likely brand-owned, each citing a MarkMonitor or Com Laude registration and,
for most, a redirect to an official Amazon site; amazon.in excluded as an official Amazon domain. Of the 10 still
open, 4 are *Conflicting evidence* (VirusTotal engines flag a MarkMonitor-registered domain that redirects to
amazon.com), 2 are redirect-only *Likely brand-owned*, 3 are *Look-alike, unconfirmed*, and 1 is *Suspicious*:
amazon.io (40) redirects to aboutamazon.eu, which is not on any official list and whose `.io`/`.eu` registries
publish no RDAP to check.

### Requirement mapping

| Requirement | Implementation | Tests | Status |
|---|---|---|---|
| Brand profile drives detection | `BrandContext` (name, keywords, handles, apps, app names, publishers, logo, allow list, sensitivity) loaded per job | `test_brand_profile_changes_affect_detection`, `test_brand_sensitivity_is_validated_saved_and_used` | Verified (sensitivity saved and shown live) |
| Profile input validation | `parse_brand_settings`, `assets/forms.py` | `test_brands`, `test_assets`, sensitivity test | Tested |
| Official social accounts excluded | `exclusion()`, `social_signals` | `test_official_accounts_are_excluded`, `test_official_bluesky_account_is_excluded` | Tested |
| Official apps excluded | `exclusion()`, `play_publisher`, `_seller_official` | `test_official_play_app_is_excluded`, `test_ios_lookalike_and_official_seller` | Tested |
| Look-alike names (substitution, spacing, added/removed words, typos) | `lookalike.py` | `test_lookalike`, social/app tests | Tested |
| Unrelated legitimate names not high risk | engine + identity gate | `test_unrelated_legitimate_names_get_nothing`, `test_unrelated_names_are_not_lookalikes` | Tested |
| Publisher mismatch weighed with other evidence | publisher is context in the title evidence; never a signal alone | `test_lookalike_title_alone_stays_low`, `test_copied_publisher_name_on_another_account_is_not_official` | Tested |
| Logo/icon similarity | pHash of the app icon (or a user-supplied profile photo) vs the brand logo; skipped for official apps | `test_icon_matching_the_logo_is_flagged_only_when_not_official` (added: no earlier test covered it) | Tested (live: the demo brand has no logo, so it did not run) |
| Contextual risk (age, audience, badge, bio links, text) | `social_signals` | `test_corroborated_impersonation_reaches_high`, `test_counter_evidence_for_established_or_verified_accounts` | Verified (live Bluesky profile: established-account counter-evidence) |
| Evidence-backed findings (URL, indicators, confidence, explanation) | signals with evidence, `riskview` confidence and classification, append-only evidence | `test_report_page_list_api_and_csv_show_the_classification` | Verified (report page live) |
| Verified threats vs suspicious vs false positives | `riskview.classify`, list filter | `test_classification_tiers_and_confidence` | Verified (findings list live) |
| Missing data / source failures don't crash | `run_check`, per-source isolation | Bluesky 503/malformed, iTunes 500/HTML, Play exceptions, Telegram unreachable | Tested |
| Duplicates handled consistently | dedupe key + unique constraint; case-insensitive handles | `test_duplicates_update_one_finding_and_evidence_is_kept`, `test_handle_dedupe_key_is_case_insensitive` | Tested |
| Findings and scan history persist | `persistence.py`, jobs table | lifecycle tests, `test_discovery`, `test_jobs` | Verified (PostgreSQL) |
| Scores consistent with evidence | `assess()` used by investigation, rescore and web search | `test_rescore_applies_the_identity_gate` | Tested |
| Existing functionality intact | all 180 original tests still pass (5 assertions updated for deliberate changes, listed below) | full suite | Tested |
| Live sources | Google Play, App Store and Bluesky investigated live through the UI (WhatsApp listings, bsky.app) | none (live) | Verified |
| Architecture diagram | `ARCHITECTURE.md` (Mermaid; rendered with Mermaid 10.9.1 without errors) | none | Verified |
| Deployment (Docker) | `Dockerfile` | `docker build`; run with an empty `postgres:16-alpine`: healthcheck healthy, non-root user `app`, Python 3.11.17, CSP header and `Secure`/`HttpOnly` cookies in prod; signup, brand creation and live Play / App Store / Bluesky investigations in the container (ENV=dev over plain HTTP) | Verified |
| Deployment (Render) | `render.yaml` | none | **Not verified** |

Original assertions changed on purpose: rule count 52 → 57 (`test_scoring`), the discovery skip result has
`closed_existing` (`test_discovery`), and the cron tick returns `purged_jobs` (`test_monitoring`, 2 assertions).

### Still incomplete or limited

* **Instagram, Facebook, X and TikTok** need `APIFY_TOKEN` (paid) or user-supplied details. The YouTube API, web
  search and reputation APIs need keys. None of these ran live here.
* **Logo similarity** is only a perceptual hash against a single logo. There is no comparison with official app icons
  and no detection of redrawn logos.
* **Google Play** depends on an unofficial scraper. Developer-account confirmation needs that scraper to return
  `developerId`; when it can't, the listed-publisher name rule applies and the risk remains.
* **Monitoring is scheduled** (default every 24 h), not real-time. There is no change detection between scans beyond
  "new finding" alerts.
* The Render deployment has not been run. With `ENV=prod` the app needs HTTPS (cookies are `Secure`; over plain HTTP
  every form POST is rejected with 403).

---

# Original rebuild report (2026-10-12)

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
