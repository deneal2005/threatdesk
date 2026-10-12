# ThreatDesk architecture

Everything below exists in the code. Optional sources only run when their key is set; without it the check is
recorded as `not_configured` and never produces a result.

## Data flow

```mermaid
flowchart TB
  subgraph Profile["Brand profile (PostgreSQL)"]
    BP["brands: name, keywords, publishers,<br/>logo pHash, detection.sensitivity"]
    AS["brand_websites / brand_social_accounts / brand_apps<br/>(source of truth, verifiable)"]
    WL["assets_whitelist (allow list)"]
    AS -- "assets/store.sync_index()" --> BP
  end

  subgraph Inputs["How leads arrive"]
    UI["Investigate page / API<br/>(one URL)"]
    INT["Public report form<br/>(link and/or text)"]
    SCH["Scheduler tick (5 min, in-process)<br/>or POST /cron/tick"]
  end

  subgraph Discovery["Discovery scan (discovery/scan.py) — every source isolated, 100 s budget"]
    D1["Look-alike domains<br/>(permutations + DNS)"]
    D2["Certificate transparency<br/>(crt.sh)"]
    D3["App Store search<br/>(iTunes Search API)"]
    D4["Google Play search<br/>(google-play-scraper, unofficial)"]
    D5["YouTube search<br/>(YOUTUBE_API_KEY)"]
    D6["Bluesky search<br/>(public API)"]
    D7["Telegram handle probes<br/>(t.me public pages)"]
    D8["Web search of IG/FB/X pages<br/>(BRAVE_API_KEY / GOOGLE_CSE_*)"]
  end

  Q[("jobs table<br/>queue, retries, backoff")]
  W["Worker (worker.py)<br/>claims jobs atomically"]

  subgraph Engine["Investigation (investigator.py)"]
    LD["linkdetect: normalise URL,<br/>kind + dedupe key"]
    EX{"exclusion():<br/>official asset or<br/>allow-listed?"}
    subgraph Collect["Collection (checks/*) — each check: ran | not_possible | not_configured"]
      CW["Website: DNS, RDAP, TLS, Wayback,<br/>page fetch (HTTPS, then HTTP fallback; SSRF guard),<br/>reputation lists, CT"]
      CA["Apps: Play listing + permissions,<br/>App Store lookup, icon vs logo, developer site"]
      CS["Social: YouTube API, Bluesky API, Telegram page,<br/>public OG tags, Apify (APIFY_TOKEN)"]
    end
    LA["lookalike.py (shared):<br/>normalise, confusables/leet, affix stripping,<br/>Damerau-Levenshtein, containment"]
    OWN["checks/ownership.py: brand-protection registrar,<br/>registrant, shared nameservers"]
    SIG["Signals (scoring.RULES, 60 rules)<br/>each with evidence text"]
    AS2["scoring.assess(): sum → 0-100,<br/>category breakdown,<br/>identity-only cap for accounts/apps"]
    PUB["Play publisher check:<br/>developer account id vs official apps"]
  end

  subgraph Store["Persistence (persistence.py)"]
    F["findings (unique per org + brand + dedupe key)"]
    E["evidence (append-only, SHA-256)"]
    S["signals + check_results (latest run)"]
    I["indicators → campaigns"]
    CE["case_events (audit trail)"]
  end

  RV["riskview.py: classification<br/>(verified threat / malicious indicators / suspicious /<br/>likely brand-owned / look-alike / false positive / official)<br/>+ confidence"]
  OUT["Findings UI, report page, CSV, JSON API,<br/>alerts (in-app, webhook, SMTP)"]
  REC["reconcile.py: asset added / allow-listed →<br/>close open findings it covers"]

  SCH --> Q
  UI --> Q
  INT --> Q
  Q --> W
  W -->|scan| Discovery
  Discovery -->|"candidate URLs → investigate jobs"| Q
  D8 -->|"search-result findings (labelled)"| F
  W -->|investigate| LD --> EX
  EX --> Collect
  BP --> EX
  WL --> EX
  Collect --> LA --> SIG
  CA --> PUB --> EX
  CW --> OWN --> SIG
  Collect --> SIG --> AS2
  AS2 --> F
  Collect --> E
  SIG --> S
  Collect --> I
  F --> RV --> OUT
  AS --> REC --> F
  WL --> REC
  REC --> CE
```

## Components

| Layer | Module | Notes |
|---|---|---|
| Collection | `checks/*.py`, `discovery/sources.py`, `discovery/websearch.py` | Each check returns `ran`, `not_possible` (reason) or `not_configured`. Timeouts, HTTP errors, malformed JSON and scraper exceptions become `not_possible`; one failing source never stops a scan. |
| Normalisation | `linkdetect.py`, `lookalike.basic/skeleton` | URLs normalised and given a dedupe key (`instagram:acmebank_help`, `android:com.x`, `host:x.com`); names case-folded, NFKC, confusable and leet characters mapped. |
| Matching | `lookalike.py` | One engine for handles, display names, app titles, developer names, package ids, bio links and intake messages. Returns a score and the techniques used (substitution, added words, spacing, typo). |
| Risk assessment | `scoring.py`, `riskview.py` | Rules carry fixed points and a category. `assess()` caps accounts/apps whose only evidence is name similarity at 35. `riskview` adds the classification and evidence confidence. |
| Exclusion | `investigator.exclusion`, `checks/apps.play_publisher`, `checks/ownership.py`, `reconcile.py` | Official assets (listed, or on the built-in list of a well-known brand the profile matches) and allow-list entries score 0. Defensive registrations get counter-evidence and are classified *Likely brand-owned*; scans don't open findings for them. On Google Play the developer *account id* must match an official app (names are not verified). Findings covered by later profile changes are closed automatically (never one an analyst confirmed). |
| Persistence | `persistence.py`, `models/*` | Findings are unique per org + brand + dedupe key; re-investigation updates the row, evidence is appended. |
| Orchestration | `jobs.py`, `worker.py`, `monitoring.py` | Database job queue with atomic claims, retry with backoff, outage detection (retry instead of saving an empty finding), scheduled scans, retention of background jobs (`JOB_RETENTION_DAYS`). |
| Presentation | `web/*`, `templates/*` | Server-rendered, strict CSP, CSRF on every POST, HTMX polling only. |

## Scoring and classification

* **Signals** come from rules in `scoring.RULES`; each fires at most once per investigation and carries the evidence
  that triggered it.
* **Categories:** name similarity (identity), copied branding, content and behaviour, reputation lists, account and
  registration context, counter-evidence, AI (bounded, labelled).
* **Identity gate (websites, accounts and apps):** when name similarity is the only evidence (corroborating evidence
  below 10 points), the score is capped at 35 and the report says so. The AI read doesn't count as corroboration,
  and neither does absence of data (no archive history, redacted registrant, no TLS). A different publisher is never
  a signal on its own.
* **Counter-evidence:** redirects to an official site, a corporate brand-protection registrar, a registrant matching
  the brand, private nameservers shared with an official domain, an established or platform-verified account.
* **Severity:** High at 70, Medium at 40. Verdicts never say "safe": the lowest are *No strong signals* and
  *Insufficient data*.
* **Classification** (`riskview.classify`): *Verified threat* (analyst confirmed), *Malicious indicators*
  (reputation hit, or credential phishing while posing as the brand), *Suspicious* (score 40+), *Look-alike,
  unconfirmed* (name only), *No strong signals*, *Insufficient data*, *False positive*, *Official asset*.
* **Confidence:** High with two or more independent kinds of evidence (or a reputation hit), Medium with one, Low with
  name-only evidence, too few checks, or user-supplied / search-result data.

## Data sources and freshness

| Source | Access | Freshness |
|---|---|---|
| DNS, RDAP, TLS, Wayback, page fetch, crt.sh, PhishTank, public scam lists | keyless public endpoints | live per investigation (scam lists cached on disk, refreshed in the background) |
| Google Play | `google-play-scraper` (unofficial; breaks when Play changes its pages) | live; official developer ids cached 24 h in-process |
| App Store | iTunes Lookup / Search API | live |
| Bluesky, Telegram public pages | public | live (Telegram existence is a heuristic) |
| YouTube | Data API v3 (`YOUTUBE_API_KEY`) | live |
| Instagram / TikTok / Facebook | Apify actors (`APIFY_TOKEN`, paid), else public OG tags (often a login wall) | live; Apify results cached 24 h in-process |
| Web search | Brave / Google CSE keys | live; findings labelled "FROM SEARCH RESULTS" |
| Demo data | `scripts/seed_demo.py` | synthetic, labelled "Demo fixture" |

Every finding shows when it was last checked, and every check shows whether it ran.
