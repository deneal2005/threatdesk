# ThreatDesk — System Architecture Specification

**Product:** ThreatDesk (Digital Risk Protection Platform)  
**Challenge:** ByteXL HacXLerate 2026 — Social & App Monitoring  
**Target:** Brand Impersonation, Fake Social Profiles, Counterfeit Mobile Apps  

---

## 1. High-Level Architecture Diagram

```mermaid
flowchart TD
    subgraph Ingestion["1. Multi-Channel Ingestion & Scanners"]
        A1["Google Play Store<br/>(Scraper API)"]
        A2["Apple App Store<br/>(iTunes Lookup API)"]
        A3["Social Networks<br/>(Telegram, Bluesky, YouTube, OpenGraph, Apify)"]
        A4["Discovery Engine<br/>(Look-alike permutations, CT logs, Web search)"]
        A5["Customer Intake<br/>(/report/token public portal)"]
    end

    subgraph Security["2. Network Security & SSRF Guard"]
        SG["SSRF Guard (threatdesk/safety.py)<br/>• Blocks 10.0.0.0/8, 127.0.0.0/8, 192.168.0.0/16<br/>• Blocks AWS metadata 169.254.169.254<br/>• Size caps (2 MB) & pinned redirect validation"]
    end

    subgraph Gate["3. Ground-Truth Exclusion Gate"]
        EG{"Is Official Asset /<br/>Whitelisted?<br/>(threatdesk/brands.py)"}
        EXCL["FORCED EXCLUSION<br/>• Score: 0<br/>• Severity: Low<br/>• Verdict: Official Asset<br/>• Alerts Suppressed"]
    end

    subgraph Analysis["4. Explainable Detection & Scoring Engine"]
        LAK["Look-Alike Classifier (threatdesk/lookalike.py)<br/>• Adjacent character swaps<br/>• Extra / Missing letters<br/>• Hyphen / spacing differences<br/>• Added suspicious words (support, official)<br/>• Look-alike symbols (homoglyphs)"]
        VIS["Visual Match (threatdesk/images.py)<br/>• Perceptual logo hashing (pHash)<br/>• Icon Hamming distance ≤ 10"]
        APP["App Store Inspector (threatdesk/checks/apps.py)<br/>• Unlisted developer identity<br/>• Free email (gmail.com, etc.)<br/>• Dangerous permissions (SMS, accessibility)"]
        SC["52 Explainable Rules (threatdesk/scoring.py)<br/>• Deterministic point ledger<br/>• Capped at 100 points<br/>• High (≥70), Med (≥40), Low (<40)"]
    end

    subgraph Persistence["5. Forensic Ledger & Database"]
        DB[("PostgreSQL Database<br/>• Multi-tenant isolated (scoped)<br/>• 19 Relational Entities")]
        EV["Append-Only Evidence<br/>• SHA-256 hashed captures<br/>• Full request/response payloads"]
    end

    subgraph Delivery["6. Interfaces & Remediation"]
        UI["Web Workstation (FastAPI + Jinja2 + HTMX)<br/>• Case dossier, score rail, triage actions"]
        API["Scoped REST API (/api/v1/findings)<br/>• Bearer key authentication, defanged JSON"]
        TD["Takedown Generator (threatdesk/takedown.py)<br/>• RDAP registrar contacts & RFC-compliant packet"]
    end

    Ingestion --> SG
    SG --> EG
    EG -- "YES (Matches Official)" --> EXCL
    EG -- "NO (Suspicious Target)" --> Analysis
    Analysis --> LAK & VIS & APP --> SC
    SC --> DB
    SC --> EV
    DB --> UI & API & TD
    EXCL --> UI & DB
```

---

## 2. Core Subsystems

### A. Ground-Truth Exclusion Gate (Zero False-Positive Guarantee)
Before any target is scored or alerted, it must pass through the `BrandContext` evaluation gate:
1. **Domain:** Host matches registered `official_domains` or active `AssetWhitelist` domain.
2. **Social:** Platform handle matches `official_handles` for that platform.
3. **App:** Android package name or iOS store ID matches `official_apps`.
4. **Publisher:** App developer name, website domain, or developer email domain matches `official_publishers`.
*Outcome if matched:* Score is forced to **0**, verdict to `"Official/whitelisted asset"`, and no notifications are dispatched.

### B. Explainable Look-Alike Classification Engine
Located in [`threatdesk/lookalike.py`](file:///home/amrit/Projects/C3/threatdesk/threatdesk/lookalike.py), this engine evaluates candidates against brand assets using Damerau-Levenshtein distance, token permutation analysis, and homoglyph mapping:
* **Adjacent Letter Swaps:** Detects transpositions (e.g. `Acme Bnak` $\rightarrow$ `bnak` instead of `bank`).
* **Hyphen / Spacing Variations:** Detects delimiter obfuscation (e.g. `ac-mebank` vs `acmebank`).
* **Added Suspicious Terms:** Identifies prefixes and suffixes targeting brand authority (e.g. `official`, `support`, `verify`, `helpdesk`, `kyc`).
* **Homoglyphs & Leetspeak:** Identifies visual look-alikes (`0` for `o`, `1` for `l`/`i`, `3` for `e`).

### C. Visual Identity Perceptual Hashing
Located in [`threatdesk/images.py`](file:///home/amrit/Projects/C3/threatdesk/threatdesk/images.py):
* Computes DCT-based 64-bit perceptual hash (`pHash`) for uploaded brand logos.
* Downloads candidate app icons and computes perceptual Hamming distance.
* Flags `icon_matches_logo` (+30 points) if distance $\le 10$, pinpointing visual brand theft even if names differ slightly.

### D. Security Boundaries & Defanging
* **Defanging:** In [`threatdesk/safety.py`](file:///home/amrit/Projects/C3/threatdesk/threatdesk/safety.py), all malicious URLs and hostnames are defanged before display in UI, API responses, or CSV exports (`hxxps://`, `[.]` delimiters, stripping `=+-@` formula injection characters).
* **Strict CSP:** Content Security Policy disables all inline scripts (`script-src 'self' https://unpkg.com`), frames (`frame-ancestors 'none'`), and objects (`object-src 'none'`).
* **CSRF Protection:** Every state-changing POST route requires a valid CSRF token derived from user session keys.
