# ThreatDesk — Master Bug & Quality Register

**Project:** ThreatDesk (Digital Risk Protection Platform)  
**Hackathon:** ByteXL HacXLerate 2026 — Challenge 3: *Social & App Monitoring*  
**Register Date:** October 2026  
**Status:** All Identified Defects Audited, Prioritized, Resolved, and Verified with Automated Regression Tests  

---

## 1. Summary of Defects by Priority

| Severity Tier | Definition | Total Found | Total Fixed | Remaining |
| :--- | :--- | :---: | :---: | :---: |
| **P0 — Critical** | Authentication bypass, cross-tenant data leakage, unauthorized actions, secret leakage, data corruption | 0 | 0 | 0 |
| **P1 — High** | Broken core workflows, CSP blocking triage actions, stuck jobs, lookalike module conflict | 2 | 2 | 0 |
| **P2 — Medium** | Navigation defects, route 404s, missing user management controls, search/severity filter edge cases, lack of pagination | 6 | 6 | 0 |
| **P3 — Low** | Empty-state onboarding guidance, flat integration listing without operational context | 2 | 2 | 0 |
| **Total** | | **10** | **10** | **0** |

---

## 2. Detailed Bug Register

### BUG-001: Deployed Application Returns 404 on `/dashboard`
* **Bug ID:** `BUG-001`
* **Severity:** P2 (Medium)
* **Component / Route:** `threatdesk/web/dashboard.py` (`/dashboard`)
* **Reproduction Steps:**
  1. Navigate to deployed application `https://threatdesk-ten.vercel.app/dashboard`.
  2. Observe HTTP 404 response.
* **Expected Behavior:** `/dashboard` should serve the authenticated Operational Dashboard (identical to `/`).
* **Actual Observed Behavior:** HTTP 404 Not Found returned on deployed instance.
* **Root Cause:** Deployed Vercel production build was deployed from an older commit prior to PR #5, where `@router.get("/dashboard")` route alias had not yet been registered.
* **Resolution:** Added `@router.get("/dashboard")` decorator to `dashboard()` handler in `threatdesk/web/dashboard.py`.
* **Regression Test:** `tests/test_site_integrity.py::test_route_aliases_and_redirects`
* **Verification Status:** ✅ Verified (200 OK locally; documented as deployment upgrade requirement).

---

### BUG-002: Inline Event Handlers Violate Strict Content-Security-Policy (CSP)
* **Bug ID:** `BUG-002`
* **Severity:** P1 (High)
* **Component / Route:** `threatdesk/templates/findings.html`, `threatdesk/static/app.js`
* **Reproduction Steps:**
  1. Open Findings workspace (`/findings`) under standard CSP policy.
  2. Select findings for bulk false-positive marking.
  3. Submit the bulk form.
* **Expected Behavior:** Browser prompts user for confirmation without CSP violations or blocked execution.
* **Actual Observed Behavior:** Inline `onsubmit="return confirm(...)"` violated `script-src 'self'` policy and was blocked by modern browsers.
* **Root Cause:** Inline JavaScript attribute in Jinja2 template conflicting with strict CSP middleware installed in `threatdesk/web/middleware.py`.
* **Resolution:** Removed inline `onsubmit` from `findings.html`. Implemented CSP-compliant listener in `threatdesk/static/app.js` (`initBulk()`) using standard DOM event delegation.
* **Regression Test:** `tests/test_site_integrity.py::test_bulk_form_csp_compliance`
* **Verification Status:** ✅ Verified (No inline scripts in HTML output; automated test confirms absence of `onsubmit=`).

---

### BUG-003: Case-Sensitivity and Missing URL Matching in Findings Search
* **Bug ID:** `BUG-003`
* **Severity:** P2 (Medium)
* **Component / Route:** `threatdesk/web/findings.py` (`GET /findings?severity=...&q=...`)
* **Reproduction Steps:**
  1. Request `/findings?severity=high` or `/findings?severity=critical`.
  2. Perform text search for a URL domain substring (`/findings?q=paypal-secure`).
* **Expected Behavior:** Returns findings matching "High" risk tier; searches both `display_name` and target `url`.
* **Actual Observed Behavior:** Severity filter failed because raw query was capitalized to `"High"` but failed on `"critical"` aliases; search only checked `display_name`, missing raw phishing URLs.
* **Root Cause:** Inflexible string capitalization in query filter and omitted `Finding.url` ILIKE clause.
* **Resolution:** Added severity normalization (`sev_norm = "High" if severity.lower() == "critical" else ...`) and compound ILIKE query: `Finding.display_name.ilike(...) | Finding.url.ilike(...)`.
* **Regression Test:** `tests/test_site_integrity.py::test_findings_search_and_severity_normalization`
* **Verification Status:** ✅ Verified.

---

### BUG-004: Missing Navigation Redirects for `/assets`, `/takedown`, `/intake`, and `/team`
* **Bug ID:** `BUG-004`
* **Severity:** P2 (Medium)
* **Component / Route:** `threatdesk/web/assets.py`, `threatdesk/web/takedown.py`, `threatdesk/web/intake.py`, `threatdesk/web/auth.py`, `threatdesk/web/brands.py`
* **Reproduction Steps:**
  1. Manually enter `/assets`, `/takedown`, `/intake`, `/team`, or `/discovery` in browser URL bar.
* **Expected Behavior:** User is seamlessly redirected via HTTP 303 to appropriate destination page.
* **Actual Observed Behavior:** HTTP 404 Not Found error displayed.
* **Root Cause:** Routes referenced in legacy documentation or bookmarks lacked explicit redirect routes.
* **Resolution:** Added HTTP 303 `RedirectResponse` handlers:
  - `/assets` $\to$ `/brands`
  - `/takedown` $\to$ `/findings?status=takedown_requested`
  - `/intake` $\to$ `/brands`
  - `/team` $\to$ `/settings#team`
  - `/discovery` $\to$ `/brands`
* **Regression Test:** `tests/test_site_integrity.py`, `tests/test_audit_fixes.py`
* **Verification Status:** ✅ Verified.

---

### BUG-005: Inability to Remove Teammates with Missing Safeguards
* **Bug ID:** `BUG-005`
* **Severity:** P2 (Medium)
* **Component / Route:** `threatdesk/web/auth.py` (`POST /settings/users/{user_id}/delete`)
* **Reproduction Steps:**
  1. Organization administrator navigates to `/settings#team`.
  2. Observe list of teammates with no option to delete or deactivate departed personnel.
* **Expected Behavior:** Organization administrator can remove analysts, while being prevented from deleting their own account or leaving the organization with zero administrators.
* **Actual Observed Behavior:** No removal route or interface controls existed.
* **Root Cause:** Feature omission in initial authentication module.
* **Resolution:** Implemented `remove_user` endpoint with three strict guardrails:
  1. `require_admin` dependency.
  2. Self-removal prohibition (`target.id == admin.id` $\to$ 400).
  3. Last-administrator preservation (`target.role == "admin"` and count $\le 1$ $\to$ 400).
  4. Tenant scoping (`get_owned(db, User, user_id, admin.org_id)` $\to$ 404 for cross-tenant attempts).
* **Regression Test:** `tests/test_audit_fixes.py::test_teammate_removal_and_safeguards`
* **Verification Status:** ✅ Verified.

---

### BUG-006: Lack of Server-Side Pagination and Configurable Sorting on Findings Triage Queue
* **Bug ID:** `BUG-006`
* **Severity:** P2 (Medium)
* **Component / Route:** `threatdesk/web/findings.py`, `threatdesk/templates/findings.html`
* **Reproduction Steps:**
  1. Seed an organization with > 50 findings.
  2. Navigate to `/findings`.
* **Expected Behavior:** Findings are paginated into manageable chunks (e.g. 50 items) with page controls and ability to sort by newest detected vs highest severity score.
* **Actual Observed Behavior:** Hardcoded query `.limit(500)` loaded all rows flat into the DOM without page navigation controls or sort options.
* **Root Cause:** Initial implementation lacked `page`, `page_size`, and dynamic `sort_by` query parameters.
* **Resolution:**
  - Added query parameters: `page` (default 1), `page_size` (default 50), and `sort` (`score`, `newest`, `oldest`).
  - Added query count calculation: `total_matching` and `total_pages`.
  - Added pagination controls (`Previous`, `Page X of Y`, `Next`) and sort dropdown in `findings.html`.
* **Regression Test:** `tests/test_audit_fixes.py::test_findings_pagination_and_sorting`
* **Verification Status:** ✅ Verified.

---

### BUG-007: Look-Alike Classifier Architecture Conflict & Line Limit Hardening
* **Bug ID:** `BUG-007`
* **Severity:** P1 (High)
* **Component / Route:** `threatdesk/lookalike.py`, `threatdesk/lookalike_ml.py`
* **Reproduction Steps:**
  1. Merge `origin/main` into feature branch `amrit/training-model`.
  2. Observe merge conflict between `origin/main`'s pure-function lookalike engine (185 lines) and feature branch's ML research lookalike classifier (279 lines).
* **Expected Behavior:** Both engines function simultaneously without exceeding the 300-line hardening constraint (`tests/test_hardening.py`).
* **Actual Observed Behavior:** Combining both engines into a single `lookalike.py` produced 464 lines, failing `test_modules_stay_small`.
* **Root Cause:** Two parallel implementations sharing the same module path.
* **Resolution:** Clean modular separation:
  - `threatdesk/lookalike_ml.py`: Houses the ML research lookalike classifier (279 lines).
  - `threatdesk/lookalike.py`: Houses the pure-function lookalike engine (199 lines) and re-exports `compare_lookalike`, `find_lookalike`, and `CATEGORY_*` constants from `threatdesk.lookalike_ml`.
* **Regression Test:** `tests/test_hardening.py`, `tests/test_lookalike.py`, `tests/test_lookalike_ml.py`
* **Verification Status:** ✅ Verified (Both test suites pass; all modules $< 300$ lines).

---

### BUG-008: Flat Integration Listing Without Health, Category or Operational Context
* **Bug ID:** `BUG-008`
* **Severity:** P3 (Low)
* **Component / Route:** `threatdesk/web/settings_page.py`, `threatdesk/templates/settings.html`
* **Reproduction Steps:**
  1. Navigate to `/settings#integrations`.
* **Expected Behavior:** Integrations show category (Reputation, Social, Search, Infrastructure), configuration status, and fallback mechanisms when credentials are unset.
* **Actual Observed Behavior:** Displayed a flat list of environment variable names and boolean flags without operational context.
* **Root Cause:** Primitive 3-tuple `(name, env, on)` data model in `settings_page.py`.
* **Resolution:** Refactored `integrations()` to return structured dictionaries containing `name`, `env`, `on`, `category`, and `note` (explaining heuristics and fallbacks). Rendered formatted status cards in `settings.html`.
* **Regression Test:** `tests/test_audit_fixes.py::test_integration_health_and_onboarding_checklist`
* **Verification Status:** ✅ Verified.

---

### BUG-009: Missing First-Time Onboarding Guidance for Empty Organizations
* **Bug ID:** `BUG-009`
* **Severity:** P3 (Low)
* **Component / Route:** `threatdesk/templates/dashboard.html`
* **Reproduction Steps:**
  1. Register a new organization account.
  2. View dashboard with 0 registered brands.
* **Expected Behavior:** Clear, step-by-step onboarding checklist guiding the administrator through brand registration, official asset definition, discovery scan, and finding triage.
* **Actual Observed Behavior:** Bare generic "Start by adding your brand" card with single link.
* **Root Cause:** Lack of structured onboarding state in `dashboard.html`.
* **Resolution:** Implemented an Onboarding Checklist card in `dashboard.html` that tracks progress through 5 key milestones with status badges and direct CTA buttons.
* **Regression Test:** `tests/test_audit_fixes.py::test_integration_health_and_onboarding_checklist`
* **Verification Status:** ✅ Verified.

---

### BUG-010: Pre-fill URL Query Parameter in On-Demand Investigation
* **Bug ID:** `BUG-010`
* **Severity:** P2 (Medium)
* **Component / Route:** `threatdesk/web/investigate.py` (`GET /investigate?url=...`)
* **Reproduction Steps:**
  1. Navigate to `/investigate?url=https://phishing-domain.com`.
* **Expected Behavior:** The target URL input field is pre-filled with the query parameter value for quick analyst triage.
* **Actual Observed Behavior:** Input field remained blank, requiring manual copy-pasting.
* **Root Cause:** Template context omitted reading `request.query_params.get("url")`.
* **Resolution:** Updated `investigate.py` to extract `url` query parameter and bind to form value.
* **Regression Test:** `tests/test_site_integrity.py::test_investigate_url_query_prefill`
* **Verification Status:** ✅ Verified.
