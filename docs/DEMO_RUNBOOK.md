# ThreatDesk — Jury Demo Runbook & Presentation Guide

**Event:** ByteXL HacXLerate 2026 — Challenge 3: Digital Risk Protection Platform  
**Target:** 3-Minute Live Jury Demonstration  
**Local App URL:** [http://localhost:8000](http://localhost:8000)  

---

## 1. Quick Setup & Verification

If the local server is not already running, execute:
```bash
# 1. Start Uvicorn backend
.venv/bin/uvicorn threatdesk.main:app --host 0.0.0.0 --port 8000 --workers 1

# 2. Verify health endpoint in browser or terminal
curl http://localhost:8000/health
# Response: {"status":"ok","db":true}
```

**Credentials for Demonstration:**
* **URL:** `http://localhost:8000/login`
* **Email:** `demo@threatdesk.local`
* **Password:** `demo12345678`

---

## 2. 3-Minute Demonstration Script

### Act 1: The Brand Profile (40 Seconds)
1. **Navigate to Brands:** Click **Brands** in the navigation bar, then click into **Acme Bank**.
2. **Showcase Defined Legitimate Assets:**
   * **Websites tab:** Show official registered domains (`acmebank.com`, `acmebank.in`) and DNS TXT verification tokens.
   * **Social accounts tab:** Show official registered handles across platforms (Instagram `@acmebank`, Telegram `@acmebank`, YouTube `@AcmeBank`).
   * **Mobile apps tab:** Show official registered Android package (`com.acme.bank`) and iOS App Store ID (`1234567890`), with listed corporate publisher `Acme Financial Group`.
   * **Logo tab:** Show the uploaded brand logo and explain the stored **Perceptual Hash (`pHash`)** used to catch visual copycats.
3. **Talking Point for Judges:**  
   > *"ThreatDesk starts with ground truth: what an enterprise genuinely owns. Every detection downstream is evaluated relative to this verified baseline."*

---

### Act 2: Official Asset Exclusion (30 Seconds)
1. **Navigate to Investigate:** Click **Investigate** in the top navigation bar.
2. **Paste an Official Asset:**
   * Enter: `https://acmebank.com`
   * Select Brand: **Acme Bank**
   * Click **Investigate**.
3. **Show the Result:**
   * **Score:** `0 / 100` (Low Severity).
   * **Verdict Banner:** `Official/whitelisted asset`.
   * **Explanation:** *"This is one of the brand's official or allowed assets, so it is not scored."*
4. **Talking Point for Judges:**  
   > *"False positives destroy analyst trust. ThreatDesk's ground-truth exclusion gate guarantees that official company assets and whitelisted partners are never falsely flagged."*

---

### Act 3: Look-Alike Social Impersonation (50 Seconds)
1. **Navigate to Investigate:**
2. **Paste a Suspicious Handle:**
   * Enter: `https://t.me/amcebank` (or enter handle `@amcebank`).
   * Select Brand: **Acme Bank**.
   * Click **Investigate**.
3. **Show the Explainable Breakdown:**
   * **Score Rail:** Automatically calculates risk points (70+ High Risk).
   * **Why It Was Flagged (Ledger):**
     * Rule: **Handle similar to an official handle (+25 pts)**
     * Evidence: `@amcebank resembles official @acmebank · Adjacent letter swap: Swapped "mc" instead of "cm"`
   * **Point out to Judges:**  
     > *"Notice that ThreatDesk doesn't just output an opaque ML probability. It explains the exact typographical manipulation: an adjacent character swap targeting 'acme'."*
4. **Try Another Variation:**
   * Enter: `https://t.me/acme_support`
   * Evidence: `@acme_support resembles official @acme · Added suspicious word: Includes "support" alongside brand name`

---

### Act 4: App Store Impersonation & Publisher Mismatch (40 Seconds)
1. **Navigate to Findings:** Click **Findings** in the top navigation bar.
2. **Open Existing Case #0001 or Investigate an App:**
   * Show how ThreatDesk analyzes mobile apps:
     * **Developer Discrepancy:** Developer is listed as an unknown LLC instead of registered publisher `Acme Financial Group`.
     * **Developer Free Email:** Flagged if developer contact is on `@gmail.com` or `@yahoo.com`.
     * **Icon Similarity:** Perceptual distance matches the Acme Bank trademark icon.
     * **Dangerous Permissions:** Flags requests for SMS reading or accessibility service overlays.

---

### Act 5: Takedown Packet Generation (20 Seconds)
1. **On Any Finding Page:** Click the **Takedown packet** button on the right-hand action card.
2. **Show the Export:**
   * Shows RDAP-derived abuse contacts (e.g. registrar abuse email).
   * Click **Download takedown packet (.txt)**.
   * Show the RFC-compliant legal notice containing:
     * Infringing URL / Package ID
     * Trademark reference
     * Immutable SHA-256 evidence hashes
     * Specific policy violations
3. **Closing Point for Judges:**  
   > *"ThreatDesk completes the full lifecycle: from discovery, to explainable triage, to an evidence-backed takedown notice ready for registrar or store enforcement."*

---

## 3. Offline Resilience & Reliability Note

ThreatDesk is designed to work even if the internet drops or external APIs rate-limit:
* All 193 unit tests run **100% offline** via mocks and patched DNS.
* Public scam lists are cached locally in `.cache/`.
* The demo dataset seeds pre-recorded findings labelled **"Demo fixture"**, so the live demo never fails due to an external network outage.
