# ThreatDesk — Machine Learning Training Roadmap & Data Strategy

**Project:** ThreatDesk (Digital Risk Protection Platform)  
**Hackathon Challenge:** ByteXL HacXLerate 2026 — Challenge 3: *Social & App Monitoring*  
**Branch:** `ml/threatdesk-training`  
**Date:** October 2026  
**Auditor / Author:** ThreatDesk ML & Security Engineering Team  

---

## 1. Mathematical Analysis: What Does a "99.99% Target" Actually Require?

Before discussing machine learning models, we mathematically define what an enterprise-grade $99.99\%$ target means and why naive accuracy claims in digital risk protection are scientifically fraudulent.

### 1.1 The Base-Rate Fallacy in Threat Detection
In internet-scale digital risk protection, brand impersonation exhibits **extreme class imbalance**:
* Typical Base Rate: $\alpha = P(\text{Malicious}) \approx 10^{-4}$ (approximately 1 true impersonator per 10,000 scanned accounts or web pages).
* Suppose a model claims $99.0\%$ True Positive Rate ($\text{TPR} = 0.99$) and $99.9\%$ Specificity ($\text{FPR} = 0.001$).
* By Bayes' Theorem, the Positive Predictive Value ($\text{Precision}$) is:
$$P(\text{Malicious} \mid \text{Alert}) = \frac{\text{TPR} \cdot \alpha}{\text{TPR} \cdot \alpha + \text{FPR} \cdot (1 - \alpha)} = \frac{0.99 \cdot 10^{-4}}{0.99 \cdot 10^{-4} + 10^{-3} \cdot (1 - 10^{-4})} = \frac{0.000099}{0.000099 + 0.0009999} \approx 9.0\%$$

> [!CAUTION]
> Even with a seemingly outstanding $99.9\%$ specificity, **$91\%$ of all generated alerts are false positives**!
> Claiming "99.99% accuracy" without specifying the operational base rate, sample size, or precision-recall curve is deceptive. A dummy classifier that simply predicts "clean" for every sample achieves $99.99\%$ accuracy on this distribution while catching zero threats!

### 1.2 Sample Size Required to Statistically Validate 99.99% Reliability
To bound an error rate of $p = 10^{-4}$ (0.01%) with a 95% confidence interval of half-width $\epsilon = 5 \times 10^{-5}$:
$$n \ge \frac{z^2 \cdot p(1 - p)}{\epsilon^2} = \frac{(1.96)^2 \cdot 10^{-4} \cdot (1 - 10^{-4})}{(5 \times 10^{-5})^2} \approx 153,600 \text{ independently verified evaluation samples}$$

**Conclusion:** ThreatDesk's current synthetic benchmark ($N=24$) is designed to verify learning mechanics and brand-separated feature transferability. It cannot and does not substantiate a 99.99% real-world reliability claim.

---

## 2. Multi-Tiered Label Taxonomy

To prevent binary oversimplification, ThreatDesk establishes a 6-class annotation taxonomy:

| Label Category | Code | Operational Definition | Production Action |
| :--- | :---: | :--- | :--- |
| **Confirmed Malicious** | `MAL_CONFIRMED` | Active credential harvesting, malware, fraudulent payment requests, or deceptive impersonation with scam intent. | High-priority takedown; alert dispatched. |
| **Suspicious / Uncertain** | `SUSP_TRIAGE` | Strong brand resemblance with high typo similarity, but lacking verified malicious activity (e.g. parked domain, new account). | Enqueued for human SOC analyst review. |
| **Official Enterprise Asset** | `OFF_VERIFIED` | Registered corporate social account, authorized domain, or mobile app bundle ID owned by the brand. | **Excluded (Score = 0)**. Automatically whitelisted. |
| **Authorized Partner / Reseller** | `AUTH_PARTNER` | Third-party vendor, franchise, or authorized distributor with legal trademark license. | Whitelisted under partner policy. |
| **Fan / Community / Satire** | `BENIGN_FAN` | Unofficial user group, fan page, or parody that clearly discloses unofficial status without phishing intent. | Low priority; monitored for status changes. |
| **Unrelated Entity** | `BENIGN_UNRELATED` | Coincidental dictionary term collision (e.g. *Metro Diner*, *Acme Cafe*) with no brand confusion. | Ignored; zero risk score. |

---

## 3. Provenance, Annotation & Dataset Versioning

Every sample in the ThreatDesk data repository must carry immutable provenance metadata:

```json
{
  "sample_id": "td-sample-2026-004821",
  "dataset_version": "v1.2.0-rc1",
  "collected_at": "2026-10-12T10:15:30Z",
  "source_adapter": "discovery:crtsh | discovery:itunes | soc_intake",
  "candidate": {
    "target_brand": "Metro Bank",
    "handle_or_id": "metrobamk",
    "display_title": "Metro Bank Support",
    "evidence_snapshot_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
  },
  "ground_truth": {
    "label": "MAL_CONFIRMED",
    "rationale": "Adjacent character transposition ('bamk') combined with urgent KYC update lure in bio.",
    "annotator_id": "soc-analyst-12",
    "reviewer_status": "PEER_REVIEWED",
    "provenance_class": "FIELD_VERIFIED"
  }
}
```

* **`provenance_class` Enum:**
  * `FIELD_VERIFIED`: Confirmed by SOC analyst from live telemetry.
  * `THREAT_FEED`: Ingested from PhishTank, URLhaus, or OpenPhish.
  * `SYNTHETIC_RESEARCH_BENCHMARK`: Curated algorithmic test cases for unit testing and mechanic validation.

---

## 4. Grouped Splitting Strategy (Zero-Leakage Architecture)

### 4.1 The Leakage Problem in Security Data
Standard random train/test splits cause four distinct types of data leakage:
1. **Brand Leakage:** Model memorizes target brand keywords rather than generalizable typo mechanics.
2. **Campaign / Infrastructure Leakage:** Multiple accounts created by the same threat actor share server subnets, WHOIS registrant emails, or bio templates. Splitting them across train and test artificially inflates metrics.
3. **Temporal Leakage:** Testing on data from the same week as training hides concept drift.
4. **Duplicate Snapshot Leakage:** Scraping the same profile on consecutive days produces near-identical rows.

### 4.2 ThreatDesk Grouped Partitioning Protocol
```
               Total Labeled Data Repository
                            │
       ┌────────────────────┴────────────────────┐
       ▼                                         ▼
 Brand-Separated Splits                Temporal Holdout
  • Brands(Train) ∩ Brands(Test) = ∅    • Historical (Month 1-3)
  • Grouped by Actor / Campaign ID      • Future Holdout (Month 4)
```

1. **Brand-Level Grouping:** All candidates targeting a brand remain strictly within one partition.
2. **Actor & Campaign Cluster Grouping:** Accounts sharing infrastructure (e.g. identical redirect destinations or IP subnets) are grouped into a single unit.
3. **Temporal Holdout:** The test set evaluates the most recent 30 days of data against models trained on preceding months.

---

## 5. Model Architecture Evolution & Baseline Hierarchy

ThreatDesk establishes a formal hierarchy of models:

```
┌────────────────────────────────────────────────────────┐
│              Level 1: Majority Baseline                │
│    Predicts most frequent class (Baseline Floor)       │
├────────────────────────────────────────────────────────┤
│              Level 2: Deterministic 52-Rule Engine     │
│    Explainable production truth (Reference Standard)   │
├────────────────────────────────────────────────────────┤
│              Level 3: Logistic Regression Pipeline     │
│    StandardScaler + L2 Regularization (Current Res.)   │
├────────────────────────────────────────────────────────┤
│              Level 4: Gradient Boosted Trees (Roadmap) │
│    LightGBM / XGBoost with Monotonic Feature Bounds    │
└────────────────────────────────────────────────────────┘
```

* **Current Implementation:** Level 2 (Production Truth) + Level 3 (Research Baseline in `scripts/research_ml_baseline.py`).
* **Level 4 Criteria:** Tree-based models will only be explored once the verified dataset exceeds $5,000$ labeled samples. Monotonic constraints must enforce that increased typo severity or phishing keywords can never decrease predicted risk.

---

## 6. Threshold Selection & Operating Points

Rather than selecting an arbitrary $0.5$ classification threshold, ThreatDesk calibrates operating points based on **Analyst Triage Capacity**:

$$\text{Daily Alert Volume} = N_{\text{scanned}} \cdot P(\text{Score} \ge \tau) \le C_{\text{analysts}}$$

1. **High-Confidence Auto-Takedown ($\tau \ge 85$):** Precision $\ge 99.5\%$. Direct API dispatch to hosting registrar or platform takedown desk.
2. **Analyst Triage Queue ($40 \le \tau < 85$):** Precision $\ge 80.0\%$. Displayed in the ThreatDesk triage interface with highlighted explainable evidence.
3. **Monitoring Only ($\tau < 40$):** Retained in telemetry database for drift detection and periodic rescanning.

---

## 7. Model Lifecycle, Drift Monitoring & Rollback

1. **Drift Detection:** Monitor Population Stability Index (PSI) and feature distributions weekly. If bio keyword distributions or TLD frequencies shift by $\text{PSI} > 0.2$, trigger retraining alerts.
2. **Automated Shadow Deployment:** New models run in shadow mode for 14 days, generating predictions logged alongside the deterministic engine without affecting analyst alerts.
3. **Instant Fallback:** If any anomaly occurs, the system defaults to the deterministic 52-rule engine.
