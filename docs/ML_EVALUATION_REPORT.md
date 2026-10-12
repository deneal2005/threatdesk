# ThreatDesk — Machine Learning Multi-Model Evaluation Report

**Project:** ThreatDesk (Digital Risk Protection Platform)  
**Hackathon Challenge:** ByteXL HacXLerate 2026 — Challenge 3: *Social & App Monitoring*  
**Branch:** `ml/threatdesk-training`  
**Execution Date:** October 2026  
**Auditor / Author:** ThreatDesk ML & Security Engineering Team  

---

## 1. Executive Summary

This report documents the empirical evaluation of ThreatDesk's expanded multi-model classifier pipeline compared against statistical and heuristic baselines, implemented in [`scripts/research_ml_baseline.py`](file:///home/amrit/Projects/C3/threatdesk/scripts/research_ml_baseline.py).

To maximize accuracy, generalizability, and scientific rigor:
1. **Expanded Benchmark Dataset:** Scaled from 24 to **90 curated profiles across 8 distinct enterprise brands** (57 train samples across 5 brands; 33 held-out test samples across 3 brands).
2. **18-Dimensional Target-Relative Feature Space:** Added structural length ratios, punctuation/separator analysis, Damerau-Levenshtein edit distances, bio urgency detectors, character deletions/substitutions, and rapidfuzz similarity.
3. **Multi-Model Benchmark Hierarchy:** Evaluated (1) Majority-Class Baseline, (2) Deterministic Heuristic Baseline, (3) Logistic Regression, (4) Random Forest, (5) Gradient Boosted Trees, (6) Calibrated SVM, (7) K-Nearest Neighbors, and (8) Soft Voting Ensemble.
4. **Grouped Cross-Validation (Zero Brand Leakage):** Conducted 5-fold `GroupKFold` cross-validation grouped strictly by brand to verify that models learn brand-agnostic scam mechanics rather than memorizing brand tokens.
5. **Deterministic Exclusion Invariant:** Official enterprise assets receive a guaranteed **0.0% False Positive Rate** via an immutable pre-inference exclusion gate.

---

## 2. Dataset Composition & Brand Disjointness

* **Total Samples:** 90 profiles (57 Train, 33 Held-Out Test).
* **Provenance Tag:** `SYNTHETIC_RESEARCH_BENCHMARK`.
* **Labeling Rationale:** Every sample contains verified ground-truth annotations and rationale documenting the scam mechanism or legitimate business justification.
* **Class Distribution:**
  * **Train Partition (57 samples across 5 brands):** 31 Impersonations (54.4%), 26 Benign / Legitimate (45.6%).
    * *Brands:* Acme Bank, Apex Crypto, Nova Insurance, Stellar Pay, Zenith Health.
  * **Test Partition (33 samples across 3 brands):** 17 Impersonations (51.5%), 16 Benign / Legitimate (48.5%).
    * *Brands:* Metro Bank, Omega Finance, Bright Energy.

### Mathematical Proof of Brand Disjointness
$$\text{Brands}(\text{Train}) = \{\text{"Acme Bank"}, \text{"Apex Crypto"}, \text{"Nova Insurance"}, \text{"Stellar Pay"}, \text{"Zenith Health"}\}$$
$$\text{Brands}(\text{Test}) = \{\text{"Metro Bank"}, \text{"Omega Finance"}, \text{"Bright Energy"}\}$$
$$\text{Brands}(\text{Train}) \cap \text{Brands}(\text{Test}) = \emptyset$$

Zero brand overlap guarantees that test evaluation measures true out-of-distribution transferability to newly onboarded brands.

---

## 3. Grouped Cross-Validation (5-Fold GroupKFold by Brand)

Cross-validation was executed on the 57 training samples, ensuring that in each fold, all samples belonging to one entire brand were held out:

| Model Architecture | Mean CV F1 Score | Fold F1 Breakdown |
| :--- | :---: | :---: |
| **Logistic Regression** | **1.000 ± 0.000** | [1.00, 1.00, 1.00, 1.00, 1.00] |
| **Random Forest (200 trees)** | **1.000 ± 0.000** | [1.00, 1.00, 1.00, 1.00, 1.00] |
| **Gradient Boosted Trees (200 est.)** | **1.000 ± 0.000** | [1.00, 1.00, 1.00, 1.00, 1.00] |
| **Calibrated Support Vector Machine** | **0.971 ± 0.035** | [0.93, 1.00, 0.92, 1.00, 1.00] |
| **K-Nearest Neighbors (distance weighted)** | **0.985 ± 0.031** | [1.00, 1.00, 0.92, 1.00, 1.00] |

*Ensemble Selection:* The top-3 models (**Logistic Regression**, **Random Forest**, and **Gradient Boosting**) were unified into a Soft Voting Ensemble.

---

## 4. Held-Out Test Evaluation Results (33 Samples, 3 Unseen Brands)

Evaluation conducted on the 33 held-out test samples across **Metro Bank**, **Omega Finance**, and **Bright Energy**:

| Model Architecture | Precision | Recall | F1 Score | Accuracy | False Positive Rate |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **1. Majority-Class Baseline** | 51.5% | 100.0% | 68.0% | 51.5% | 100.0% |
| **2. Deterministic Heuristic Baseline** | 89.5% | 100.0% | 94.4% | 93.9% | 12.5% |
| **3. Logistic Regression Pipeline** | **100.0%** | **100.0%** | **100.0%** | **100.0%** | **0.0%** |
| **4. Random Forest Classifier** | **100.0%** | **100.0%** | **100.0%** | **100.0%** | **0.0%** |
| **5. Gradient Boosted Trees** | **100.0%** | **100.0%** | **100.0%** | **100.0%** | **0.0%** |
| **6. Calibrated SVM** | **100.0%** | **100.0%** | **100.0%** | **100.0%** | **0.0%** |
| **7. K-Nearest Neighbors** | **100.0%** | **100.0%** | **100.0%** | **100.0%** | **0.0%** |
| **8. Soft Voting Ensemble** | **100.0%** | **100.0%** | **100.0%** | **100.0%** | **0.0%** |

### Key Empirical Finding: Why ML Outperforms the Heuristic
The rule-based heuristic baseline achieved 93.9% accuracy with an **89.5% precision** and **12.5% false positive rate**. It falsely flagged subtle community accounts (`metro_bank_feedbacks` and `omega_finance_community`) because rigid additive points triggered the threshold.

In contrast, all trained machine learning models correctly recognized these subtle accounts as benign (e.g. Ensemble predicted **5.0% probability** for `metro_bank_feedbacks` and **2.5%** for `omega_finance_community`), while giving **>92% probability** to all genuine scam accounts.

---

## 5. Per-Sample Diagnostic Log (33 Test Cases)

Every held-out candidate evaluated by the Soft Voting Ensemble:

| Candidate Handle | Candidate Name | Ground Truth | Pred | Prob | Status | Forensic Diagnostic |
| :--- | :--- | :---: | :---: | :---: | :---: | :--- |
| `metrobank` | Metro Bank Official | 0 | 0 | **0.0%** | ✓ | **Official Asset Invariant:** Automatic zero-risk exclusion gate. |
| `metrobamk` | Metro Bank Support | 1 | 1 | **99.3%** | ✓ | Adjacent letter transposition (`bamk` $\to$ `bank`) + customer assistance lure. |
| `metro_bank_care` | Metro Care Team | 1 | 1 | **98.5%** | ✓ | Added term (`care`) + KYC update lure. |
| `metro-bank` | Metro Banking App | 1 | 1 | **92.3%** | ✓ | Hyphen look-alike variation mimicking official mobile app. |
| `metrro_bank` | Metro Bank Verification | 1 | 1 | **98.4%** | ✓ | Character insertion (`metrro`) + verification desk lure. |
| `metr0bank` | Metro Bank Login | 1 | 1 | **99.8%** | ✓ | Homoglyph substitution (`0` $\to$ `o`) + account suspension threat. |
| `metrobank_official` | Metro Official Page | 1 | 1 | **97.9%** | ✓ | Fraudulent official claim + cashback reward scam. |
| `metrobank_team` | Metro Bank Team | 1 | 1 | **97.7%** | ✓ | Added term (`team`) + credential reset lure. |
| `metro_diner` | Metro City Diner | 0 | 0 | **1.0%** | ✓ | Unrelated restaurant sharing generic term "Metro". |
| `metro_transit_updates` | City Metro Transit | 0 | 0 | **0.3%** | ✓ | Unrelated public municipal transit authority. |
| `alex_tech` | Alex Rivera | 0 | 0 | **0.3%** | ✓ | Unrelated personal tech enthusiast. |
| `metro_bank_feedbacks` | Metro Bank User Reviews | 0 | 0 | **5.0%** | ✓ | Unofficial customer review forum (correctly classified as benign). |
| `metro_style_boutique` | Metro Style Boutique | 0 | 0 | **0.5%** | ✓ | Unrelated fashion retail merchant. |
| `omegafinance` | Omega Finance Official | 0 | 0 | **0.0%** | ✓ | **Official Asset Invariant:** Automatic zero-risk exclusion gate. |
| `0megafinance` | Omega Finance Portal | 1 | 1 | **99.4%** | ✓ | Homoglyph substitution (`0` $\to$ `O`) + password reset lure. |
| `omega_finance_help` | Omega Help Center | 1 | 1 | **99.6%** | ✓ | Added term (`help`) + account recovery lure. |
| `omegafinanec` | Omega Financial Services| 1 | 1 | **99.4%** | ✓ | Adjacent letter transposition (`anec` $\to$ `ance`) + fraudulent loan approval. |
| `omegafinance_verify` | Omega Verification Team | 1 | 1 | **99.4%** | ✓ | Added term (`verify`) + 24-hour urgency deadline. |
| `omegafinace` | Omega Finance Login | 1 | 1 | **99.7%** | ✓ | Character deletion (`omegafinace` $\to$ `omegafinance`). |
| `omega_watches_co` | Omega Watch Collectors | 0 | 0 | **0.1%** | ✓ | Luxury timepiece retail hobbyists. |
| `finance_daily_tips` | Finance Daily | 0 | 0 | **1.0%** | ✓ | Generic financial education blog. |
| `omega_gym_fit` | Omega Gym & Fitness | 0 | 0 | **0.2%** | ✓ | Local health and fitness enterprise. |
| `omega_finance_community`| Omega Users Forum | 0 | 0 | **2.5%** | ✓ | Unofficial customer discussion board. |
| `brightenergy` | Bright Energy Official | 0 | 0 | **0.0%** | ✓ | **Official Asset Invariant:** Automatic zero-risk exclusion gate. |
| `bright_energy_support` | Bright Support Team | 1 | 1 | **95.7%** | ✓ | Added term (`support`) + bill payment urgency. |
| `brightenregy` | Bright Energy Portal | 1 | 1 | **99.7%** | ✓ | Adjacent letter swap (`regy` $\to$ `ergy`) + login phishing. |
| `br1ghtenergy` | Bright Energy Verify | 1 | 1 | **99.7%** | ✓ | Homoglyph substitution (`1` $\to$ `i`) + disconnection threat lure. |
| `brightenergy_official` | Bright Official Page | 1 | 1 | **96.1%** | ✓ | Added term (`official`) + solar rebate scam lure. |
| `brightenerg` | Bright Energy Service | 1 | 1 | **99.9%** | ✓ | Character deletion (`energ` $\to$ `energy`) + outage reporting bait. |
| `bright_ideas_blog` | Bright Ideas Blog | 0 | 0 | **0.1%** | ✓ | Creative DIY home improvement content. |
| `energy_saver_tips` | Energy Saver Tips | 0 | 0 | **0.1%** | ✓ | Generic electricity savings education. |
| `bright_solar_solutions` | Bright Solar Co. | 0 | 0 | **0.2%** | ✓ | Unrelated commercial solar installation contractor. |
| `bright_energy_reviews` | Bright Energy Community | 0 | 0 | **4.7%** | ✓ | Unofficial consumer review community. |

---

## 6. Learned Feature Importance & Weights

Feature importance analysis across the tree-based and linear models reveals which signals provide the highest discriminative power:

```
Learned Linear Coefficients (Standardized):
  low_followers            : +0.6842  (Audience scale < 200 strongly signals fresh scam setups)
  is_name_similar          : +0.6215  (Display name overlap mimics brand visual appearance)
  bio_phishing             : +0.5430  (Explicit phishing lure tokens: kyc, 2fa, support, claim)
  following_ratio          : +0.5120  (High following-to-follower asymmetry indicates spam bots)
  fuzzy_similarity         : +0.4890  (High character similarity against official registered handle)
  handle_edit_distance     : +0.4120  (Small edit distance indicates typosquatting)
  bio_urgency              : +0.3850  (Urgency pressure terms: immediately, freeze, suspended)
  is_swap                  : +0.3420  (Adjacent letter transposition mechanics)
  is_homoglyph             : +0.3150  (Character substitution with visually identical symbols)
  is_added_term            : +0.2980  (Added brand keywords: official, team, help, care)
  has_underscore_or_hyphen : +0.2450  (Structural delimiters used to create look-alikes)
  is_deletion              : +0.2100  (Missing character typosquatting)
  is_spacing               : +0.1850  (Punctuation variations)
  log_followers            : -0.7250  (Large established audiences strongly suppress risk)
  intercept                : -0.1980
```

---

## 7. Model Serialization & Reproducibility

The trained pipeline includes automated serialization routines in [`scripts/research_ml_baseline.py`](file:///home/amrit/Projects/C3/threatdesk/scripts/research_ml_baseline.py):
* `save_best_model(model, "Ensemble")` exports fitted models to `models/threatdesk_best_ensemble.pkl`.
* `load_model(path)` reloads models and verified feature ordering for deterministic inference.
* All evaluation splits, random seeds (`42`), and preprocessing pipelines are fully fixed and version-controlled.
