# ThreatDesk — Machine Learning Baseline Evaluation Report

**Project:** ThreatDesk (Digital Risk Protection Platform)  
**Hackathon Challenge:** ByteXL HacXLerate 2026 — Challenge 3: *Social & App Monitoring*  
**Branch:** `ml/threatdesk-training`  
**Execution Date:** October 2026  
**Auditor / Author:** ThreatDesk ML & Security Engineering Team  

---

## 1. Executive Summary

This report documents the empirical evaluation of ThreatDesk's learned classifier pipeline compared against statistical and heuristic baselines, implemented in [`scripts/research_ml_baseline.py`](file:///home/amrit/Projects/C3/threatdesk/scripts/research_ml_baseline.py).

To ensure scientific integrity and eliminate manufactured confidence:
1. **Curated Synthetic Benchmark:** The evaluation is conducted on a transparent synthetic benchmark (`SYNTHETIC_RESEARCH_BENCHMARK`). No claim of production-scale real-world data is made.
2. **Brand-Separated Partitioning:** All candidates for **Metro Bank** are isolated in the test partition, ensuring **zero brand leakage** from the training partition (**Acme Bank** and **Apex Crypto**).
3. **Tripartite Comparison:** We evaluate (1) Majority-Class Baseline, (2) Deterministic Heuristic Baseline, and (3) Learned Scikit-Learn Pipeline (`StandardScaler` + `LogisticRegression`).
4. **Deterministic Exclusion Invariant:** Official brand assets are guaranteed a **0.0% False Positive Rate** via a pre-inference exclusion gate.

---

## 2. Dataset Composition & Brand Disjointness

* **Total Samples:** 24 profiles (15 Train, 9 Held-Out Test).
* **Provenance Tag:** `SYNTHETIC_RESEARCH_BENCHMARK`.
* **Labeling Rationale:** Every sample includes documented rationale explaining why it is labeled benign or impersonation.
* **Class Distribution:**
  * **Train Partition (15 samples):** 7 Impersonations (46.7%), 8 Benign / Legitimate (53.3%).
  * **Test Partition (9 samples):** 4 Impersonations (44.4%), 5 Benign / Legitimate (55.6%).

### Mathematical Proof of Brand Disjointness
$$\text{Brands}(\text{Train}) = \{\text{"Acme Bank"}, \text{"Apex Crypto"}\}, \quad \text{Brands}(\text{Test}) = \{\text{"Metro Bank"}\}$$
$$\text{Brands}(\text{Train}) \cap \text{Brands}(\text{Test}) = \emptyset$$

---

## 3. Tripartite Model Comparison Results

All three models were evaluated on the held-out test partition (**Metro Bank**):

| Evaluation Metric | Model 1: Majority-Class Baseline | Model 2: Deterministic Heuristic Baseline | Model 3: Learned Pipeline (`LogisticRegression`) |
| :--- | :---: | :---: | :---: |
| **Model Type** | Statistical Mode (Predict 0) | Rule-based Score ($\ge 40$) | Scikit-Learn Pipeline (`.fit()`) |
| **Learned Parameters** | None (constant) | None (manual weights) | $\mathbf{w} \in \mathbb{R}^{10}$, $b \in \mathbb{R}$ |
| **Test Accuracy** | 55.6% | **100.0%** | **100.0%** |
| **95% Confidence Interval (Accuracy)** | $[26.7\%, 81.1\%]$ | $[70.1\%, 100.0\%]$ | $[70.1\%, 100.0\%]$ |
| **Precision (Impersonation)** | 0.0% (undefined) | **100.0%** | **100.0%** |
| **Recall (Impersonation)** | 0.0% | **100.0%** | **100.0%** |
| **F1 Score** | 0.0% | **100.0%** | **100.0%** |
| **False Positive Rate (Legitimate)**| **0.0%** | **0.0%** | **0.0%** |
| **Confusion Matrix ($TP, FP, TN, FN$)**| $0, 0, 5, 4$ | $4, 0, 5, 0$ | $4, 0, 5, 0$ |

---

## 4. Learned Pipeline Inspection & Coefficient Analysis

The scikit-learn pipeline was trained via `pipeline.fit(X_train, y_train)`. Inspection of the learned logistic regression coefficients confirms that the model learned meaningful risk signals from training data:

```
Learned Model Coefficients (Standardized):
  low_followers       : +0.7830  (Low audience size in brand context indicates new phishing setup)
  is_name_similar     : +0.7183  (Display name mimicking brand strongly predicts impersonation)
  following_ratio     : +0.7082  (Aggressive following-to-follower ratio indicates spam behavior)
  is_swap             : +0.3948  (Adjacent character transpositions indicate impersonation)
  bio_phishing        : +0.3065  (Phishing/support lures in bio indicate scam intent)
  is_spacing          : +0.2849  (Hyphen/punctuation variations indicate look-alikes)
  is_homoglyph        : +0.2046  (Alphanumeric homoglyphs indicate evasion)
  is_added_term       : +0.1701  (Added operational terms indicate fake support)
  digit_ratio         : -0.0429  (Neutral / slightly negative correlation)
  log_followers       : -0.5923  (High audience scale strongly suppresses risk)
  intercept (bias)    : -0.2369
```

---

## 5. Case Diagnostics on Test Partition (Metro Bank)

Every held-out candidate was evaluated by both the heuristic baseline and the learned pipeline:

| Candidate Handle | Candidate Name | Ground Truth | Heuristic Score | Learned Model Prob. | Pred. | Diagnostic Analysis |
| :--- | :--- | :---: | :---: | :---: | :---: | :--- |
| `metrobank` | Metro Bank Official | **0 (Legit)** | 0.0 | **0.0%** | **0** | **Deterministic Exclusion Gate:** Verified official handle. |
| `metrobamk` | Metro Bank Support | **1 (Phish)** | 75.0 | **98.3%** | **1** | **Impersonation:** Adjacent letter transposition (`bamk` $\to$ `bank`) + support lure. |
| `metro_bank_care` | Metro Care Team | **1 (Phish)** | 80.0 | **97.7%** | **1** | **Impersonation:** Added term (`care`) + KYC phishing lure. |
| `metro-bank` | Metro Banking App | **1 (Phish)** | 55.0 | **91.8%** | **1** | **Impersonation:** Hyphenated look-alike variation mimicking brand. |
| `metrro_bank` | Metro Bank Verification | **1 (Phish)** | 75.0 | **96.4%** | **1** | **Impersonation:** Insertion typo (`metrro`) + verification lure. |
| `metro_diner` | Metro City Diner | **0 (Legit)** | 0.0 | **2.9%** | **0** | **Difficult Benign:** Local restaurant sharing generic word "Metro". |
| `metro_transit_updates` | City Metro Transit | **0 (Legit)** | 0.0 | **1.9%** | **0** | **Difficult Benign:** Public transit service; large legitimate following. |
| `alex_tech` | Alex Rivera | **0 (Legit)** | 0.0 | **3.7%** | **0** | **Difficult Benign:** Personal tech blogger; no brand overlap. |
| `metro_bank_feedbacks` | Metro Bank User Reviews | **0 (Legit)** | 0.0 | **17.3%** | **0** | **Difficult Benign:** Unofficial customer review forum; benign discussion. |

---

## 6. Critical Distinctions & Scientific Limitations

### 6.1 Distinction Between Heuristic Scorer and Learned Model
* **Deterministic Heuristic Baseline:** Uses fixed integer points awarded by human security engineers ($score = \sum w_i$, threshold $\ge 40$). It is transparent and explainable, but does not adapt to data distributions. It is **NOT** machine learning.
* **Learned Classifier Pipeline:** Optimizes empirical log-loss on training samples via convex gradient descent (`LogisticRegression.fit()`), learning continuous decision boundary coefficients $\mathbf{w}$.

### 6.2 Raw Sigmoid Output vs Calibrated Real-World Probability
* The percentage reported above (e.g. `98.3%`) is the **raw logistic sigmoid score** $\sigma(\mathbf{w}^T \mathbf{x} + b)$ on the synthetic benchmark distribution where the class ratio is $\approx 1:1$.
* In real-world enterprise operations, the prior distribution is $\alpha \approx 10^{-4}$ (extreme rarity). Without Platt scaling or isotonic regression calibrated on millions of operational web samples, **the raw model probability cannot be interpreted as a true Bayesian posterior probability**.

### 6.3 Sample Size Uncertainty & Confidence Intervals
* With $N = 9$ held-out test samples, the observed $9/9$ accuracy yields a Wilson 95% confidence interval of $[70.1\%, 100.0\%]$.
* High test accuracy on a small benchmark demonstrates that the feature extraction pipeline transfers across unseen brands, but **does NOT prove 99.99% real-world generalization**.
* For live enterprise operations, ThreatDesk's **deterministic 52-rule scoring engine** remains the certified production truth.
