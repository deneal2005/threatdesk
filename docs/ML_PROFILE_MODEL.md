# Fake-profile model, credential-form rules and analyst labels

## What runs in production

| Piece | Where | Effect on a score |
|---|---|---|
| Fake-profile model (Instagram) | `threatdesk/profile_model.py`, weights in `threatdesk/profile_model.json` | `profile_model_fake` +10, only on accounts whose handle or name already resembles the brand, only at ≥ 80% model confidence. Weak context: it never lifts a name-only match above the 35-point cap. |
| Credential form posts off-site | `checks/generic.py: form_signals` | `credential_form_offsite` +20: a password/card/OTP form submits to an unrelated domain or is e-mailed (`mailto:`). Sign-in providers (Okta, Auth0…) and payment gateways (Razorpay, CCAvenue, Stripe…) are expected receivers and do not count. |
| Credential form over HTTP | same | `credential_form_insecure` +10: such a form is sent unencrypted. |

Official and well-known brand hosts never get the form rules. The model reads only fields the Apify Instagram
reader already returns; if any is missing it does not run (no guessing). Turn it off with `PROFILE_MODEL=off`.

The idea for the form rules comes from LegitURL (AGPL-3.0); the code here is our own, no LegitURL code is copied.

## The model

Logistic regression on 11 profile features (photo, digits in username, bio length, posts, followers, follows…),
trained on the public fake/real Instagram table shipped with
[InstaGuard](https://github.com/allu16kumoulica/Fake-Social-Media-Profile-Detection-and-Reporting) (698 rows,
balanced). That table has no stated licence, so it is **not** committed; the model file records its sha256.

Held-out 20% (140 rows never trained on):

| Model | Precision | Recall | F1 |
|---|---|---|---|
| **Shipped logistic regression** (threshold tuned for ≥ 95% CV precision) | 0.94 | 0.89 | 0.91 |
| InstaGuard's AdaBoost (reference, same split) | 0.89 | 0.90 | 0.89 |
| Random forest (reference, same split) | 0.90 | 0.89 | 0.89 |

These numbers describe generic fake accounts in that table, not brand impersonation on your traffic. That is why
the model's weight is small and bounded; measure it on your own decisions (below) before giving it more.

Inference is plain Python over JSON weights: no scikit-learn, pickle or joblib at runtime, so loading the model
cannot execute code.

## Phase 2: learn from analyst decisions

Confirmed / takedown requested / taken down = **scam**; false positive = **legit**; other statuses are ignored.

```bash
python -m scripts.label_report --org 1
```

Read-only. Prints precision and recall of the verdicts as investigated **and** of today's rules replayed on the
stored signals (so a weight change can be checked against past decisions with no network calls), a per-kind
breakdown, and the rules that fire mostly on false positives. Writes `labels/labels.jsonl` (gitignored; signal
codes and model features only, no URLs or names). `--all-orgs` pools every organisation and must be asked for.

```bash
python -m scripts.train_profile_model path/to/dataset.csv --extra labels/labels.jsonl
```

Adds your Instagram decisions to the training side only. The new model is kept only if its held-out precision and
F1 are not worse than the current model's on the same untouched public rows; otherwise nothing is written
(`--force` overrides). Wrong or careless labels therefore cannot quietly degrade the shipped model.
