"""Fake-profile model for Instagram accounts: a logistic regression evaluated in plain Python.

The weights live in profile_model.json, written by scripts/train_profile_model.py (scikit-learn is needed only
there, never at runtime). No pickle/joblib: the model file is data, so loading it cannot run code.

The model says "this account looks fake or throwaway" (no photo, numeric username, empty bio, follows many but
followed by few). That is not impersonation on its own, so social checks use it only on accounts whose name already
resembles the brand, and scoring treats it as weak context (it never corroborates a name match by itself).
"""
from __future__ import annotations

import json
import math
from functools import lru_cache
from pathlib import Path

MODEL_PATH = Path(__file__).with_name("profile_model.json")
FEATURES = ("profile_pic", "username_digit_ratio", "fullname_words", "fullname_digit_ratio", "name_eq_username",
            "description_length", "external_url", "private", "log_posts", "log_followers", "log_follows")
# What a feature looks like when it pushes towards "fake": (wording when the value is low, wording when high).
LABELS = {
    "profile_pic": ("no profile photo", "has a profile photo"),
    "username_digit_ratio": ("few digits in the username", "many digits in the username"),
    "fullname_words": ("no or one-word display name", "long display name"),
    "fullname_digit_ratio": ("no digits in the display name", "digits in the display name"),
    "name_eq_username": ("display name differs from the username", "display name equals the username"),
    "description_length": ("short or empty bio", "long bio"),
    "external_url": ("no link in the bio", "link in the bio"),
    "private": ("public account", "private account"),
    "log_posts": ("few posts", "many posts"), "log_followers": ("few followers", "many followers"),
    "log_follows": ("follows few accounts", "follows many accounts"),
}
# Instagram serves this stock image to accounts that never uploaded a photo.
DEFAULT_AVATAR_MARKERS = ("44884218_345707102882519_2446069589734326272_n", "/default_profile", "anonymous_profile")


def _digit_ratio(s: str) -> float:
    return round(sum(c.isdigit() for c in s) / len(s), 2) if s else 0.0


def _count(v) -> int | None:
    return v if isinstance(v, int) and not isinstance(v, bool) and v >= 0 else None


def instagram_features(item: dict) -> dict[str, float] | None:
    """Model inputs from an Apify Instagram profile item, or None when a needed field is missing (no guessing)."""
    if not isinstance(item, dict):
        return None
    username = str(item.get("username") or "")
    posts, followers, follows = (_count(item.get(k)) for k in ("postsCount", "followersCount", "followsCount"))
    if not username or posts is None or followers is None or follows is None:
        return None
    if "profilePicUrl" not in item and "profilePicUrlHD" not in item:
        return None
    pic = str(item.get("profilePicUrlHD") or item.get("profilePicUrl") or "")
    full = str(item.get("fullName") or "")
    return {
        "profile_pic": float(bool(pic) and not any(m in pic for m in DEFAULT_AVATAR_MARKERS)),
        "username_digit_ratio": _digit_ratio(username),
        "fullname_words": float(len(full.split())),
        "fullname_digit_ratio": _digit_ratio(full),
        "name_eq_username": float(bool(full) and full.replace(" ", "").lower() == username.lower()),
        "description_length": float(len(str(item.get("biography") or ""))),
        "external_url": float(bool(item.get("externalUrl"))),
        "private": float(bool(item.get("private"))),
        "log_posts": math.log1p(posts), "log_followers": math.log1p(followers), "log_follows": math.log1p(follows),
    }


def dataset_features(row: dict) -> dict[str, float]:
    """Model inputs from one row of the public training CSV (InstaGuard / Kaggle column names)."""
    f = lambda k: float(row[k])  # noqa: E731
    return {
        "profile_pic": f("profile pic"), "username_digit_ratio": f("nums/length username"),
        "fullname_words": f("fullname words"), "fullname_digit_ratio": f("nums/length fullname"),
        "name_eq_username": f("name==username"), "description_length": f("description length"),
        "external_url": f("external URL"), "private": f("private"),
        "log_posts": math.log1p(f("#posts")), "log_followers": math.log1p(f("#followers")),
        "log_follows": math.log1p(f("#follows")),
    }


@lru_cache(maxsize=1)
def load(path: str | None = None) -> dict | None:
    """The trained model, or None when the file is missing or malformed (the check then simply does not run)."""
    try:
        m = json.loads(Path(path or MODEL_PATH).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if tuple(m.get("features") or ()) != FEATURES or not all(len(m.get(k) or ()) == len(FEATURES)
                                                             for k in ("mean", "scale", "coef")):
        return None
    return m


def predict(features: dict[str, float], model: dict | None = None) -> dict | None:
    """Probability that the profile is fake, plus the inputs that pushed it most (for the evidence text)."""
    m = model or load()
    if m is None or features is None:
        return None
    parts = [(name, (features[name] - mu) / (sd or 1.0), c)
             for name, mu, sd, c in zip(FEATURES, m["mean"], m["scale"], m["coef"])]
    z = m["intercept"] + sum(x * c for _, x, c in parts)
    prob = 1.0 / (1.0 + math.exp(-max(-30.0, min(30.0, z))))
    drivers = [LABELS[n][int(x > 0)] for n, x, c in sorted(parts, key=lambda p: -p[1] * p[2]) if x * c > 0.3][:3]
    return {"probability": round(prob, 3), "threshold": m["threshold"], "fake": prob >= m["threshold"],
            "drivers": drivers, "model_version": m.get("version")}
