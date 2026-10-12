import os

os.environ["THREATDESK_TESTING"] = "1"
os.environ.pop("DATABASE_URL", None)
for k in ("GEMINI_API_KEY", "YOUTUBE_API_KEY", "SAFE_BROWSING_API_KEY", "VT_API_KEY", "URLHAUS_AUTH_KEY",
          "GOOGLE_CSE_KEY", "GOOGLE_CSE_CX", "BRAVE_API_KEY", "WEBHOOK_URL", "SMTP_HOST", "CRON_SECRET",
          "APIFY_TOKEN", "PHISHTANK_APP_KEY", "APPLE_APP_STORE_SEARCH_API"):   # never use real keys in tests
    os.environ[k] = ""

import pytest  # noqa: E402

from threatdesk import config, db  # noqa: E402


@pytest.fixture(autouse=True)
def fresh_db():
    config._settings = None
    config.get_settings()
    db.reset_engine("sqlite+pysqlite:///:memory:")
    db.create_all()
    yield
