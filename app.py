"""Vercel entrypoint: Vercel's FastAPI support looks for an `app` instance in a root-level app.py."""
from threatdesk.main import app  # noqa: F401
