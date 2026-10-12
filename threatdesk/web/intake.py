"""Public customer report form /report/<token>: no login, honeypot, 5/hour/IP, neutral receipt."""
from fastapi import APIRouter

router = APIRouter()
