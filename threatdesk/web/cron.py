"""Machine endpoint for an external scheduler/pinger: POST /cron/tick with header X-Cron-Secret."""
from fastapi import APIRouter

router = APIRouter()
