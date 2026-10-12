"""All routers, in registration order."""
from threatdesk.web import (
    api, assets, auth, brands, campaigns, cron, dashboard, findings, intake, investigate, reports, settings_page,
    takedown,
)

# brands before assets: /brands/{id}/whitelist and /scan must match before the generic /brands/{id}/{segment}.
ROUTERS = [auth.router, dashboard.router, settings_page.router, brands.router, assets.router, investigate.router,
           findings.router, cron.router, intake.router, takedown.router, campaigns.router, reports.router, api.router]

# POST routes without the CSRF dependency, and why (a test enumerates every POST route against this list).
CSRF_EXEMPT = {
    "/cron/tick": "machine endpoint authenticated by the X-Cron-Secret header; no cookies are used",
}
CSRF_EXEMPT_PREFIXES = ("/api/v1/",)    # API-key authenticated (Authorization: Bearer); cookies are ignored
