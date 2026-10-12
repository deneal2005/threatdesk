"""Optional page screenshot (ENABLE_SCREENSHOTS=true, Playwright installed separately). Off by default.

Every request the headless browser makes is checked by the SSRF guard first; anything else is aborted.
"""
from __future__ import annotations

import base64
import hashlib

from threatdesk.config import get_settings
from threatdesk.safety import UnsafeURL, check_url


class ScreenshotUnavailable(Exception):
    pass


async def capture(url: str) -> dict:
    if not get_settings().enable_screenshots:
        raise ScreenshotUnavailable("screenshots are turned off (ENABLE_SCREENSHOTS=false)")
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        raise ScreenshotUnavailable("Playwright is not installed on this server")
    await check_url(url)

    async def guard(route):
        try:
            await check_url(route.request.url)
            await route.continue_()
        except UnsafeURL:
            await route.abort()

    async with async_playwright() as pw:
        browser = await pw.chromium.launch()
        try:
            page = await browser.new_page(viewport={"width": 1280, "height": 860}, java_script_enabled=False)
            await page.route("**/*", guard)
            await page.goto(url, timeout=15000, wait_until="load")
            png = await page.screenshot(full_page=False)
        finally:
            await browser.close()
    return {"url": url, "png_base64": base64.b64encode(png).decode(), "sha256": hashlib.sha256(png).hexdigest(),
            "bytes": len(png)}
