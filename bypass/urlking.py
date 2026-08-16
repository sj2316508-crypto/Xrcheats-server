"""
urlking (viku.urlking.in) bypass.

Unlike earnlinks/linksgo, urlking sits behind an *interactive* Cloudflare
Turnstile challenge ("Verify you are human"), so a pure curl_cffi session gets
403 on every request. This script therefore has two stages:

  Stage 1 - Playwright opens the link in a real browser and waits until the
            Cloudflare challenge is cleared (cf_clearance cookie issued).
  Stage 2 - the browser cookies + the exact browser User-Agent are handed to a
            curl_cffi session, which then walks the usual blog / countdown
            ad-gate chain and POSTs the go-link form to /links/go.

If the whole flow already resolves inside the browser (some urlking links just
redirect to the destination once the challenge is passed), stage 2 is skipped.

Requirements:
    pip install curl_cffi playwright && playwright install chromium

Usage:
    python urlking_bypass.py https://viku.urlking.in/rocky
    python urlking_bypass.py https://viku.urlking.in/rocky --headful   # if CF loops

NOTE: Cloudflare blocks datacenter/VPS IPs hard. Run this from a normal
residential connection; on a server the challenge never resolves.
"""

import asyncio
import re
import sys
from urllib.parse import urlparse

from curl_cffi.requests import AsyncSession

HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}
DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
)


# --------------------------------------------------------------------------- #
# parsing helpers (same shape as the earnlinks / linksgo scripts)
# --------------------------------------------------------------------------- #
def extract_gt_link(html: str) -> str | None:
    m = re.search(r'<a[^>]*id=["\'](?:gt-link|dl-link)["\'][^>]*>', html, re.I)
    if m:
        mh = re.search(r'href=["\']([^"\']+)["\']', m.group(0), re.I)
        if mh and "javascript" not in mh.group(1):
            return mh.group(1)
    return None


def parse_form(html: str) -> dict[str, str] | None:
    f = re.search(r'<form[^>]*id="go-link"[\s\S]*?</form>', html)
    if not f:
        return None
    data = {}
    for m in re.finditer(r'<input[^>]*name="([^"]+)"[^>]*value="([^"]*)"', f.group(0)):
        data[m.group(1)] = m.group(2)
    return data or None


def next_hop(html: str, code: str, seen: set[str]) -> str | None:
    m = re.search(
        r'<meta[^>]+http-equiv=["\']refresh["\'][^>]*content=["\'][^"\']*URL=[\'"]?(https?://[^"\'>]+)',
        html, re.I)
    if m and m.group(1) not in seen:
        return m.group(1)
    m = re.search(r'window\.location\.href\s*=\s*["\'](https?://[^"\']+)', html)
    if m and "example.com" not in m.group(1) and m.group(1) not in seen:
        return m.group(1)
    for c in re.findall(r'https?://[^\s"\'<>]+\?[a-z]+=' + re.escape(code), html):
        if c not in seen:
            return c
    return None


# --------------------------------------------------------------------------- #
# stage 1: clear Cloudflare with a real browser
# --------------------------------------------------------------------------- #
async def clear_cloudflare(url: str, headless: bool = True, timeout: int = 90):
    """Return (cookies dict, user_agent, final_url, final_html)."""
    from playwright.async_api import async_playwright

    async with async_playwright() as p:
        browser = await p.chromium.launch(
            headless=headless,
            args=["--disable-blink-features=AutomationControlled", "--no-sandbox"],
        )
        ctx = await browser.new_context(
            viewport={"width": 1280, "height": 900},
            user_agent=DEFAULT_UA,
            locale="en-US",
        )
        page = await ctx.new_page()
        await page.add_init_script(
            "Object.defineProperty(navigator,'webdriver',{get:()=>undefined})"
        )
        print(f"[+] Opening {url} in browser to clear Cloudflare...")
        await page.goto(url, wait_until="domcontentloaded", timeout=60000)

        waited = 0
        while waited < timeout:
            title = await page.title()
            if "Just a moment" not in title and "Attention Required" not in title:
                break
            # click the Turnstile checkbox if the widget is rendered
            box = await page.evaluate(
                "()=>{const d=[...document.querySelectorAll('div')]"
                ".find(e=>e.shadowRoot);if(!d)return null;"
                "const r=d.getBoundingClientRect();"
                "return {x:r.x,y:r.y,h:r.height};}"
            )
            if box:
                await page.mouse.move(box["x"] + 30, box["y"] + box["h"] / 2, steps=12)
                await asyncio.sleep(0.4)
                await page.mouse.click(box["x"] + 30, box["y"] + box["h"] / 2)
                print("[*] Clicked the 'Verify you are human' checkbox...")
            await asyncio.sleep(4)
            waited += 4
        else:
            await browser.close()
            raise RuntimeError(
                "Cloudflare challenge never cleared. Run with --headful, and from a "
                "residential IP (datacenter/VPS IPs are hard-blocked)."
            )

        # give any post-challenge redirect a moment to settle
        await asyncio.sleep(4)
        cookies = {c["name"]: c["value"] for c in await ctx.cookies()}
        final_url, html = page.url, await page.content()
        print(f"[+] Cloudflare cleared. Landed on: {final_url}")
        await browser.close()
        return cookies, DEFAULT_UA, final_url, html


# --------------------------------------------------------------------------- #
# stage 2: walk the ad-gate chain with the cleared session
# --------------------------------------------------------------------------- #
async def bypass_urlking(url: str, wait: int = 12, headless: bool = True) -> str:
    code = url.rstrip("/").split("/")[-1].split("?")[0]
    base = f"{urlparse(url).scheme}://{urlparse(url).netloc}"

    cookies, ua, landed, html = await clear_cloudflare(url, headless=headless)

    # the browser may already have been redirected straight to the destination
    if urlparse(landed).netloc not in (urlparse(url).netloc, ""):
        if not parse_form(html) and "Just a moment" not in html:
            gt = extract_gt_link(html)
            if gt:
                print(f"[+] SUCCESS! Bypassed link: {gt}")
                return gt

    s = AsyncSession(verify=False, impersonate="chrome120", cookies=cookies)
    H = {**HEADERS, "User-Agent": ua}

    async def try_unlock(page_html: str, referer: str) -> str | None:
        form = parse_form(page_html)
        if not form:
            return extract_gt_link(page_html)
        print("[+] Reached the unlock page, waiting out the timer...")
        await asyncio.sleep(6)
        post = await s.post(
            f"{base}/links/go",
            data=form,
            headers={**H, "Referer": referer, "Origin": base,
                     "X-Requested-With": "XMLHttpRequest"},
            timeout=25,
        )
        try:
            j = post.json()
        except Exception:
            j = {}
        target = j.get("url") or extract_gt_link(post.text)
        if not target:
            print(f"[-] Unexpected /links/go response: {post.status_code} {post.text[:200]}")
        return target

    try:
        r = await s.get(url, headers=H, timeout=30)
        if r.status_code == 403:
            raise RuntimeError("Session still blocked by Cloudflare after clearance.")
        ref = str(r.url)
        seen: set[str] = {url}

        for step in range(12):
            target = await try_unlock(r.text, url)
            if target:
                print(f"[+] SUCCESS! Bypassed link: {target}")
                return target

            nxt = next_hop(r.text, code, seen)
            if nxt is None:
                break
            seen.add(nxt)
            print(f"[+] Hop {step}: {nxt}")
            if "?" in nxt or ".php" in nxt:
                print(f"[*] Waiting {wait}s for countdown timer...")
                await asyncio.sleep(wait)
            r = await s.get(nxt, headers={**H, "Referer": ref}, timeout=30)
            ref = nxt

        for attempt in range(3):
            print(f"[+] Returning to the urlking page (attempt {attempt + 1})...")
            rr = await s.get(url, headers={**H, "Referer": ref}, timeout=25)
            target = await try_unlock(rr.text, url)
            if target:
                print(f"[+] SUCCESS! Bypassed link: {target}")
                return target
            await asyncio.sleep(6)

        raise ValueError("Target link not found; the ad-gate chain did not unlock.")
    finally:
        await s.close()


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if not args:
        print("Usage: python urlking_bypass.py <urlking_url> [--headful]")
        sys.exit(1)
    try:
        res = asyncio.run(bypass_urlking(args[0], headless="--headful" not in sys.argv))
        print(f"\nFinal Link: {res}")
    except Exception as e:
        print(f"\n[-] Error during bypass: {e}")
        sys.exit(1)
