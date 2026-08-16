import asyncio
import re
import sys
from curl_cffi.requests import AsyncSession

from .proxy import choose_proxy

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
}


def extract_gt_link(html: str) -> str | None:
    m = re.search(r'<a[^>]*id=["\']gt-link["\'][^>]*>', html, re.I)
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
    m = re.search(r'window\.location\.href\s*=\s*["\'](https?://[^"\']+)', html)
    if m and "example.com" not in m.group(1) and m.group(1) not in seen:
        return m.group(1)
    a = re.search(
        r'<a[^>]+href=["\'](https?://[^"\']+)["\'][^>]*>[\s\S]{0,300}?id=["\']tp-snp2', html
    )
    if a and a.group(1) not in seen:
        return a.group(1)
    for c in re.findall(r'https?://[^\s"\'<>]+\?[a-z]+=' + re.escape(code), html):
        if c not in seen:
            return c
    return None


async def bypass_earnlinks(url: str, wait: float = 8, s: AsyncSession | None = None) -> str:
    """Bypass earnlinks.in by traversing the itiexamshala blog/countdown chain."""
    code = url.rstrip("/").split("/")[-1].split("?")[0]
    close_session = s is None
    if s is None:
        proxy = choose_proxy()
        session_options = {"verify": False, "impersonate": "chrome120"}
        if proxy:
            session_options["proxy"] = proxy
        s = AsyncSession(**session_options)

    try:
        print("[+] Initializing session on earnlinks homepage...")
        await s.get("https://earnlinks.in/", headers=HEADERS, timeout=20)

        print(f"[+] GET initial earnlinks URL: {url}")
        r = await s.get(url, headers=HEADERS, timeout=20)
        ref = url
        seen: set[str] = set()

        for step in range(12):
            form = parse_form(r.text)
            if form:
                print("[+] Reached earnlinks unlock page, waiting out the 5s timer...")
                await asyncio.sleep(6)
                post = await s.post(
                    "https://earnlinks.in/links/go",
                    data=form,
                    headers={**HEADERS, "Referer": url, "X-Requested-With": "XMLHttpRequest",
                             "Origin": "https://earnlinks.in"},
                    timeout=25,
                )
                try:
                    j = post.json()
                except Exception:
                    j = {}
                target = j.get("url") or extract_gt_link(post.text)
                if target:
                    print(f"[+] SUCCESS! Bypassed link: {target}")
                    return target
                print(f"[-] Unexpected /links/go response: {post.status_code} {post.text[:300]}")

            found = extract_gt_link(r.text)
            if found:
                print(f"[+] SUCCESS! Bypassed link: {found}")
                return found

            nxt = next_hop(r.text, code, seen)
            if nxt is None:
                break

            seen.add(nxt)
            print(f"[+] Hop {step}: {nxt}")
            if ".php" in nxt or "?" in nxt:
                print(f"[*] Waiting {wait}s for countdown timer...")
                await asyncio.sleep(wait)
            r = await s.get(nxt, headers={**HEADERS, "Referer": ref}, timeout=25)
            ref = nxt

        # Return to earnlinks to collect the unlocked link
        for attempt in range(3):
            print(f"[+] Returning to earnlinks page (attempt {attempt + 1})...")
            rr = await s.get(url, headers={**HEADERS, "Referer": ref}, timeout=20)
            form = parse_form(rr.text)
            if form:
                await asyncio.sleep(6)
                post = await s.post(
                    "https://earnlinks.in/links/go", data=form,
                    headers={**HEADERS, "Referer": url, "X-Requested-With": "XMLHttpRequest",
                             "Origin": "https://earnlinks.in"}, timeout=25)
                try:
                    target = post.json().get("url")
                except Exception:
                    target = None
                if target:
                    print(f"[+] SUCCESS! Bypassed link: {target}")
                    return target
            found = extract_gt_link(rr.text)
            if found:
                print(f"[+] SUCCESS! Bypassed link: {found}")
                return found
            await asyncio.sleep(6)

        raise ValueError("Target gt-link not found; the ad-gate chain did not unlock.")
    finally:
        if close_session:
            await s.close()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python earnlinks_bypass.py <earnlinks_url>")
        sys.exit(1)
    try:
        res = asyncio.run(bypass_earnlinks(sys.argv[1]))
        print(f"\nFinal Link: {res}")
    except Exception as e:
        print(f"\n[-] Error during bypass: {e}")
        sys.exit(1)
