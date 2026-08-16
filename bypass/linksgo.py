"""linksgo.in resolver with tolerant unlock-page parsing."""

from __future__ import annotations

import asyncio
import os
import random
import re
from urllib.parse import urljoin, urlparse

from curl_cffi.requests import AsyncSession

from .proxy import choose_proxy, proxy_count
from .vplink import _clean, _is_external, _parse, _target_from_json, js_location

UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
]
IMPERSONATIONS = ["chrome120", "chrome124", "chrome116", "safari17_0"]
BASE = "https://linksgo.in"
BYPASS_PROXY = os.getenv("BYPASS_PROXY", "").strip()


def _headers(user_agent: str) -> dict[str, str]:
    return {
        "User-Agent": user_agent,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Upgrade-Insecure-Requests": "1",
    }


def extract_gt_link(source: str, page_url: str = BASE) -> str | None:
    parser = _parse(source)
    for tag, attrs in parser.tags:
        element_id = attrs.get("id", "").lower()
        element_class = attrs.get("class", "").lower()
        if not (
            element_id in {"gt-link", "download", "dl-link", "target-link"}
            or "gt-link" in element_class
            or "download" in element_class
        ):
            continue
        for key in ("href", "data-href", "data-url", "data-link"):
            target = _clean(attrs.get(key), page_url)
            if _is_external(target, page_url):
                return target

    target = _target_from_json(source)
    return target if _is_external(target, page_url) else None


def parse_form(source: str) -> tuple[str, dict[str, str]] | None:
    parser = _parse(source)
    for attrs, inputs in parser.forms:
        form_id = attrs.get("id", "").lower()
        form_class = attrs.get("class", "").lower()
        if form_id != "go-link" and "go-link" not in form_class:
            continue
        data = {
            item["name"]: item.get("value", "")
            for item in inputs
            if item.get("name")
        }
        if data:
            return attrs.get("action") or "/links/go", data
    return None


def next_hop(source: str, code: str, seen: set[str], base_url: str) -> str | None:
    redirect = js_location(source, base_url)
    if redirect and redirect not in seen:
        return redirect

    for candidate in re.findall(
        r"""https?://[^\s"'<>]+""", source, flags=re.IGNORECASE
    ):
        candidate = _clean(candidate, base_url)
        if (
            candidate
            and candidate not in seen
            and ("?" in candidate or code in candidate)
            and "example.com" not in candidate
        ):
            return candidate
    return None


async def _once(
    url: str,
    wait: float,
    impersonate: str,
    user_agent: str,
    verbose: bool,
) -> str:
    code = url.rstrip("/").split("/")[-1].split("?")[0]
    headers = _headers(user_agent)
    proxy = choose_proxy()
    session_options = {
        "verify": False,
        "impersonate": impersonate,
        "timeout": 40,
    }
    if proxy:
        session_options["proxy"] = proxy
    session = AsyncSession(**session_options)

    def log(*args):
        if verbose:
            print(*args, flush=True)

    def check_response(response, label: str):
        if response.status_code in (403, 429):
            suffix = " with proxy rotation" if proxy else " without a proxy"
            raise RuntimeError(
                f"{label} blocked by linksgo (HTTP {response.status_code}){suffix}"
            )
        return response

    async def try_unlock(source: str, page_url: str) -> str | None:
        direct = extract_gt_link(source, page_url)
        if direct:
            return direct

        form = parse_form(source)
        if not form:
            return None

        action, data = form
        action = urljoin(page_url, action)
        log("[+] Unlock page reached, waiting out the timer...")
        await asyncio.sleep(7)
        response = check_response(
            await session.post(
            action,
            data=data,
            headers={
                **headers,
                "Referer": page_url,
                "X-Requested-With": "XMLHttpRequest",
                "Origin": BASE,
                "Accept": "application/json, text/javascript, */*; q=0.01",
            },
            timeout=30,
            ),
            "unlock request",
        )
        target = _target_from_json(response.text) or extract_gt_link(
            response.text, str(response.url)
        )
        if not target:
            log(
                f"[-] unlock response {response.status_code}: "
                f"{response.text[:180]}"
            )
        return target

    try:
        log(f"[+] Session init ({impersonate})...")
        await session.get(BASE + "/", headers=headers, timeout=25)
        response = check_response(
            await session.get(
                url, headers={**headers, "Referer": BASE + "/"}, timeout=30
            ),
            "shortlink request",
        )
        log(
            f"[+] linksgo egress: "
            f"{'proxy pool (' + str(proxy_count()) + ')' if proxy else 'direct'}"
        )
        referer = str(response.url)
        seen = {url}

        for step in range(14):
            target = await try_unlock(response.text, referer)
            if target:
                return target
            next_url = next_hop(response.text, code, seen, referer)
            if not next_url:
                break
            seen.add(next_url)
            log(f"[+] Hop {step}: {next_url}")
            if "?" in next_url or ".php" in next_url:
                log(f"[*] Countdown wait {wait}s...")
                await asyncio.sleep(wait)
            response = check_response(
                await session.get(
                    next_url, headers={**headers, "Referer": referer}, timeout=40
                ),
                "chain request",
            )
            referer = str(response.url)

        for attempt in range(4):
            log(f"[+] Return to linksgo (try {attempt + 1})...")
            response = check_response(
                await session.get(
                    url, headers={**headers, "Referer": referer}, timeout=30
                ),
                "retry request",
            )
            target = await try_unlock(response.text, str(response.url))
            if target:
                return target
            await asyncio.sleep(7)

        raise RuntimeError(
            "linksgo unlock completed but no destination was returned; "
            "the site may require a fresh browser/session"
        )
    finally:
        await session.close()


async def bypass_linksgo(url: str, wait: float = 9, attempts: int = 3) -> str:
    last_error: Exception | None = None
    for attempt in range(attempts):
        impersonate = IMPERSONATIONS[attempt % len(IMPERSONATIONS)]
        user_agent = random.choice(UAS)
        try:
            target = await _once(
                url,
                wait + attempt * 4,
                impersonate,
                user_agent,
                verbose=True,
            )
            if target:
                return target
        except Exception as error:  # noqa: BLE001
            last_error = error
            print(
                f"[-] linksgo attempt {attempt + 1} failed: "
                f"{type(error).__name__}: {error}",
                flush=True,
            )
        if attempt + 1 < attempts:
            await asyncio.sleep(3)
    raise RuntimeError(
        f"linksgo bypass failed after {attempts} attempts ({last_error})"
    )