"""Resolver registry for the Bypass API."""

import asyncio
import inspect
import os
from urllib.parse import urlparse

from .linksgo import bypass_linksgo
from .vplink import VPLinkBypass

VPLINK_WAIT = float(os.getenv("VPLINK_WAIT", "15"))
LINKSGO_WAIT = float(os.getenv("LINKSGO_WAIT", "9"))
EARNLINKS_WAIT = float(os.getenv("EARNLINKS_WAIT", "8"))
RETRIES = int(os.getenv("BYPASS_RETRIES", "2"))


def _vplink(url: str) -> str:
    return VPLinkBypass(wait=VPLINK_WAIT, verbose=True).resolve(url)


async def _linksgo(url: str) -> str:
    return await bypass_linksgo(url, wait=LINKSGO_WAIT)


async def _earnlinks(url: str) -> str:
    from .earnlinks import bypass_earnlinks

    return await bypass_earnlinks(url, wait=EARNLINKS_WAIT)


def _urlking(url: str) -> str:
    try:
        from .urlking import bypass_urlking
    except Exception as error:  # noqa: BLE001
        raise RuntimeError(
            "urlking needs playwright and Chromium installed: "
            f"{error}"
        ) from error
    return bypass_urlking(url)


RESOLVERS = {
    "earnlinks.in": _earnlinks,
    "linksgo.in": _linksgo,
    "vplink.in": _vplink,
    "viku.urlking.in": _urlking,
    "urlking.in": _urlking,
}
SUPPORTED = sorted(RESOLVERS)


def _host(url: str) -> str:
    host = (urlparse(url).netloc or "").lower().split(":", 1)[0]
    return host[4:] if host.startswith("www.") else host


def get_resolver(url: str):
    host = _host(url)
    if host in RESOLVERS:
        return RESOLVERS[host]
    for domain, resolver in RESOLVERS.items():
        if host.endswith("." + domain):
            return resolver
    return None


async def _call(fn, url: str) -> str:
    if inspect.iscoroutinefunction(fn):
        return await fn(url)
    return await asyncio.to_thread(fn, url)


async def bypass(url: str) -> str:
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    resolver = get_resolver(url)
    if resolver is None:
        raise ValueError(
            f"Unsupported site '{_host(url)}'. Supported: {', '.join(SUPPORTED)}"
        )

    last_error: Exception | None = None
    for attempt in range(max(1, RETRIES)):
        try:
            destination = await _call(resolver, url)
            if destination:
                return destination
            last_error = RuntimeError("resolver returned no destination")
        except Exception as error:  # noqa: BLE001
            last_error = error
            print(
                f"[!] attempt {attempt + 1} failed: "
                f"{type(error).__name__}: {error}",
                flush=True,
            )
        if attempt + 1 < max(1, RETRIES):
            await asyncio.sleep(2)

    raise last_error or RuntimeError("bypass failed")
