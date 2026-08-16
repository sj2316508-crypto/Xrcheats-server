"""Safe parsing and rotation for optional outbound proxy settings."""

from __future__ import annotations

import os
import random
from urllib.parse import quote

# Hardcoded Webshare proxies (host:port:username:password).
# Used automatically if no BYPASS_PROXIES / BYPASS_PROXY / BYPASS_PROXY_FILE env var is set.
HARDCODED_PROXIES = [
    "31.59.20.176:6754:odkefkzz:70sb4o6gorad",
    "31.56.127.193:7684:odkefkzz:70sb4o6gorad",
    "45.38.107.97:6014:odkefkzz:70sb4o6gorad",
    "198.105.121.200:6462:odkefkzz:70sb4o6gorad",
    "64.137.96.74:6641:odkefkzz:70sb4o6gorad",
    "198.23.243.226:6361:odkefkzz:70sb4o6gorad",
    "38.154.185.97:6370:odkefkzz:70sb4o6gorad",
    "84.247.60.125:6095:odkefkzz:70sb4o6gorad",
    "142.111.67.146:5611:odkefkzz:70sb4o6gorad",
    "191.96.254.138:6185:odkefkzz:70sb4o6gorad",
]


def _as_url(line: str) -> str | None:
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    # Webshare exports: host:port:username:password
    parts = line.split(":", 3)
    if len(parts) == 4 and parts[1].isdigit() and "://" not in line:
        host, port, username, password = parts
        return (
            "http://"
            f"{quote(username, safe='')}:{quote(password, safe='')}"
            f"@{host}:{port}"
        )

    if "://" not in line:
        return "http://" + line
    return line


def get_proxy_pool() -> list[str]:
    raw = os.getenv("BYPASS_PROXIES", "").strip()
    if not raw:
        raw = os.getenv("BYPASS_PROXY", "").strip()
    if not raw:
        file_path = os.getenv("BYPASS_PROXY_FILE", "").strip()
        if file_path:
            try:
                with open(file_path, encoding="utf-8") as proxy_file:
                    raw = proxy_file.read()
            except OSError:
                raw = ""
    proxies = []
    for line in raw.replace(",", "\n").splitlines():
        proxy = _as_url(line)
        if proxy:
            proxies.append(proxy)
    if not proxies:
        for line in HARDCODED_PROXIES:
            proxy = _as_url(line)
            if proxy:
                proxies.append(proxy)
    return proxies


def choose_proxy() -> str | None:
    proxies = get_proxy_pool()
    return random.choice(proxies) if proxies else None


def proxy_count() -> int:
    return len(get_proxy_pool())