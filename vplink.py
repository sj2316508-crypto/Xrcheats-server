"""vplink.in resolver with tolerant HTML and response parsing."""

from __future__ import annotations

import html as html_lib
import json
import os
import re
import sys
import time
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

from curl_cffi import requests
from .proxy import choose_proxy

IMPERSONATE = "chrome124"
MAX_ROUNDS = 6
MAX_STEPS = 12


def _clean(value: str | None, base_url: str | None = None) -> str | None:
    if not value:
        return None
    value = html_lib.unescape(value).strip().strip("\"' ")
    if not value or value.lower().startswith(("javascript:", "#", "data:")):
        return None
    return urljoin(base_url, value) if base_url else value


class _PageParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.tags: list[tuple[str, dict[str, str]]] = []
        self.form_stack: list[dict[str, str]] = []
        self.forms: list[tuple[dict[str, str], list[dict[str, str]]]] = []

    def handle_starttag(self, tag: str, attrs):
        attrs_dict = {str(k).lower(): str(v or "") for k, v in attrs}
        tag = tag.lower()
        self.tags.append((tag, attrs_dict))
        if tag == "form":
            self.form_stack.append(attrs_dict)
            self.forms.append((attrs_dict, []))
        elif tag == "input" and self.form_stack and self.forms:
            self.forms[-1][1].append(attrs_dict)

    def handle_startendtag(self, tag: str, attrs):
        self.handle_starttag(tag, attrs)
        if tag.lower() == "form" and self.form_stack:
            self.form_stack.pop()

    def handle_endtag(self, tag: str):
        if tag.lower() == "form" and self.form_stack:
            self.form_stack.pop()


def _parse(html: str) -> _PageParser:
    parser = _PageParser()
    try:
        parser.feed(html)
    except Exception:
        # The page is third-party HTML; partial parsing is still useful.
        pass
    return parser


def _target_from_json(text: str) -> str | None:
    try:
        value = json.loads(text)
    except (TypeError, ValueError):
        value = None

    def walk(item):
        if isinstance(item, dict):
            for key in ("url", "target", "destination", "link", "redirect"):
                result = _clean(str(item.get(key) or ""))
                if result and result.startswith(("http://", "https://")):
                    return result
            for child in item.values():
                result = walk(child)
                if result:
                    return result
        elif isinstance(item, list):
            for child in item:
                result = walk(child)
                if result:
                    return result
        return None

    result = walk(value)
    if result:
        return result

    # Some versions return JSON with escaped slashes but no content type.
    match = re.search(
        r"""https?:\\?/\\?/[^"'<>\\\s]+""",
        text,
        flags=re.IGNORECASE,
    )
    return _clean(match.group(0).replace("\\/", "/")) if match else None


def js_location(source: str, base_url: str | None = None) -> str | None:
    """Read JS/meta redirects, including relative and single-quoted values."""
    source = html_lib.unescape(source)
    patterns = (
        r"""(?:window\.)?location\s*\.\s*(?:href|replace)\s*"""
        r"""(?:=|\()\s*["']([^"']+)""",
        r"""(?:window\.)?location\s*=\s*["']([^"']+)""",
        r"""(?:window\.)?open\s*\(\s*["']([^"']+)""",
    )
    for pattern in patterns:
        match = re.search(pattern, source, flags=re.IGNORECASE)
        if match:
            return _clean(match.group(1), base_url)

    parser = _parse(source)
    for tag, attrs in parser.tags:
        if tag != "meta":
            continue
        if attrs.get("http-equiv", "").lower() != "refresh":
            continue
        match = re.search(r"url\s*=\s*(.+)$", attrs.get("content", ""), re.I)
        if match:
            return _clean(match.group(1).strip(" \"'"), base_url)
    return None


def _is_external(value: str | None, page_url: str) -> bool:
    if not value:
        return False
    candidate = urljoin(page_url, value)
    return candidate.startswith(("http://", "https://")) and (
        "vplink.in" not in (urlparse(candidate).netloc or "").lower()
    )


class VPLinkBypass:
    def __init__(self, wait=25.0, verbose=True):
        session_options = {"impersonate": IMPERSONATE}
        proxy = choose_proxy()
        if proxy:
            session_options["proxy"] = proxy
        self.s = requests.Session(**session_options)
        self.wait = wait
        self.verbose = verbose

    def log(self, *args):
        if self.verbose:
            print(*args, flush=True)

    def get(self, url, referer=None):
        headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0.0.0 Safari/537.36"
            ),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        }
        if referer:
            headers["Referer"] = referer
        response = self.s.get(
            url, headers=headers, timeout=40, allow_redirects=True
        )
        if response.status_code in (403, 429):
            suffix = " with proxy rotation" if proxy else " without a proxy"
            raise RuntimeError(
                f"vplink blocked request (HTTP {response.status_code}){suffix}"
            )
        if response.status_code >= 400:
            raise RuntimeError(f"HTTP {response.status_code} from {response.url}")
        return response

    def extract_destination(self, source, page_url):
        parser = _parse(source)
        for tag, attrs in parser.tags:
            element_id = attrs.get("id", "").lower()
            element_class = attrs.get("class", "").lower()
            is_target = (
                element_id in {"gt-link", "dl-link", "download", "target-link"}
                or "gt-link" in element_class
                or "download" in element_class
            )
            if not is_target:
                continue
            for key in ("href", "data-href", "data-url", "data-link"):
                destination = _clean(attrs.get(key), page_url)
                if _is_external(destination, page_url):
                    return destination

        # The server sometimes renders the destination only in inline JSON.
        destination = _target_from_json(source)
        if _is_external(destination, page_url):
            return destination

        return self.post_go(source, page_url)

    def _extract_direct_destination(self, source, page_url):
        """Extract only a rendered link/JSON value; never submit another form."""
        parser = _parse(source)
        for tag, attrs in parser.tags:
            element_id = attrs.get("id", "").lower()
            element_class = attrs.get("class", "").lower()
            is_target = (
                element_id in {"gt-link", "dl-link", "download", "target-link"}
                or "gt-link" in element_class
                or "download" in element_class
            )
            if not is_target:
                continue
            for key in ("href", "data-href", "data-url", "data-link"):
                destination = _clean(attrs.get(key), page_url)
                if _is_external(destination, page_url):
                    return destination
        destination = _target_from_json(source)
        return destination if _is_external(destination, page_url) else None

    def post_go(self, source, page_url):
        parser = _parse(source)
        for form_attrs, inputs in parser.forms:
            form_id = form_attrs.get("id", "").lower()
            form_class = form_attrs.get("class", "").lower()
            if form_id != "go-link" and "go-link" not in form_class:
                continue
            action = urljoin(page_url, form_attrs.get("action") or "/links/go")
            data = {
                item["name"]: item.get("value", "")
                for item in inputs
                if item.get("name")
            }
            if not data:
                continue
            time.sleep(11)
            response = self.s.post(
                action,
                data=data,
                timeout=40,
                headers={
                    "Referer": page_url,
                    "Origin": f"{urlparse(page_url).scheme}://{urlparse(page_url).netloc}",
                    "X-Requested-With": "XMLHttpRequest",
                    "Accept": "application/json, text/javascript, */*; q=0.01",
                },
            )
            destination = self._extract_direct_destination(
                response.text, str(response.url)
            )
            if _is_external(destination, page_url):
                return destination
        return None

    def blog_hop(self, landing_url, referer):
        response = self.get(landing_url, referer)
        article = js_location(response.text, str(response.url))
        if not article:
            raise RuntimeError(f"no article link on {landing_url}")
        origin = f"{urlparse(article).scheme}://{urlparse(article).netloc}/"
        self.get(article, origin)
        self.log("    article:", article)
        time.sleep(self.wait)
        response = self.get(urljoin(article, "learn_more.php"), article)
        next_url = js_location(response.text, str(response.url))
        if not next_url:
            raise RuntimeError("learn_more.php gave no next hop")
        return next_url, article

    def resolve(self, url):
        current, referer = url, None
        for round_number in range(MAX_ROUNDS):
            response = self.get(current, referer)
            source, current_url = response.text, str(response.url)
            self.log(f"[round {round_number}] {response.status_code} {current_url}")

            next_url = js_location(source, current_url)
            if not next_url:
                destination = self.extract_destination(source, current_url)
                if destination:
                    return destination
                raise RuntimeError(
                    "unlock page reached but no destination found "
                    f"(status={response.status_code}, url={current_url})"
                )

            last_article = None
            for _ in range(MAX_STEPS):
                next_url, last_article = self.blog_hop(
                    next_url, current_url if last_article is None else last_article
                )
                self.log("    ->", next_url)
                if "vplink.in" in (urlparse(next_url).netloc or "").lower():
                    break
            else:
                raise RuntimeError("blog chain did not return to vplink")
            current, referer = next_url, last_article
        raise RuntimeError("too many rounds")


def main():
    args = sys.argv[1:]
    wait, verbose = 25.0, True
    if "--quiet" in args:
        verbose = False
        args.remove("--quiet")
    if "--wait" in args:
        index = args.index("--wait")
        wait = float(args[index + 1])
        del args[index:index + 2]
    if not args:
        print(__doc__)
        sys.exit(1)
    print("FINAL:", VPLinkBypass(wait=wait, verbose=verbose).resolve(args[0]))


if __name__ == "__main__":
    main()