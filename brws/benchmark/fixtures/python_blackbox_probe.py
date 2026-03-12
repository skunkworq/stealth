#!/usr/bin/env python3
import argparse
import asyncio
import json
import sys


def emit_availability(available: bool, reason: str = "") -> int:
    print(json.dumps({"available": available, "reason": reason}))
    return 0 if available else 11


def run_scrapy(url: str) -> int:
    try:
        import scrapy
        from scrapy.crawler import CrawlerProcess
    except Exception as exc:  # pragma: no cover - depends on local env
        return emit_availability(False, f"scrapy unavailable: {exc}")

    class ProbeSpider(scrapy.Spider):
        name = "blackbox_probe"
        custom_settings = {
            "LOG_ENABLED": False,
            "TELNETCONSOLE_ENABLED": False,
            "RETRY_ENABLED": False,
        }
        start_urls = [url]

        def parse(self, response):
            sys.stdout.write(response.text)

    process = CrawlerProcess(settings={"LOG_ENABLED": False, "TELNETCONSOLE_ENABLED": False})
    process.crawl(ProbeSpider)
    process.start()
    return 0


async def run_nodriver(url: str, wait_ms: int) -> int:
    try:
        import nodriver as uc
    except Exception as exc:  # pragma: no cover - depends on local env
        return emit_availability(False, f"nodriver unavailable: {exc}")

    browser = await uc.start(headless=True)
    try:
        page = await browser.get(url)
        await asyncio.sleep(wait_ms / 1000)
        text = ""
        try:
            text = await page.evaluate(
                "document.body ? (document.body.innerText || document.body.textContent || '') : ''"
            )
        except Exception:
            if hasattr(page, "get_content"):
                text = await page.get_content()
        sys.stdout.write((text or "").strip())
        return 0
    finally:
        stop = getattr(browser, "stop", None)
        if stop is not None:
            maybe_awaitable = stop()
            if asyncio.iscoroutine(maybe_awaitable):
                await maybe_awaitable


def run_scrapling(url: str, tool: str) -> int:
    try:
        from scrapling.fetchers import DynamicFetcher, StealthyFetcher
    except Exception as exc:  # pragma: no cover - depends on local env
        return emit_availability(False, f"scrapling unavailable: {exc}")

    fetcher = StealthyFetcher if tool == "scrapling_stealthy" else DynamicFetcher
    page = fetcher.fetch(url)

    for attr in ("text", "html", "content"):
        value = getattr(page, attr, None)
        if callable(value):
            try:
                value = value()
            except TypeError:
                value = None
        if value:
            sys.stdout.write(str(value))
            return 0

    sys.stdout.write(str(page))
    return 0


def check_tool(tool: str) -> int:
    if tool == "scrapy_default":
        try:
            import scrapy  # noqa: F401
        except Exception as exc:  # pragma: no cover - depends on local env
            return emit_availability(False, f"scrapy unavailable: {exc}")
        return emit_availability(True)

    if tool == "nodriver":
        try:
            import nodriver  # noqa: F401
        except Exception as exc:  # pragma: no cover - depends on local env
            return emit_availability(False, f"nodriver unavailable: {exc}")
        return emit_availability(True)

    if tool in {"scrapling_stealthy", "scrapling_playwright"}:
        try:
            import scrapling  # noqa: F401
        except Exception as exc:  # pragma: no cover - depends on local env
            return emit_availability(False, f"scrapling unavailable: {exc}")
        return emit_availability(True)

    return emit_availability(False, f"unknown tool: {tool}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tool", required=True)
    parser.add_argument("--url")
    parser.add_argument("--wait-ms", type=int, default=1500)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()

    if args.check:
        return check_tool(args.tool)
    if not args.url:
        return emit_availability(False, "missing --url")

    if args.tool == "scrapy_default":
        return run_scrapy(args.url)
    if args.tool == "nodriver":
        return asyncio.run(run_nodriver(args.url, args.wait_ms))
    if args.tool in {"scrapling_stealthy", "scrapling_playwright"}:
        return run_scrapling(args.url, args.tool)

    return emit_availability(False, f"unknown tool: {args.tool}")


if __name__ == "__main__":
    raise SystemExit(main())
