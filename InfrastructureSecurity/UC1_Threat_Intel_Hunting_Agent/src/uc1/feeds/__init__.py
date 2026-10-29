"""Feed registry: run every enabled feed; one failing feed never stops the others."""

from __future__ import annotations

import logging

from uc1.config import read_csv
from uc1.feeds import advisories, attack, iocs, nvd
from uc1.feeds.common import FeedContext, FeedSkipped

log = logging.getLogger("uc1.feeds")

FEEDS = {
    "attack": attack.collect,
    "nvd": nvd.collect,
    "ncsc_nl": lambda ctx: advisories.collect_rss(ctx, "ncsc_nl"),
    "cert_eu": lambda ctx: advisories.collect_rss(ctx, "cert_eu"),
    "msrc": advisories.collect_msrc,
    "abusech": iocs.collect_abusech,
    "otx": iocs.collect_otx,
    "lab_test": iocs.load_lab_test_iocs,
}


def enabled_feeds() -> list[str]:
    """Feeds switched on in config/feeds.csv (all on if the file is missing)."""
    rows = read_csv("feeds.csv")
    if not rows:
        return list(FEEDS)
    on = {r["feed"] for r in rows if r.get("enabled", "yes").lower() in ("yes", "true", "1")}
    return [f for f in FEEDS if f in on]


def collect_all(ctx: FeedContext, only: list[str] | None = None) -> dict[str, str]:
    results: dict[str, str] = {}
    for name in only or enabled_feeds():
        try:
            outcome = FEEDS[name](ctx)
            results[name] = f"ok ({outcome if not isinstance(outcome, dict) else outcome})"
            log.info("Feed %s: %s", name, results[name])
        except FeedSkipped as exc:
            ctx.store.save_feed_state(name, "skipped", 0, error=str(exc))
            results[name] = f"skipped: {exc}"
        except Exception as exc:   # noqa: BLE001 - a feed failure must not stop the run
            message = str(exc).splitlines()[0][:300]
            ctx.store.save_feed_state(name, "error", 0, error=message)
            results[name] = f"FAILED: {message}"
            log.warning("Feed %s failed: %s", name, message)
    return results
