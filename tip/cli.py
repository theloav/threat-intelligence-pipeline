"""
threat-intel-pipeline CLI  (tip)

Entry point: tip.cli:main
"""
from __future__ import annotations

import asyncio
import json
import sys
from datetime import datetime, timedelta

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box
from rich.live import Live
from rich.align import Align

console = Console()


def _get_settings():
    from tip.core.config import get_settings
    return get_settings()


def _build_clients(settings):
    """Build all service clients from settings."""
    from tip.misp.client import MISPClient
    from tip.misp.dedup_cache import DedupCache
    from tip.siem.elastic_client import ElasticClient
    from tip.siem.sentinel_client import SentinelClient
    from tip.notification.slack_notifier import SlackNotifier
    from tip.enrichment.misp_lookup import MISPLookup
    from tip.enrichment.tag_writer import TagWriter
    from tip.enrichment.alert_enricher import AlertEnricher

    misp = MISPClient(settings)
    cache = DedupCache(settings)
    elastic = ElasticClient(settings) if settings.elastic_url else None
    sentinel = SentinelClient(settings) if settings.sentinel_subscription_id else None
    slack = SlackNotifier(settings)
    lookup = MISPLookup(misp)
    tag_writer = TagWriter(sentinel, elastic)
    enricher = AlertEnricher(
        misp_lookup=lookup,
        tag_writer=tag_writer,
        sentinel_client=sentinel,
        elastic_client=elastic,
        slack_notifier=slack,
        notify_on=settings.slack_notify_on,
    )
    return misp, cache, elastic, sentinel, slack, lookup, enricher


@click.group()
@click.version_option("0.1.0", prog_name="tip")
def main():
    """
    \b
    ████████╗██╗██████╗
       ██╔══╝██║██╔══██╗
       ██║   ██║██████╔╝
       ██║   ██║██╔═══╝
       ██║   ██║██║
       ╚═╝   ╚═╝╚═╝  Threat Intelligence Pipeline

    Ingest → Normalise → Store → Enrich → Notify
    """


# ---------------------------------------------------------------------------
# tip run
# ---------------------------------------------------------------------------
@main.command("run")
@click.option("--feeds/--no-feeds", default=True, help="Run feed ingestion")
@click.option("--enrich/--no-enrich", default=True, help="Run alert enrichment")
@click.option("--alert-window", default=60, show_default=True, help="Look back N minutes for alerts")
@click.option("--verbose", is_flag=True, help="Show each IOC as it's processed")
def cmd_run(feeds: bool, enrich: bool, alert_window: int, verbose: bool):
    """Full pipeline: ingest feeds → enrich SIEM alerts → send Slack notifications."""
    settings = _get_settings()
    asyncio.run(_run_pipeline(settings, feeds, enrich, alert_window, verbose))


async def _run_pipeline(settings, run_feeds: bool, run_enrich: bool, alert_window: int, verbose: bool):
    from tip.misp.client import MISPClient
    from tip.misp.dedup_cache import DedupCache
    from tip.feeds.feed_scheduler import FeedScheduler
    from tip.notification.slack_notifier import SlackNotifier
    from tip.enrichment.misp_lookup import MISPLookup
    from tip.enrichment.tag_writer import TagWriter
    from tip.enrichment.alert_enricher import AlertEnricher
    from tip.siem.elastic_client import ElasticClient
    from tip.siem.sentinel_client import SentinelClient

    console.print(Panel.fit("[bold cyan]🚀 Threat Intelligence Pipeline[/bold cyan]", border_style="cyan"))

    misp = MISPClient(settings)
    cache = DedupCache(settings)
    slack = SlackNotifier(settings)
    elastic = ElasticClient(settings)
    sentinel = SentinelClient(settings)

    if run_feeds:
        console.rule("[cyan]Feed Ingestion[/cyan]")
        scheduler = FeedScheduler(settings, misp, cache)
        results = await scheduler.run_once("all")

        table = Table(title="Ingestion Results", box=box.ROUNDED)
        table.add_column("Feed", style="cyan")
        table.add_column("Fetched", justify="right")
        table.add_column("New", justify="right", style="green")
        table.add_column("Dupes", justify="right", style="yellow")
        table.add_column("Stored", justify="right", style="green")
        table.add_column("Errors", justify="right", style="red")
        table.add_column("Duration", justify="right")

        for r in results:
            table.add_row(
                r.feed_name,
                str(r.total_fetched),
                str(r.new_iocs),
                str(r.duplicate_iocs),
                str(r.stored_in_misp),
                str(r.errors),
                f"{r.duration_seconds():.1f}s",
            )
        console.print(table)

    if run_enrich:
        console.rule("[cyan]Alert Enrichment[/cyan]")
        lookup = MISPLookup(misp)
        tag_writer = TagWriter(sentinel, elastic)
        enricher = AlertEnricher(
            misp_lookup=lookup,
            tag_writer=tag_writer,
            sentinel_client=sentinel if sentinel.is_configured() else None,
            elastic_client=elastic if elastic.is_configured() else None,
            slack_notifier=slack,
            notify_on=settings.slack_notify_on,
        )
        summary = await enricher.run_enrichment_cycle(alert_window)

        table = Table(title="Enrichment Summary", box=box.ROUNDED)
        table.add_column("Metric")
        table.add_column("Value", justify="right")
        table.add_row("Elastic alerts processed", str(summary["elastic"]))
        table.add_row("Sentinel alerts processed", str(summary["sentinel"]))
        table.add_row("Total alerts", str(summary["total"]))
        table.add_row("[green]IOC matches found[/green]", str(summary["matched"]))
        table.add_row("[cyan]Slack notifications sent[/cyan]", str(summary["notified"]))
        console.print(table)

    console.print("[bold green]✅ Pipeline run complete.[/bold green]")


# ---------------------------------------------------------------------------
# tip feeds
# ---------------------------------------------------------------------------
@main.group("feeds")
def feeds_group():
    """Feed ingestion commands."""


@feeds_group.command("run")
@click.option("--feed", type=click.Choice(["otx", "abusech", "all"]), default="all", show_default=True)
def cmd_feeds_run(feed: str):
    """Run feed ingestion once (no scheduler)."""
    settings = _get_settings()
    asyncio.run(_feeds_run(settings, feed))


async def _feeds_run(settings, feed_name: str):
    from tip.misp.client import MISPClient
    from tip.misp.dedup_cache import DedupCache
    from tip.feeds.feed_scheduler import FeedScheduler

    misp = MISPClient(settings)
    cache = DedupCache(settings)
    scheduler = FeedScheduler(settings, misp, cache)

    console.print(f"[cyan]Running {feed_name} feed(s)...[/cyan]")
    results = await scheduler.run_once(feed_name)

    for r in results:
        status = "✅" if r.errors == 0 else "⚠️"
        console.print(
            f"{status} [bold]{r.feed_name}[/bold]: "
            f"{r.new_iocs} new, {r.duplicate_iocs} dupes, "
            f"{r.stored_in_misp} stored, {r.errors} errors "
            f"({r.duration_seconds():.1f}s)"
        )
        if r.error_details:
            for err in r.error_details[:3]:
                console.print(f"  [red]• {err}[/red]")


@feeds_group.command("status")
def cmd_feeds_status():
    """Show feed status and cache stats."""
    settings = _get_settings()
    asyncio.run(_feeds_status(settings))


async def _feeds_status(settings):
    from tip.misp.dedup_cache import DedupCache
    from tip.feeds.otx_feed import OTXFeed
    from tip.feeds.abusech_feed import AbuseCHFeed

    cache = DedupCache(settings)
    stats = await cache.stats()

    otx = OTXFeed(settings)
    abusech = AbuseCHFeed(settings)

    otx_ok = await otx.health_check()
    abusech_ok = await abusech.health_check()

    table = Table(title="Feed & Cache Status", box=box.ROUNDED)
    table.add_column("Feed")
    table.add_column("Status")
    table.add_row("OTX (AlienVault)", "✅ reachable" if otx_ok else "❌ unreachable")
    table.add_row("Abuse.ch", "✅ reachable" if abusech_ok else "❌ unreachable")
    console.print(table)

    console.print(f"\n[bold]Cache:[/bold] {stats['backend']} backend | "
                  f"{stats['total_entries']} entries | TTL {stats['ttl_days']} days")
    if stats.get("by_type"):
        for t, count in stats["by_type"].items():
            console.print(f"  {t}: {count}")


# ---------------------------------------------------------------------------
# tip enrich
# ---------------------------------------------------------------------------
@main.command("enrich")
@click.option("--siem", type=click.Choice(["sentinel", "elastic", "all"]), default="all", show_default=True)
@click.option("--since", default=None, help="ISO datetime override for lookback (e.g. 2024-01-01T00:00:00)")
@click.option("--alert-window", default=60, show_default=True, help="Lookback minutes (if --since not set)")
def cmd_enrich(siem: str, since: str | None, alert_window: int):
    """Run one alert enrichment cycle."""
    settings = _get_settings()
    asyncio.run(_enrich(settings, siem, since, alert_window))


async def _enrich(settings, siem: str, since_str: str | None, alert_window: int):
    from tip.misp.client import MISPClient
    from tip.enrichment.misp_lookup import MISPLookup
    from tip.enrichment.tag_writer import TagWriter
    from tip.enrichment.alert_enricher import AlertEnricher
    from tip.siem.elastic_client import ElasticClient
    from tip.siem.sentinel_client import SentinelClient
    from tip.notification.slack_notifier import SlackNotifier

    since = (
        datetime.fromisoformat(since_str)
        if since_str
        else datetime.utcnow() - timedelta(minutes=alert_window)
    )

    misp = MISPClient(settings)
    elastic = ElasticClient(settings) if siem in ("elastic", "all") else None
    sentinel = SentinelClient(settings) if siem in ("sentinel", "all") else None
    slack = SlackNotifier(settings)
    lookup = MISPLookup(misp)
    tag_writer = TagWriter(sentinel, elastic)
    enricher = AlertEnricher(
        misp_lookup=lookup, tag_writer=tag_writer,
        sentinel_client=sentinel, elastic_client=elastic,
        slack_notifier=slack, notify_on=settings.slack_notify_on,
    )

    summary = await enricher.run_enrichment_cycle(alert_window)
    console.print(f"[green]Enrichment done:[/green] "
                  f"{summary['total']} alerts, {summary['matched']} matched, "
                  f"{summary['notified']} notified")


# ---------------------------------------------------------------------------
# tip lookup
# ---------------------------------------------------------------------------
@main.command("lookup")
@click.argument("value")
@click.option("--json-output", is_flag=True, help="Output raw JSON")
def cmd_lookup(value: str, json_output: bool):
    """Look up a single IOC value in MISP and print full context."""
    settings = _get_settings()
    asyncio.run(_lookup(settings, value, json_output))


async def _lookup(settings, value: str, json_output: bool):
    from tip.misp.client import MISPClient
    from tip.enrichment.misp_lookup import MISPLookup

    misp = MISPClient(settings)
    lookup = MISPLookup(misp)
    result = await lookup.lookup_ioc(value)

    if json_output:
        click.echo(json.dumps(result, default=str, indent=2))
        return

    if not result["matched"]:
        console.print(f"[yellow]⚪ No match found in MISP for:[/yellow] {value}")
        return

    ctx = result["context"]
    console.print(Panel.fit(f"[green]✅ MISP Match: {value}[/green]", border_style="green"))

    table = Table(box=box.SIMPLE)
    table.add_column("Field", style="bold")
    table.add_column("Value")
    table.add_row("Attributes matched", str(len(ctx.get("attributes", []))))
    table.add_row("Events", str(len(ctx.get("events", []))))
    table.add_row("Threat Actors", ", ".join(ctx.get("threat_actors", [])) or "Unknown")
    table.add_row("Campaigns", ", ".join(ctx.get("campaigns", [])) or "None")
    table.add_row("Source Feeds", ", ".join(ctx.get("feeds", [])) or "Unknown")
    table.add_row("Tags", "\n".join(ctx.get("tags", [])[:10]))
    console.print(table)


# ---------------------------------------------------------------------------
# tip scheduler
# ---------------------------------------------------------------------------
@main.command("scheduler")
def cmd_scheduler():
    """Start the continuous scheduler (blocks, runs feeds on cron schedule)."""
    settings = _get_settings()
    asyncio.run(_run_scheduler(settings))


async def _run_scheduler(settings):
    from tip.misp.client import MISPClient
    from tip.misp.dedup_cache import DedupCache
    from tip.feeds.feed_scheduler import FeedScheduler

    misp = MISPClient(settings)
    cache = DedupCache(settings)
    scheduler = FeedScheduler(settings, misp, cache)

    console.print(Panel.fit(
        "[bold green]🕐 Starting scheduler...[/bold green]\n"
        f"OTX every {settings.otx_schedule_minutes}m | "
        f"Abuse.ch every {settings.abusech_schedule_minutes}m\n"
        "[dim]Press Ctrl+C to stop[/dim]",
        border_style="green"
    ))

    scheduler.start()
    try:
        while True:
            await asyncio.sleep(60)
            results = scheduler.get_last_results()
            if results:
                console.log(f"[dim]Scheduler running — last results: {list(results.keys())}[/dim]")
    except (KeyboardInterrupt, asyncio.CancelledError):
        scheduler.stop()
        console.print("\n[yellow]Scheduler stopped.[/yellow]")


# ---------------------------------------------------------------------------
# tip status
# ---------------------------------------------------------------------------
@main.command("status")
@click.option("--retry", default=1, help="Retry MISP check N times (useful during startup)")
def cmd_status(retry: int):
    """Health check all configured services."""
    settings = _get_settings()
    asyncio.run(_status(settings, retry))


async def _status(settings, retry: int):
    from tip.misp.client import MISPClient
    from tip.feeds.otx_feed import OTXFeed
    from tip.feeds.abusech_feed import AbuseCHFeed
    from tip.siem.elastic_client import ElasticClient
    from tip.siem.sentinel_client import SentinelClient
    from tip.notification.slack_notifier import SlackNotifier

    table = Table(title="🔍 Service Health Check", box=box.ROUNDED)
    table.add_column("Service", style="bold")
    table.add_column("Status", justify="center")
    table.add_column("Note")

    checks = []

    # MISP (with retry for startup)
    misp = MISPClient(settings)
    misp_ok = False
    for attempt in range(retry):
        misp_ok = await misp.health_check()
        if misp_ok:
            break
        if attempt < retry - 1:
            console.print(f"[yellow]MISP not ready, retrying... ({attempt + 2}/{retry})[/yellow]")
            await asyncio.sleep(5)
    checks.append(("MISP", misp_ok, settings.misp_url if misp_ok else "Check TIP_MISP_URL and TIP_MISP_API_KEY"))

    # OTX
    if settings.otx_api_key:
        otx = OTXFeed(settings)
        otx_ok = await otx.health_check()
        checks.append(("AlienVault OTX", otx_ok, "API key configured" if otx_ok else "Check TIP_OTX_API_KEY"))
    else:
        checks.append(("AlienVault OTX", None, "TIP_OTX_API_KEY not set"))

    # Abuse.ch
    abusech = AbuseCHFeed(settings)
    abusech_ok = await abusech.health_check()
    checks.append(("Abuse.ch", abusech_ok, "No API key needed" if abusech_ok else "Network error"))

    # Elastic
    elastic = ElasticClient(settings)
    if elastic.is_configured():
        el_ok = await elastic.health_check()
        checks.append(("Elasticsearch", el_ok, settings.elastic_url if el_ok else "Check TIP_ELASTIC_URL"))
    else:
        checks.append(("Elasticsearch", None, "Not configured (optional)"))

    # Sentinel
    sentinel = SentinelClient(settings)
    if sentinel.is_configured():
        sen_ok = await sentinel.health_check()
        checks.append(("Microsoft Sentinel", sen_ok, "Connected" if sen_ok else "Check Sentinel credentials"))
    else:
        checks.append(("Microsoft Sentinel", None, "Not configured (optional)"))

    # Slack
    if settings.slack_webhook_url:
        slack = SlackNotifier(settings)
        slack_ok = await slack.health_check()
        checks.append(("Slack", slack_ok, "Webhook working" if slack_ok else "Check TIP_SLACK_WEBHOOK_URL"))
    else:
        checks.append(("Slack", None, "TIP_SLACK_WEBHOOK_URL not set"))

    all_required_ok = True
    for name, ok, note in checks:
        if ok is True:
            status_str = "[green]✅ OK[/green]"
        elif ok is False:
            status_str = "[red]❌ FAIL[/red]"
            all_required_ok = False
        else:
            status_str = "[yellow]⚪ N/A[/yellow]"
        table.add_row(name, status_str, note)

    console.print(table)

    if all_required_ok:
        console.print("\n[bold green]All required services operational! Run:[/bold green] tip feeds run")
    else:
        console.print("\n[bold yellow]Some services need attention. Check .env file.[/bold yellow]")


# ---------------------------------------------------------------------------
# tip cache
# ---------------------------------------------------------------------------
@main.group("cache")
def cache_group():
    """Dedup cache management."""


@cache_group.command("stats")
def cmd_cache_stats():
    """Show dedup cache statistics."""
    settings = _get_settings()
    asyncio.run(_cache_stats(settings))


async def _cache_stats(settings):
    from tip.misp.dedup_cache import DedupCache
    cache = DedupCache(settings)
    stats = await cache.stats()

    table = Table(title="Cache Statistics", box=box.ROUNDED)
    table.add_column("Metric")
    table.add_column("Value", justify="right")
    table.add_row("Backend", stats["backend"])
    table.add_row("Total entries", str(stats["total_entries"]))
    table.add_row("TTL (days)", str(stats["ttl_days"]))
    if stats.get("by_type"):
        for t, count in stats["by_type"].items():
            table.add_row(f"  {t}", str(count))
    console.print(table)


@cache_group.command("purge")
@click.confirmation_option(prompt="This will delete expired cache entries. Continue?")
def cmd_cache_purge():
    """Delete expired cache entries."""
    settings = _get_settings()
    asyncio.run(_cache_purge(settings))


async def _cache_purge(settings):
    from tip.misp.dedup_cache import DedupCache
    cache = DedupCache(settings)
    count = await cache.purge_expired()
    console.print(f"[green]Purged {count} expired cache entries.[/green]")
