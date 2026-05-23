"""
TIP Master Pipeline
Orchestrates the full ingestion → scoring → storage → SIEM sync cycle.
Runs once immediately, then on a scheduled interval.

Usage:
  python main.py              # run once and exit
  python main.py --schedule   # run on schedule (every 1 hour)
  python main.py --setup      # initialize DB indexes only
"""

import click
import schedule
import time
from rich.console import Console
from rich.panel import Panel

from src.database import setup_indexes, upsert_indicators, get_stats
from src.fetchers import fetch_all
from src.risk_scorer import score_batch
from src.siem_sync import sync_to_elasticsearch

console = Console()


def run_pipeline():
    """Full ingestion pipeline: fetch → score → store → sync."""
    console.print(Panel("[bold cyan]TIP Pipeline Starting[/bold cyan]", expand=False))

    # Step 1: Fetch from all OSINT feeds
    raw_indicators = fetch_all()
    if not raw_indicators:
        console.print("[yellow]No indicators fetched — check API keys and network.[/yellow]")
        return

    # Step 2: Score each indicator
    scored = score_batch(raw_indicators)
    console.print(f"[blue]Scored {len(scored)} indicators[/blue]")

    # Step 3: Upsert into MongoDB
    result = upsert_indicators(scored)
    console.print(
        f"[green]MongoDB:[/green] {result['upserted']} new, {result['modified']} updated"
    )

    # Step 4: Sync to Elasticsearch / SIEM
    try:
        sync_to_elasticsearch(hours_back=2)
    except Exception as e:
        console.print(f"[yellow]SIEM sync skipped (ES not running?): {e}[/yellow]")

    # Step 5: Print stats
    stats = get_stats()
    console.print(Panel(
        f"[bold]Pipeline Complete[/bold]\n"
        f"Total indicators : {stats['total']}\n"
        f"High-risk (≥80)  : {stats['high_risk']}\n"
        f"Blocked          : {stats['blocked']}\n"
        f"IPs / Domains    : {stats['ips']} / {stats['domains']}",
        expand=False
    ))


@click.command()
@click.option("--schedule", "use_schedule", is_flag=True, help="Run on hourly schedule")
@click.option("--setup",    is_flag=True,   help="Initialize DB indexes and exit")
def main(use_schedule, setup):
    if setup:
        setup_indexes()
        console.print("[green]Database initialized.[/green]")
        return

    # Always run once immediately
    setup_indexes()
    run_pipeline()

    if use_schedule:
        schedule.every(1).hour.do(run_pipeline)
        console.print("[bold]Scheduler active — running every 1 hour. Ctrl+C to stop.[/bold]")
        while True:
            schedule.run_pending()
            time.sleep(60)


if __name__ == "__main__":
    main()
