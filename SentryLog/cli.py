"""CLI interface using Click + Rich."""

from __future__ import annotations

import logging
from datetime import datetime
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

from sentrylog.config import Config
from sentrylog.parsers.auto import AutoParser, get_parser
from sentrylog.engine.rules import load_rules_from_dir, validate_rule
from sentrylog.engine.detector import DetectionEngine
from sentrylog.output.console import print_alerts
from sentrylog.output.jsonlines import write_alerts
from sentrylog.storage.db import Database
from sentrylog.storage.models import Severity

log = logging.getLogger(__name__)

console = Console()

SEVERITY_COLORS = {
    Severity.INFO: "dim",
    Severity.LOW: "blue",
    Severity.MEDIUM: "yellow",
    Severity.HIGH: "red",
    Severity.CRITICAL: "bold red",
}


def get_db(config: Config) -> Database:
    db = Database(config.db_path)
    db.connect()
    return db


@click.group()
@click.option("--config", "-c", "config_path", type=click.Path(exists=False), default=None)
@click.option("--db", "db_path", type=click.Path(), default=None)
@click.option("--verbose", "-v", count=True, help="Increase verbosity (-v info, -vv debug)")
@click.pass_context
def cli(ctx, config_path, db_path, verbose):
    """SentryLog — SIEM Lite log analyzer."""
    # Configure logging based on verbosity
    level = logging.WARNING
    if verbose == 1:
        level = logging.INFO
    elif verbose >= 2:
        level = logging.DEBUG
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    ctx.ensure_object(dict)
    config = Config.load(Path(config_path)) if config_path else Config()
    if db_path:
        config.db_path = Path(db_path)
    ctx.obj["config"] = config


@cli.command()
@click.argument("path", type=click.Path(exists=True))
@click.option("--parser", "-p", "parser_name", default="auto", help="Parser to use")
@click.pass_context
def ingest(ctx, path: str, parser_name: str):
    """Ingest log files into the database."""
    config = ctx.obj["config"]
    target = Path(path)
    parser = get_parser(parser_name)

    files = []
    if target.is_dir():
        files = sorted(target.iterdir())
        files = [f for f in files if f.is_file() and not f.name.startswith(".")]
    else:
        files = [target]

    db = get_db(config)
    total = 0
    try:
        for filepath in files:
            with console.status(f"[bold blue]Parsing {filepath.name}..."):
                if parser_name == "auto":
                    auto = AutoParser()
                    events = auto.parse_file(filepath)
                else:
                    events = parser.parse_file(filepath)

                if not events:
                    console.print(f"  [dim]Skipped {filepath.name} (no parseable lines)[/dim]")
                    continue

                count = db.insert_events(events)
                total += count
                console.print(
                    f"  [green]✓[/green] {filepath.name}: {count} events "
                    f"[dim]({events[0].source} parser)[/dim]"
                )
    finally:
        db.close()

    console.print(
        Panel(
            f"[bold green]{total}[/bold green] events ingested into [cyan]{config.db_path}[/cyan]",
            title="Ingest Complete",
            box=box.ROUNDED,
        )
    )


@cli.group("query")
def query_group():
    """Query stored events and alerts."""


@query_group.command("events")
@click.option("--ip", "source_ip", help="Filter by source IP")
@click.option("--severity", "-s", type=click.Choice([s.value for s in Severity]))
@click.option("--action", "-a", help="Filter by action (substring match)")
@click.option("--since", help="Since timestamp (ISO format)")
@click.option("--limit", "-n", default=50, help="Max results")
@click.pass_context
def query_events(ctx, source_ip, severity, action, since, limit):
    """Query stored events."""
    config = ctx.obj["config"]
    db = get_db(config)

    try:
        since_dt = datetime.fromisoformat(since) if since else None
        events = db.query_events(
            source_ip=source_ip,
            severity=severity,
            action=action,
            since=since_dt,
            limit=limit,
        )
    finally:
        db.close()

    if not events:
        console.print("[dim]No events found.[/dim]")
        return

    table = Table(title=f"Events ({len(events)} results)", box=box.SIMPLE_HEAVY)
    table.add_column("ID", style="dim", width=6)
    table.add_column("Timestamp", width=19)
    table.add_column("Source", width=8)
    table.add_column("Source IP", width=15)
    table.add_column("User", width=12)
    table.add_column("Action", width=18)
    table.add_column("Severity", width=8)

    for e in events:
        color = SEVERITY_COLORS.get(e.severity, "")
        table.add_row(
            str(e.id),
            e.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            e.source,
            e.source_ip or "-",
            e.user or "-",
            e.action,
            f"[{color}]{e.severity.value}[/{color}]",
        )

    console.print(table)


@query_group.command("alerts")
@click.option("--severity", "-s", type=click.Choice([s.value for s in Severity]))
@click.option("--unacked", is_flag=True, help="Show only unacknowledged alerts")
@click.option("--limit", "-n", default=50, help="Max results")
@click.pass_context
def query_alerts(ctx, severity, unacked, limit):
    """Query stored alerts."""
    config = ctx.obj["config"]
    db = get_db(config)

    try:
        alerts = db.query_alerts(
            severity=severity,
            acknowledged=False if unacked else None,
            limit=limit,
        )
    finally:
        db.close()

    if not alerts:
        console.print("[dim]No alerts found.[/dim]")
        return

    table = Table(title=f"Alerts ({len(alerts)} results)", box=box.SIMPLE_HEAVY)
    table.add_column("ID", style="dim", width=6)
    table.add_column("Timestamp", width=19)
    table.add_column("Rule", width=22)
    table.add_column("Severity", width=8)
    table.add_column("Source IP", width=15)
    table.add_column("User", width=12)
    table.add_column("MITRE", width=12)
    table.add_column("Ack", width=3)

    for a in alerts:
        color = SEVERITY_COLORS.get(a.severity, "")
        mitre = ", ".join(a.mitre_tags) if a.mitre_tags else "-"
        table.add_row(
            str(a.id),
            a.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            a.rule_name,
            f"[{color}]{a.severity.value}[/{color}]",
            a.source_ip or "-",
            a.user or "-",
            mitre,
            "✓" if a.acknowledged else "",
        )

    console.print(table)


def _safe(text: str) -> str:
    """Replace characters outside latin-1 range so Helvetica font doesn't crash."""
    return (
        text.replace("—", "--")   # em dash
            .replace("–", "-")    # en dash
            .replace("‘", "'")    # left single quote
            .replace("’", "'")    # right single quote
            .replace("“", '"')    # left double quote
            .replace("”", '"')    # right double quote
            .encode("latin-1", errors="replace")
            .decode("latin-1")
    )


def _write_pdf_report(alerts, config) -> Path:
    from fpdf import FPDF
    reports_dir = Path("reports")
    reports_dir.mkdir(exist_ok=True)
    ts = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    path = reports_dir / f"sentrylog_scan_report_{ts}.pdf"

    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 10, "SentryLog Scan Report", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", size=11)
    pdf.cell(0, 8, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 8, f"Database: {config.db_path}", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 8, f"Total alerts: {len(alerts)}", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(5)

    for alert in alerts:
        pdf.set_font("Helvetica", "B", 11)
        pdf.cell(0, 8, _safe(f"[{alert.severity.value.upper()}] {alert.rule_name}"), new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", size=10)
        pdf.multi_cell(0, 6, _safe(alert.description))
        parts = []
        if alert.source_ip:
            parts.append(f"IP: {alert.source_ip}")
        if alert.user:
            parts.append(f"User: {alert.user}")
        if alert.mitre_tags:
            parts.append(f"MITRE: {', '.join(alert.mitre_tags)}")
        if parts:
            pdf.cell(0, 6, _safe("  " + " | ".join(parts)), new_x="LMARGIN", new_y="NEXT")
        pdf.ln(2)

    pdf.output(str(path))
    return path


@cli.command()
@click.option("--rules-dir", "-r", type=click.Path(exists=True), default=None)
@click.option("--alert-file", type=click.Path(), default=None)
@click.option("--report", "generate_report", is_flag=True, help="Save PDF report to reports/")
@click.pass_context
def scan(ctx, rules_dir, alert_file, generate_report):
    """Run detection rules against stored events."""
    config = ctx.obj["config"]
    rdir = Path(rules_dir) if rules_dir else config.rules_dir
    db = get_db(config)

    try:
        rules = load_rules_from_dir(rdir)
        if not rules:
            console.print("[yellow]No rules found.[/yellow]")
            return

        console.print(f"[bold]Loaded {len(rules)} rule(s) from {rdir}[/bold]\n")

        events = db.get_all_events()
        if not events:
            console.print("[dim]No events in database to scan.[/dim]")
            return

        console.print(f"Scanning {len(events)} events...\n")
        engine = DetectionEngine(rules)
        alerts = engine.check_batch(events)

        if alerts:
            print_alerts(alerts)
            for alert in alerts:
                db.insert_alert(alert)
            if alert_file:
                write_alerts(alerts, Path(alert_file))
                console.print(f"[dim]Alerts written to {alert_file}[/dim]")
            if generate_report:
                report_path = _write_pdf_report(alerts, config)
                console.print(f"[green]Report saved:[/green] {report_path}")
        else:
            console.print("[green]No alerts generated — all clear.[/green]")
    finally:
        db.close()


@cli.group("rules")
def rules_group():
    """Manage detection rules."""


@rules_group.command("list")
@click.option("--rules-dir", "-r", type=click.Path(exists=True), default=None)
@click.pass_context
def rules_list(ctx, rules_dir):
    """List all loaded detection rules."""
    config = ctx.obj["config"]
    rdir = Path(rules_dir) if rules_dir else config.rules_dir
    try:
        rules = load_rules_from_dir(rdir)
    except ValueError as e:
        console.print(f"[red]Error: {e}[/red]")
        return

    if not rules:
        console.print(f"[dim]No rules found in {rdir}[/dim]")
        return

    table = Table(title=f"Detection Rules ({len(rules)})", box=box.SIMPLE_HEAVY)
    table.add_column("Name", width=24)
    table.add_column("Type", width=10)
    table.add_column("Severity", width=8)
    table.add_column("MITRE", width=16)
    table.add_column("Description", min_width=30)

    for r in rules:
        color = SEVERITY_COLORS.get(r.severity, "")
        mitre = ", ".join(r.mitre_tags) if r.mitre_tags else "-"
        table.add_row(
            r.name,
            r.type,
            f"[{color}]{r.severity.value}[/{color}]",
            mitre,
            r.description,
        )

    console.print(table)


@rules_group.command("validate")
@click.argument("path", type=click.Path(exists=True))
def rules_validate(path):
    """Validate a YAML rule file."""
    import yaml as _yaml

    target = Path(path)
    files = sorted(target.glob("*.yml")) if target.is_dir() else [target]
    all_ok = True

    for f in files:
        with open(f) as fh:
            data = _yaml.safe_load(fh)
        if data is None:
            console.print(f"[yellow]Warning: {f.name}: empty file[/yellow]")
            continue

        items = data if isinstance(data, list) else [data]
        for item in items:
            errors = validate_rule(item)
            if errors:
                all_ok = False
                console.print(f"[red]x {f.name} ({item.get('name', '?')}):[/red]")
                for err in errors:
                    console.print(f"    {err}")
            else:
                console.print(f"[green]ok {f.name} ({item['name']})[/green]")

    if all_ok:
        console.print("\n[bold green]All rules valid.[/bold green]")


@cli.command()
@click.option("--rules-dir", "-r", type=click.Path(exists=True), default=None)
@click.option("--keep-db", is_flag=True, help="Keep the database after demo")
@click.pass_context
def demo(ctx, rules_dir, keep_db):
    """Generate demo data, ingest, and run detection — zero-friction showcase."""
    import tempfile

    from sentrylog.storage.models import Severity as _Sev

    config = ctx.obj["config"]

    # Find rules directory — check common locations
    if rules_dir:
        rdir = Path(rules_dir)
    elif config.rules_dir.exists():
        rdir = config.rules_dir
    else:
        # Try to find rules relative to package
        candidates = [
            Path(__file__).parent.parent.parent / "rules",
            Path("rules"),
            Path(__file__).parent.parent.parent.parent / "rules",
        ]
        rdir = next((c for c in candidates if c.exists()), None)
        if rdir is None:
            console.print("[red]Cannot find rules directory. Use --rules-dir.[/red]")
            return

    console.print(Panel(
        "[bold cyan]SentryLog[/bold cyan] — SIEM Lite Demo\n"
        "Generating realistic logs with embedded attack patterns...",
        box=box.DOUBLE,
        border_style="cyan",
    ))
    console.print()

    # Step 1: Generate demo logs
    with console.status("[bold blue]Generating demo logs..."):
        from sentrylog.demo import DemoLogGenerator
        gen = DemoLogGenerator()
        tmpdir = Path(tempfile.mkdtemp(prefix="sentrylog_demo_"))
        auth_path, access_path = gen.write(tmpdir)

    auth_lines = len(auth_path.read_text().strip().split("\n"))
    access_lines = len(access_path.read_text().strip().split("\n"))
    console.print(f"[green]1.[/green] Generated demo logs:")
    console.print(f"   auth.log:   {auth_lines} lines")
    console.print(f"   access.log: {access_lines} lines\n")

    # Step 2: Ingest
    if not keep_db:
        # Use temp database
        db_path = tmpdir / "demo.db"
        config.db_path = db_path

    db = get_db(config)
    try:
        with console.status("[bold blue]Ingesting logs..."):
            from sentrylog.parsers.auto import AutoParser as _Auto
            for log_file in [auth_path, access_path]:
                auto = _Auto()
                events = auto.parse_file(log_file)
                if events:
                    db.insert_events(events)

        event_count = db.get_event_count()
        console.print(f"[green]2.[/green] Ingested [bold]{event_count}[/bold] events into database\n")

        # Step 3: Load rules and scan
        with console.status("[bold blue]Loading detection rules..."):
            rules = load_rules_from_dir(rdir)

        console.print(f"[green]3.[/green] Loaded [bold]{len(rules)}[/bold] detection rules\n")

        with console.status("[bold blue]Running detection engine..."):
            events = db.get_all_events()
            engine = DetectionEngine(rules)
            alerts = engine.check_batch(events)

        console.print(f"[green]4.[/green] Detection complete — [bold]{len(alerts)}[/bold] alerts generated\n")

        # Store alerts
        for alert in alerts:
            db.insert_alert(alert)

        # Step 4: Display results
        console.rule("[bold]Detection Results[/bold]")
        console.print()

        # Summary by severity
        severity_counts: dict[_Sev, int] = {}
        for a in alerts:
            severity_counts[a.severity] = severity_counts.get(a.severity, 0) + 1

        summary_table = Table(title="Alert Summary", box=box.ROUNDED)
        summary_table.add_column("Severity", width=10)
        summary_table.add_column("Count", justify="right", width=8)
        for sev in [_Sev.CRITICAL, _Sev.HIGH, _Sev.MEDIUM, _Sev.LOW, _Sev.INFO]:
            count = severity_counts.get(sev, 0)
            if count > 0:
                color = SEVERITY_COLORS.get(sev, "")
                summary_table.add_row(f"[{color}]{sev.value.upper()}[/{color}]", str(count))
        console.print(summary_table)
        console.print()

        # Top attacking IPs
        ip_counts: dict[str, int] = {}
        for a in alerts:
            if a.source_ip:
                ip_counts[a.source_ip] = ip_counts.get(a.source_ip, 0) + 1
        if ip_counts:
            ip_table = Table(title="Top Attacking IPs", box=box.ROUNDED)
            ip_table.add_column("IP Address", width=18)
            ip_table.add_column("Alerts", justify="right", width=8)
            for ip, count in sorted(ip_counts.items(), key=lambda x: -x[1])[:5]:
                ip_table.add_row(f"[red]{ip}[/red]", str(count))
            console.print(ip_table)
            console.print()

        # MITRE ATT&CK coverage
        mitre_tags = set()
        for a in alerts:
            mitre_tags.update(a.mitre_tags)
        if mitre_tags:
            console.print(Panel(
                "  ".join(f"[cyan]{t}[/cyan]" for t in sorted(mitre_tags)),
                title="MITRE ATT&CK Coverage",
                box=box.ROUNDED,
                border_style="cyan",
            ))
            console.print()

        # Detailed alerts
        console.rule("[bold]Alert Details[/bold]")
        console.print()
        print_alerts(alerts)

        # Final banner
        console.print(Panel(
            f"[bold green]Demo complete![/bold green]\n\n"
            f"  Events: {event_count}  |  Alerts: {len(alerts)}  |  "
            f"Rules: {len(rules)}  |  MITRE tags: {len(mitre_tags)}\n\n"
            f"  Database: [cyan]{config.db_path}[/cyan]\n"
            f"  Try: [dim]sentrylog --db {config.db_path} query alerts -s high[/dim]",
            box=box.DOUBLE,
            border_style="green",
        ))

    finally:
        db.close()
