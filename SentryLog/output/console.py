"""Rich console alert output."""

from __future__ import annotations

import logging

from rich.console import Console
from rich.panel import Panel
from rich import box

from sentrylog.storage.models import Alert, Severity

log = logging.getLogger(__name__)

console = Console()

SEVERITY_STYLES = {
    Severity.INFO: ("dim", "INFO"),
    Severity.LOW: ("blue", "LOW"),
    Severity.MEDIUM: ("yellow", "MEDIUM"),
    Severity.HIGH: ("red bold", "HIGH"),
    Severity.CRITICAL: ("red bold reverse", "CRITICAL"),
}


def format_alert(alert: Alert) -> Panel:
    style, label = SEVERITY_STYLES.get(alert.severity, ("", "?"))
    mitre = " ".join(f"[dim]{t}[/dim]" for t in alert.mitre_tags) if alert.mitre_tags else ""

    lines = [
        f"[{style}]{label}[/{style}] [{style}]{alert.rule_name}[/{style}]",
        f"  {alert.description}",
    ]
    if alert.source_ip:
        lines.append(f"  Source IP: [cyan]{alert.source_ip}[/cyan]")
    if alert.user:
        lines.append(f"  User: [cyan]{alert.user}[/cyan]")
    if alert.event_ids:
        lines.append(f"  Events: {alert.event_ids}")
    if mitre:
        lines.append(f"  MITRE: {mitre}")

    border_style = style.split()[0] if style else "white"
    return Panel(
        "\n".join(lines),
        title=f"[{style}]Alert[/{style}]",
        title_align="left",
        border_style=border_style,
        box=box.HEAVY,
        padding=(0, 1),
    )


def print_alert(alert: Alert) -> None:
    console.print(format_alert(alert))


def print_alerts(alerts: list[Alert]) -> None:
    for alert in alerts:
        print_alert(alert)
    if alerts:
        console.print(f"\n[bold]{len(alerts)}[/bold] alert(s) generated.\n")
