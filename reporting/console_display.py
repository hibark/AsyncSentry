from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
import pyfiglet

from core.models import Vulnerability, Severity
from core.risk_engine import RiskEngine

console = Console()

SEVERITY_COLORS = {
    "Critique": "bold red",
    "Élevé": "bold orange3",
    "Moyen": "bold yellow",
    "Faible": "bold green",
    "Info": "bold blue",
}


def print_banner():
    banner = pyfiglet.figlet_format("AsyncSentry", font="slant")
    console.print(f"[bold magenta]{banner}[/bold magenta]")
    console.print("[dim]Web Vulnerability Scanner v1.0 — VAPT / Purple Team[/dim]\n")


def print_scan_config(target: str, mode: str, depth: int, concurrency: int):
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_row("[bold]Cible[/bold]", target)
    table.add_row("[bold]Mode[/bold]", mode)
    table.add_row("[bold]Profondeur[/bold]", str(depth))
    table.add_row("[bold]Concurrence[/bold]", str(concurrency))
    console.print(Panel(table, title="[bold cyan]Configuration du scan[/bold cyan]", border_style="cyan"))


def print_crawl_summary(endpoint_count: int, form_count: int, param_count: int):
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_row("Endpoints découverts", str(endpoint_count))
    table.add_row("Formulaires trouvés", str(form_count))
    table.add_row("Paramètres trouvés", str(param_count))
    console.print(Panel(table, title="[bold cyan]Résumé du Crawling[/bold cyan]", border_style="cyan"))


def print_risk_summary(vulnerabilities: list[Vulnerability]):
    risk_data = RiskEngine.calculate_score(vulnerabilities)

    summary_table = Table(show_header=False, box=None, padding=(0, 2))
    risk_color = {
        "CRITIQUE": "bold red",
        "ÉLEVÉ": "bold orange3",
        "MOYEN": "bold yellow",
        "FAIBLE": "bold green",
        "AUCUN": "bold green",
    }.get(risk_data["risk_level"], "white")

    summary_table.add_row("Niveau de risque", f"[{risk_color}]{risk_data['risk_level']}[/{risk_color}]")
    summary_table.add_row("Score total", str(risk_data["total_score"]))
    summary_table.add_row("Total vulnérabilités", str(risk_data["total_vulnerabilities"]))

    console.print(Panel(summary_table, title="[bold cyan]Score de Risque[/bold cyan]", border_style="cyan"))

    # Tableau répartition par criticité
    if risk_data["breakdown"]:
        sev_table = Table(title="Répartition par criticité", show_lines=False)
        sev_table.add_column("Criticité")
        sev_table.add_column("Nombre", justify="right")
        for level, count in risk_data["breakdown"].items():
            color = SEVERITY_COLORS.get(level, "white")
            sev_table.add_row(f"[{color}]{level}[/{color}]", str(count))
        console.print(sev_table)


def print_vulnerabilities_table(vulnerabilities: list[Vulnerability]):
    if not vulnerabilities:
        console.print(Panel("[bold green]✔ Aucune vulnérabilité détectée[/bold green]", border_style="green"))
        return

    sorted_vulns = RiskEngine.sort_by_severity(vulnerabilities)

    table = Table(title="Vulnérabilités détectées", show_lines=True)
    table.add_column("Sévérité", justify="center")
    table.add_column("Nom", overflow="fold")
    table.add_column("Endpoint", overflow="fold", style="dim")

    for vuln in sorted_vulns:
        color = SEVERITY_COLORS.get(vuln.severity.value, "white")
        table.add_row(
            f"[{color}]{vuln.severity.value}[/{color}]",
            vuln.name,
            vuln.endpoint
        )

    console.print(table)


def print_scan_complete(json_path: str, html_path: str):
    console.print(Panel(
        f"[bold green]Scan terminé ![/bold green]\n\n"
        f"[bold]Rapport JSON :[/bold] {json_path}\n"
        f"[bold]Rapport HTML :[/bold] {html_path}",
        border_style="green",
        title="✔ Terminé"
    ))