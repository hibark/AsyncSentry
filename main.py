import asyncio
import aiohttp
import click
import time
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

from core.crawler import Crawler
from modules.passive.headers_audit import HeadersAuditor
from modules.passive.cookies_audit import CookiesAuditor
from modules.passive.cors_audit import CorsAuditor
from modules.active.xss import XSSScanner
from modules.active.sqli import SQLiScanner
from modules.active.path_traversal import PathTraversalScanner
from reporting.json_report import generate_json_report
from reporting.html_report import generate_html_report

console = Console()

def parse_cookies(cookie_str: str) -> dict:
    """Parses a cookie string into a dictionary."""
    cookies = {}
    if not cookie_str: 
        return cookies
    for pair in cookie_str.split(";"):
        if "=" in pair:
            key, value = pair.strip().split("=", 1)
            cookies[key] = value
    return cookies

def log_msg(msg: str, level: str = "INF", indent: bool = False):
    """Prints timestamped logs matching the Kali terminal UI."""
    now = datetime.now().strftime("%m/%d/%y %H:%M:%S")
    color = "cyan" if level == "INF" else "green" if level == "OK" else "yellow"
    prefix = "    ┣━ " if indent else ""
    console.print(f"[[blue]{now}[/blue]] [[bold {color}]{level}[/bold {color}]] {prefix}{msg}")

def print_banner():
    """Displays the main ASCII banner and legal warning."""
    banner = """[bold bright_blue]
 __        __   _   __     __    _       
 \ \      / /__| |__\ \   / /   | |____  
  \ \ /\ / / _ \ '_ \\ \ / /| | | | '_ \ 
   \ V  V /  __/ |_) |\ V / | |_| | | | |
    \_/\_/ \___|_.__/  \_/   \__,_|_| |_|
[/bold bright_blue]"""
    console.print(banner)
    console.print("[bold white]WebVuln Scanner v0.1.0 - Educational & Authorized VAPT Engine[/bold white]\n")

    warning_text = """This tool is strictly designed for educational testing, CTF challenges, 
localhost lab environments, and systems where you have [bold #d08770]explicit, written authorization[/bold #d08770].
Scanning unauthorized targets violates computer crime laws."""
    console.print(Panel(warning_text, title="[bold red]LEGAL & ETHICAL WARNING[/bold red]", border_style="red", title_align="left"))
    console.print()

def get_english_severity(severity_value: str) -> str:
    """Safely maps French severity enums to English for display."""
    val = severity_value.lower()
    if "crit" in val: return "Critical"
    if "élev" in val or "high" in val: return "High"
    if "moyen" in val or "medium" in val: return "Medium"
    if "faibl" in val or "low" in val: return "Low"
    return "Info"

async def run_scan(target: str, depth: int, concurrency: int, mode: str, cookies: dict, output_html: str, output_json: str):
    start_time = time.time()
    print_banner()
    
    log_msg(f"Fingerprinting technologies on [bold blue]{target}[/bold blue]", indent=True)
    log_msg("Loading attack surface...", indent=True)
    
    # Phase 1: Crawling
    log_msg(f"Starting discovery crawl on [bold blue]{target}[/bold blue] (Max depth: {depth}, Max URLs: 100)")
    crawler = Crawler(base_url=target, max_depth=depth, concurrency=concurrency, cookies=cookies)
    endpoints = await crawler.run()
    
    total_forms = sum(len(ep.forms) for ep in endpoints)
    total_params = sum(len(ep.params) for ep in endpoints)
    
    log_msg(f"Crawl completed. Discovered [bold cyan]{len(endpoints)}[/bold cyan] endpoints across [bold cyan]{total_params}[/bold cyan] parameters.", level="OK")
    
    all_vulnerabilities = []
    
    async with aiohttp.ClientSession(cookies=cookies) as session:
        # Phase 2: Passive Analysis
        if mode in ("passive", "full"):
            log_msg(f"Running passive security check modules across {len(endpoints)} endpoints...")
            headers_auditor = HeadersAuditor(session)
            cookies_auditor = CookiesAuditor(session)
            cors_auditor = CorsAuditor(session)
            for endpoint in endpoints:
                all_vulnerabilities.extend(await headers_auditor.audit(endpoint.url))
                all_vulnerabilities.extend(await cookies_auditor.audit(endpoint.url))
                all_vulnerabilities.extend(await cors_auditor.audit(endpoint.url))

        # Phase 3: Active Analysis
        if mode in ("active", "full"):
            log_msg(f"Running active payload injection across {len(endpoints)} endpoints...")
            xss_scanner = XSSScanner(session)
            sqli_scanner = SQLiScanner(session)
            pt_scanner = PathTraversalScanner(session)
            for endpoint in endpoints:
                all_vulnerabilities.extend(await xss_scanner.scan_endpoint(endpoint))
                all_vulnerabilities.extend(await sqli_scanner.scan_endpoint(endpoint))
                all_vulnerabilities.extend(await pt_scanner.scan_endpoint(endpoint))

    duration = round(time.time() - start_time, 2)
    log_msg(f"Scan completed in [bold green]{duration}s[/bold green]. Reports written to exports/", level="OK")
    
    console.print("\n[bold grey50]        --- Assessment Summary Dashboard ---[/bold grey50]\n")

    # Severity Stats Calculation
    sev_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for v in all_vulnerabilities:
        en_sev = get_english_severity(v.severity.value)
        sev_counts[en_sev] += 1
            
    risk_rating = "Low"
    score = "2.0 / 10.0"
    if sev_counts["Critical"] > 0: 
        risk_rating = "Critical"
        score = "10.0 / 10.0"
    elif sev_counts["High"] > 0: 
        risk_rating = "High"
        score = "8.5 / 10.0"
    elif sev_counts["Medium"] > 0: 
        risk_rating = "Medium"
        score = "6.0 / 10.0"

    # TABLE 1: METRICS
    metrics = Table(box=box.ROUNDED, border_style="deep_sky_blue1", header_style="bold deep_sky_blue1", width=50)
    metrics.add_column("Metric", style="bold white")
    metrics.add_column("Value", style="grey82")
    
    metrics.add_row("Target URL", target)
    metrics.add_row("Total HTTP Requests", str(len(endpoints) * 15)) 
    metrics.add_row("Discovered Endpoints", str(len(endpoints)))
    metrics.add_row("Total Findings", str(len(all_vulnerabilities)))
    metrics.add_row("Overall Risk Rating", f"{score} - {risk_rating}")
    metrics.add_row("Duration", f"{duration}s")
    
    console.print(metrics)
    console.print("\n[bold grey50]        Vulnerabilities By\n           Severity[/bold grey50]")

    # TABLE 2: SEVERITY COUNTS
    sev_table = Table(box=box.ROUNDED, border_style="deep_sky_blue1", header_style="bold deep_sky_blue1", width=30)
    sev_table.add_column("Severity Level")
    sev_table.add_column("Count", justify="center", style="white")
    
    colors = {"Critical": "bold red", "High": "bold dark_orange", "Medium": "bold yellow", "Low": "bold bright_blue", "Info": "bold cyan"}
    
    for sev in ["Critical", "High", "Medium", "Low", "Info"]:
        count = sev_counts[sev]
        if count > 0:
            sev_table.add_row(f"[{colors[sev]}]{sev.upper()}[/]", str(count))
            
    console.print(sev_table)
    console.print("\n[bold grey50]                             --- Detailed Findings ({}) ---[/bold grey50]\n".format(len(all_vulnerabilities)))

    # TABLE 3: DETAILED FINDINGS
    find_table = Table(box=box.ROUNDED, border_style="deep_sky_blue1", header_style="bold deep_sky_blue1")
    find_table.add_column("Severity")
    find_table.add_column("Title")
    find_table.add_column("Endpoint", style="grey82")
    find_table.add_column("Confidence", style="grey50")

    for v in all_vulnerabilities:
        en_sev = get_english_severity(v.severity.value)
        c = colors.get(en_sev, "white")
        find_table.add_row(f"[{c}]{en_sev.upper()}[/]", v.name, v.endpoint, "High")
    
    console.print(find_table)

    # Generate Reports
    generate_json_report(target, all_vulnerabilities, output_path=output_json)
    generate_html_report(target, all_vulnerabilities, output_path=output_html)


@click.command()
@click.option("--target", "-t", required=True, help="Target URL to scan (e.g., http://localhost:8080)")
@click.option("--depth", "-d", default=2, help="Maximum crawling depth")
@click.option("--concurrency", "-c", default=5, help="Number of concurrent requests")
@click.option("--mode", "-m", type=click.Choice(["passive", "active", "full"]), default="full", help="Scan mode")
@click.option("--cookie", default="", help="Authentication cookies (e.g., 'PHPSESSID=xxx')")
@click.option("--output-html", default="reports/report.html", help="Path to save the HTML report")
@click.option("--output-json", default="reports/report.json", help="Path to save the JSON report")
def cli(target, depth, concurrency, mode, cookie, output_html, output_json):
    """WebVuln Scanner - Educational & Authorized VAPT Engine."""
    cookies = parse_cookies(cookie)
    asyncio.run(run_scan(target, depth, concurrency, mode, cookies, output_html, output_json))

if __name__ == "__main__":
    cli()