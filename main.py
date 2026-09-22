import asyncio
import aiohttp
import click

from core.crawler import Crawler
from modules.passive.headers_audit import HeadersAuditor
from modules.passive.cookies_audit import CookiesAuditor
from modules.passive.cors_audit import CorsAuditor
from modules.active.xss import XSSScanner
from modules.active.sqli import SQLiScanner
from modules.active.path_traversal import PathTraversalScanner
from reporting.json_report import generate_json_report
from reporting.html_report import generate_html_report


def parse_cookies(cookie_str: str) -> dict:
    """Parse une chaîne du type 'PHPSESSID=abc123;security=low' en dict."""
    cookies = {}
    if not cookie_str:
        return cookies
    for pair in cookie_str.split(";"):
        if "=" in pair:
            key, value = pair.strip().split("=", 1)
            cookies[key] = value
    return cookies


async def run_scan(target: str, depth: int, concurrency: int, mode: str, cookies: dict, output_html: str, output_json: str):
    print(f"=== Phase 1 : Crawling de {target} ===\n")
    crawler = Crawler(base_url=target, max_depth=depth, concurrency=concurrency, cookies=cookies)
    endpoints = await crawler.run()

    print(f"\n=== Résumé du crawl ===")
    print(f"Total endpoints découverts : {len(endpoints)}")
    total_forms = sum(len(ep.forms) for ep in endpoints)
    total_params = sum(len(ep.params) for ep in endpoints)
    print(f"Total formulaires trouvés  : {total_forms}")
    print(f"Total paramètres trouvés   : {total_params}")

    all_vulnerabilities = []

    async with aiohttp.ClientSession(cookies=cookies) as session:

        if mode in ("passive", "full"):
            print(f"\n=== Phase 2 : Analyse passive ===")
            headers_auditor = HeadersAuditor(session)
            cookies_auditor = CookiesAuditor(session)
            cors_auditor = CorsAuditor(session)

            for endpoint in endpoints:
                print(f"[*] Audit passif : {endpoint.url}")
                all_vulnerabilities.extend(await headers_auditor.audit(endpoint.url))
                all_vulnerabilities.extend(await cookies_auditor.audit(endpoint.url))
                all_vulnerabilities.extend(await cors_auditor.audit(endpoint.url))

        if mode in ("active", "full"):
            print(f"\n=== Phase 3 : Analyse active ===")
            xss_scanner = XSSScanner(session)
            sqli_scanner = SQLiScanner(session)
            pt_scanner = PathTraversalScanner(session)

            for endpoint in endpoints:
                print(f"[*] Audit actif sur : {endpoint.url}")
                all_vulnerabilities.extend(await xss_scanner.scan_endpoint(endpoint))
                all_vulnerabilities.extend(await sqli_scanner.scan_endpoint(endpoint))
                all_vulnerabilities.extend(await pt_scanner.scan_endpoint(endpoint))

    # Rapports
    generate_json_report(target, all_vulnerabilities, output_path=output_json)
    generate_html_report(target, all_vulnerabilities, output_path=output_html)

    print(f"\n{'=' * 50}")
    print(f"Scan terminé. {len(all_vulnerabilities)} vulnérabilité(s) trouvée(s).")
    print(f"Rapport JSON : {output_json}")
    print(f"Rapport HTML : {output_html}")
    print(f"{'=' * 50}")


@click.command()
@click.option("--target", "-t", required=True, help="URL cible à scanner (ex: http://localhost:8080)")
@click.option("--depth", "-d", default=2, help="Profondeur maximale du crawling (défaut: 2)")
@click.option("--concurrency", "-c", default=5, help="Nombre de requêtes simultanées (défaut: 5)")
@click.option("--mode", "-m", type=click.Choice(["passive", "active", "full"]), default="full", help="Mode d'analyse")
@click.option("--cookie", default="", help="Cookies d'authentification, format: 'PHPSESSID=xxx;security=low'")
@click.option("--output-html", default="reports/report.html", help="Chemin du rapport HTML")
@click.option("--output-json", default="reports/report.json", help="Chemin du rapport JSON")
def cli(target, depth, concurrency, mode, cookie, output_html, output_json):
    """PurpleScan - Scanner de vulnérabilités web asynchrone (VAPT/Purple Team)."""

    click.secho("\n⚠️  AVERTISSEMENT LÉGAL", fg="yellow", bold=True)
    click.echo("Cet outil effectue des tests actifs (injection de payloads).")
    click.echo("Utilisez-le UNIQUEMENT sur des cibles pour lesquelles vous avez une autorisation explicite.\n")

    if not click.confirm("Confirmez-vous être autorisé à scanner cette cible ?"):
        click.secho("Scan annulé.", fg="red")
        return

    cookies = parse_cookies(cookie)
    asyncio.run(run_scan(target, depth, concurrency, mode, cookies, output_html, output_json))


if __name__ == "__main__":
    cli()