import asyncio
import aiohttp
from core.crawler import Crawler
from modules.passive.headers_audit import HeadersAuditor
from modules.passive.cookies_audit import CookiesAuditor

async def main():
    target = "http://localhost:8080"

    # Phase 1 : Crawling
    crawler = Crawler(base_url=target, max_depth=2, concurrency=5)
    endpoints = await crawler.run()

    print(f"\n=== Résumé du crawl ===")
    print(f"Total endpoints découverts : {len(endpoints)}")

    # Phase 2 : Analyse passive
    print(f"\n=== Analyse passive ===")
    all_vulnerabilities = []

    async with aiohttp.ClientSession() as session:
        headers_auditor = HeadersAuditor(session)
        cookies_auditor = CookiesAuditor(session)

        for endpoint in endpoints:
            vulns_headers = await headers_auditor.audit(endpoint.url)
            vulns_cookies = await cookies_auditor.audit(endpoint.url)
            all_vulnerabilities.extend(vulns_headers)
            all_vulnerabilities.extend(vulns_cookies)

    # Affichage des résultats
    if all_vulnerabilities:
        print(f"\n[!] {len(all_vulnerabilities)} problème(s) détecté(s) :\n")
        for vuln in all_vulnerabilities:
            print(f"  [{vuln.severity.value}] {vuln.name}")
            print(f"    -> Endpoint : {vuln.endpoint}")
            print(f"    -> {vuln.description}")
            print(f"    -> Remédiation : {vuln.remediation}\n")
    else:
        print("Aucun problème détecté.")

if __name__ == "__main__":
    asyncio.run(main())