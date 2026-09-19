import asyncio
import aiohttp
from core.crawler import Crawler
from modules.passive.headers_audit import HeadersAuditor

async def main():
    target = "http://localhost:8080"

    # Phase 1 : Crawling
    crawler = Crawler(base_url=target, max_depth=2, concurrency=5)
    endpoints = await crawler.run()

    print(f"\n=== Résumé du crawl ===")
    print(f"Total endpoints découverts : {len(endpoints)}")

    # Phase 2 : Analyse passive (Security Headers)
    print(f"\n=== Analyse passive : Security Headers ===")
    all_vulnerabilities = []

    async with aiohttp.ClientSession() as session:
        auditor = HeadersAuditor(session)
        for endpoint in endpoints:
            vulns = await auditor.audit(endpoint.url)
            all_vulnerabilities.extend(vulns)

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