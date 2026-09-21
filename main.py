import asyncio
import aiohttp

from core.crawler import Crawler
from modules.passive.headers_audit import HeadersAuditor
from modules.passive.cookies_audit import CookiesAuditor
from modules.passive.cors_audit import CorsAuditor
from modules.active.xss import XSSScanner
from modules.active.sqli import SQLiScanner
from modules.active.path_traversal import PathTraversalScanner


async def main():
    target = "http://localhost:8080"

    # Cookies DVWA pour scanner en étant authentifié
    # Remplace la valeur de PHPSESSID par celle récupérée dans ton navigateur
    mes_cookies = {
        "PHPSESSID": "b72eo8m4fbf198f3ah6vj56au7",
        "security": "low"
    }

    # ================================
    # Phase 1 : Cartographie (Crawling)
    # ================================
    print(f"=== Phase 1 : Crawling de {target} ===\n")
    crawler = Crawler(base_url=target, max_depth=2, concurrency=5, cookies=mes_cookies)
    endpoints = await crawler.run()

    print(f"\n=== Résumé du crawl ===")
    print(f"Total endpoints découverts : {len(endpoints)}")
    total_forms = sum(len(ep.forms) for ep in endpoints)
    total_params = sum(len(ep.params) for ep in endpoints)
    print(f"Total formulaires trouvés  : {total_forms}")
    print(f"Total paramètres trouvés   : {total_params}")

    all_vulnerabilities = []

    async with aiohttp.ClientSession(cookies=mes_cookies) as session:

        # ================================
        # Phase 2 : Analyse passive
        # ================================
        print(f"\n=== Phase 2 : Analyse passive ===")
        headers_auditor = HeadersAuditor(session)
        cookies_auditor = CookiesAuditor(session)
        cors_auditor = CorsAuditor(session)

        for endpoint in endpoints:
            print(f"[*] Audit passif : {endpoint.url}")
            all_vulnerabilities.extend(await headers_auditor.audit(endpoint.url))
            all_vulnerabilities.extend(await cookies_auditor.audit(endpoint.url))
            all_vulnerabilities.extend(await cors_auditor.audit(endpoint.url))

        # ================================
        # Phase 3 : Analyse active (XSS, SQLi, LFI)
        # ================================
        print(f"\n=== Phase 3 : Analyse active ===")
        xss_scanner = XSSScanner(session)
        sqli_scanner = SQLiScanner(session)
        pt_scanner = PathTraversalScanner(session)

        for endpoint in endpoints:
            print(f"[*] Audit actif sur : {endpoint.url}")
            all_vulnerabilities.extend(await xss_scanner.scan_endpoint(endpoint))
            all_vulnerabilities.extend(await sqli_scanner.scan_endpoint(endpoint))
            all_vulnerabilities.extend(await pt_scanner.scan_endpoint(endpoint))

    # ================================
    # Résultats finaux
    # ================================
    print(f"\n{'=' * 50}")
    print("RÉSULTATS FINAUX DU SCAN")
    print(f"{'=' * 50}")

    if len(all_vulnerabilities) == 0:
        print("\n[-] Aucune faille trouvée (ou les cookies fournis sont invalides).")
    else:
        # Tri par criticité
        severity_order = {
            "Critique": 0,
            "Élevé": 1,
            "Moyen": 2,
            "Faible": 3,
            "Info": 4
        }
        sorted_vulns = sorted(
            all_vulnerabilities,
            key=lambda v: severity_order.get(v.severity.value, 99)
        )

        print(f"\n[+] {len(sorted_vulns)} faille(s) trouvée(s) !\n")
        for vuln in sorted_vulns:
            print(f"  [{vuln.severity.value}] {vuln.name}")
            print(f"    URL          : {vuln.endpoint}")
            print(f"    Description  : {vuln.description}")
            if vuln.evidence:
                print(f"    Preuve       : {vuln.evidence}")
            print(f"    Remédiation  : {vuln.remediation}")
            print("-" * 50)

        print(f"\nRésumé par criticité :")
        for level in ["Critique", "Élevé", "Moyen", "Faible", "Info"]:
            count = sum(1 for v in sorted_vulns if v.severity.value == level)
            if count > 0:
                print(f"  {level} : {count}")


if __name__ == "__main__":
    asyncio.run(main())