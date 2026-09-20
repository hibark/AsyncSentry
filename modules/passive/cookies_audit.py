import aiohttp
from core.models import Vulnerability, Severity


class CookiesAuditor:
    def __init__(self, session: aiohttp.ClientSession):
        self.session = session

    async def audit(self, url: str) -> list[Vulnerability]:
        vulnerabilities = []

        try:
            async with self.session.get(url, timeout=10) as response:
                # aiohttp expose les cookies bruts via le header Set-Cookie
                raw_cookies = response.headers.getall("Set-Cookie", [])

                if not raw_cookies:
                    return vulnerabilities

                for raw_cookie in raw_cookies:
                    cookie_name = raw_cookie.split("=")[0].strip()
                    cookie_lower = raw_cookie.lower()

                    # Vérif HttpOnly
                    if "httponly" not in cookie_lower:
                        vulnerabilities.append(Vulnerability(
                            name=f"Cookie sans flag HttpOnly : {cookie_name}",
                            severity=Severity.MEDIUM,
                            endpoint=url,
                            description=f"Le cookie '{cookie_name}' est accessible via JavaScript (document.cookie), ce qui facilite le vol de session via XSS.",
                            evidence=raw_cookie,
                            remediation="Ajouter le flag 'HttpOnly' à ce cookie pour empêcher son accès via JavaScript."
                        ))

                    # Vérif Secure
                    if "secure" not in cookie_lower:
                        vulnerabilities.append(Vulnerability(
                            name=f"Cookie sans flag Secure : {cookie_name}",
                            severity=Severity.MEDIUM,
                            endpoint=url,
                            description=f"Le cookie '{cookie_name}' peut être transmis en clair sur une connexion HTTP non chiffrée.",
                            evidence=raw_cookie,
                            remediation="Ajouter le flag 'Secure' pour forcer l'envoi du cookie uniquement en HTTPS."
                        ))

                    # Vérif SameSite
                    if "samesite" not in cookie_lower:
                        vulnerabilities.append(Vulnerability(
                            name=f"Cookie sans attribut SameSite : {cookie_name}",
                            severity=Severity.LOW,
                            endpoint=url,
                            description=f"Le cookie '{cookie_name}' n'a pas d'attribut SameSite, ce qui augmente le risque de CSRF.",
                            evidence=raw_cookie,
                            remediation="Ajouter 'SameSite=Strict' ou 'SameSite=Lax' selon le besoin fonctionnel."
                        ))
                    elif "samesite=none" in cookie_lower and "secure" not in cookie_lower:
                        vulnerabilities.append(Vulnerability(
                            name=f"SameSite=None sans Secure : {cookie_name}",
                            severity=Severity.HIGH,
                            endpoint=url,
                            description=f"Le cookie '{cookie_name}' utilise 'SameSite=None' sans 'Secure', ce qui est rejeté par les navigateurs modernes ou expose à des risques CSRF.",
                            evidence=raw_cookie,
                            remediation="Ajouter 'Secure' lorsque 'SameSite=None' est utilisé."
                        ))

        except Exception as e:
            print(f"[Erreur audit cookies] {url} -> {e}")

        return vulnerabilities