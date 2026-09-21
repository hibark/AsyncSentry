import aiohttp
from core.models import Vulnerability, Severity

EVIL_ORIGIN = "https://evil-attacker.com"


class CorsAuditor:
    def __init__(self, session: aiohttp.ClientSession):
        self.session = session

    async def audit(self, url: str) -> list[Vulnerability]:
        vulnerabilities = []

        try:
            headers = {"Origin": EVIL_ORIGIN}
            async with self.session.get(url, headers=headers, timeout=10) as response:
                acao = response.headers.get("Access-Control-Allow-Origin")
                acac = response.headers.get("Access-Control-Allow-Credentials")

                if acao is None:
                    return vulnerabilities

                if acao == "*":
                    severity = Severity.MEDIUM
                    if acac and acac.lower() == "true":
                        severity = Severity.HIGH
                    vulnerabilities.append(Vulnerability(
                        name="Configuration CORS permissive (wildcard)",
                        severity=severity,
                        endpoint=url,
                        description="Le serveur autorise toutes les origines via 'Access-Control-Allow-Origin: *'.",
                        evidence=f"Access-Control-Allow-Origin: {acao}, Access-Control-Allow-Credentials: {acac}",
                        remediation="Restreindre 'Access-Control-Allow-Origin' à une liste blanche d'origines de confiance."
                    ))

                elif acao == EVIL_ORIGIN:
                    vulnerabilities.append(Vulnerability(
                        name="Réflexion dynamique de l'origine CORS (Origin Reflection)",
                        severity=Severity.CRITICAL,
                        endpoint=url,
                        description="Le serveur reflète automatiquement n'importe quelle origine envoyée dans le header 'Origin', permettant à un site malveillant de lire les réponses authentifiées.",
                        evidence=f"Origin envoyé: {EVIL_ORIGIN} -> Access-Control-Allow-Origin reçu: {acao}",
                        remediation="Valider strictement l'origine contre une liste blanche côté serveur, ne jamais la refléter directement."
                    ))

        except Exception as e:
            print(f"[Erreur audit CORS] {url} -> {e}")

        return vulnerabilities