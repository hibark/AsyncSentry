import aiohttp
from core.models import Vulnerability, Severity

SECURITY_HEADERS = {
    "Content-Security-Policy": Severity.HIGH,
    "Strict-Transport-Security": Severity.HIGH,
    "X-Content-Type-Options": Severity.MEDIUM,
    "X-Frame-Options": Severity.MEDIUM,
    "Referrer-Policy": Severity.LOW,
    "Permissions-Policy": Severity.LOW,
}

REMEDIATIONS = {
    "Content-Security-Policy": "Définir une politique CSP stricte pour limiter les sources de scripts/styles.",
    "Strict-Transport-Security": "Ajouter 'Strict-Transport-Security: max-age=31536000; includeSubDomains' pour forcer HTTPS.",
    "X-Content-Type-Options": "Ajouter 'X-Content-Type-Options: nosniff' pour empêcher le MIME-sniffing.",
    "X-Frame-Options": "Ajouter 'X-Frame-Options: DENY' ou 'SAMEORIGIN' pour prévenir le clickjacking.",
    "Referrer-Policy": "Définir une politique Referrer-Policy (ex: 'strict-origin-when-cross-origin').",
    "Permissions-Policy": "Restreindre les APIs navigateur sensibles (caméra, géolocalisation, etc.).",
}


class HeadersAuditor:
    def __init__(self, session: aiohttp.ClientSession):
        self.session = session

    async def audit(self, url: str) -> list[Vulnerability]:
        vulnerabilities = []

        try:
            async with self.session.get(url, timeout=10) as response:
                headers = response.headers

                for header_name, severity in SECURITY_HEADERS.items():
                    if header_name not in headers:
                        vulnerabilities.append(Vulnerability(
                            name=f"Header de sécurité manquant : {header_name}",
                            severity=severity,
                            endpoint=url,
                            description=f"Le header '{header_name}' n'est pas présent dans la réponse HTTP.",
                            evidence=f"Headers reçus : {dict(headers)}",
                            remediation=REMEDIATIONS[header_name]
                        ))

                if "Server" in headers:
                    server_value = headers["Server"]
                    if any(char.isdigit() for char in server_value):
                        vulnerabilities.append(Vulnerability(
                            name="Divulgation de version serveur",
                            severity=Severity.LOW,
                            endpoint=url,
                            description="Le header 'Server' révèle la version exacte du logiciel serveur.",
                            evidence=f"Server: {server_value}",
                            remediation="Masquer ou généraliser le header 'Server' (ex: retirer le numéro de version)."
                        ))

        except Exception as e:
            print(f"[Erreur audit headers] {url} -> {e}")

        return vulnerabilities