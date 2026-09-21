import aiohttp
import yaml
import os
from core.models import Vulnerability, Severity, Endpoint

PAYLOADS_PATH = os.path.join("payloads", "lfi_payloads.yaml")

# Noms de paramètres suspects, souvent liés à l'inclusion de fichiers
SUSPICIOUS_PARAM_NAMES = ["file", "page", "path", "doc", "document", "include", "filename", "view", "load"]


class PathTraversalScanner:
    def __init__(self, session: aiohttp.ClientSession):
        self.session = session
        self.payloads, self.signatures = self._load_payloads()

    def _load_payloads(self):
        with open(PAYLOADS_PATH, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        return data.get("payloads", []), data.get("signatures", [])

    def _is_suspicious(self, param_name: str) -> bool:
        return any(keyword in param_name.lower() for keyword in SUSPICIOUS_PARAM_NAMES)

    def _detect_signature(self, body: str) -> str | None:
        for sig in self.signatures:
            if sig.lower() in body.lower():
                return sig
        return None

    async def scan_endpoint(self, endpoint: Endpoint) -> list[Vulnerability]:
        vulnerabilities = []

        # On teste tous les paramètres (pas seulement les suspects, mais on priorise)
        params_to_test = endpoint.params if endpoint.params else []

        base_url = endpoint.url.split("?")[0]

        for param in params_to_test:
            for payload in self.payloads:
                test_url = f"{base_url}?{param}={payload}"
                try:
                    async with self.session.get(test_url, timeout=10) as response:
                        body = await response.text()
                        signature = self._detect_signature(body)
                        if signature:
                            vulnerabilities.append(Vulnerability(
                                name=f"Path Traversal / LFI détecté (paramètre '{param}')",
                                severity=Severity.CRITICAL,
                                endpoint=test_url,
                                description=f"Le paramètre '{param}' permet de lire des fichiers systèmes en dehors du répertoire web.",
                                evidence=f"Payload: {payload} | Signature trouvée: '{signature}'",
                                remediation="Valider strictement les chemins de fichiers, utiliser une liste blanche de fichiers autorisés, ne jamais construire un chemin depuis une entrée utilisateur brute."
                            ))
                            break
                except Exception as e:
                    print(f"[Erreur LFI] {test_url} -> {e}")

        return vulnerabilities