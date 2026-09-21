import aiohttp
import yaml
import os
from core.models import Vulnerability, Severity, Endpoint

PAYLOADS_PATH = os.path.join("payloads", "xss_payloads.yaml")


class XSSScanner:
    def __init__(self, session: aiohttp.ClientSession):
        self.session = session
        self.payloads = self._load_payloads()

    def _load_payloads(self) -> list[str]:
        with open(PAYLOADS_PATH, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        return data.get("payloads", [])

    async def scan_endpoint(self, endpoint: Endpoint) -> list[Vulnerability]:
        vulnerabilities = []

        # Test sur les paramètres d'URL (GET)
        if endpoint.params:
            vulnerabilities.extend(await self._test_get_params(endpoint))

        # Test sur les formulaires (GET ou POST)
        for form in endpoint.forms:
            vulnerabilities.extend(await self._test_form(form))

        return vulnerabilities

    async def _test_get_params(self, endpoint: Endpoint) -> list[Vulnerability]:
        vulnerabilities = []
        base_url = endpoint.url.split("?")[0]

        for param in endpoint.params:
            for payload in self.payloads:
                try:
                    test_url = f"{base_url}?{param}={payload}"
                    async with self.session.get(test_url, timeout=10) as response:
                        body = await response.text()
                        if payload in body:
                            vulnerabilities.append(Vulnerability(
                                name=f"XSS Réfléchi détecté (paramètre GET '{param}')",
                                severity=Severity.HIGH,
                                endpoint=test_url,
                                description=f"Le payload injecté dans le paramètre '{param}' est reflété sans échappement dans la réponse HTML.",
                                evidence=f"Payload : {payload}",
                                remediation="Encoder/échapper systématiquement les données utilisateur avant de les insérer dans le HTML (ex: htmlspecialchars en PHP)."
                            ))
                            break  # un payload suffit pour ce paramètre
                except Exception as e:
                    print(f"[Erreur XSS GET] {test_url} -> {e}")

        return vulnerabilities

    async def _test_form(self, form) -> list[Vulnerability]:
        vulnerabilities = []

        for field in form.fields:
            if field.type in ("submit", "hidden", "button"):
                continue  # ne pas injecter dans les champs non pertinents

            for payload in self.payloads:
                data = {f.name: (payload if f.name == field.name else f.value) for f in form.fields}

                try:
                    if form.method.upper() == "POST":
                        async with self.session.post(form.action, data=data, timeout=10) as response:
                            body = await response.text()
                    else:
                        async with self.session.get(form.action, params=data, timeout=10) as response:
                            body = await response.text()

                    if payload in body:
                        vulnerabilities.append(Vulnerability(
                            name=f"XSS détecté (champ formulaire '{field.name}')",
                            severity=Severity.HIGH,
                            endpoint=form.action,
                            description=f"Le payload injecté dans le champ '{field.name}' du formulaire est reflété sans échappement.",
                            evidence=f"Payload : {payload} | Method: {form.method}",
                            remediation="Encoder/échapper systématiquement les données utilisateur avant insertion dans le HTML."
                        ))
                        break

                except Exception as e:
                    print(f"[Erreur XSS Form] {form.action} -> {e}")

        return vulnerabilities