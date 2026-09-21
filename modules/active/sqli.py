import aiohttp
import yaml
import os
import time
from core.models import Vulnerability, Severity, Endpoint

PAYLOADS_PATH = os.path.join("payloads", "sqli_payloads.yaml")


class SQLiScanner:
    def __init__(self, session: aiohttp.ClientSession):
        self.session = session
        self.payloads, self.error_signatures = self._load_payloads()

    def _load_payloads(self):
        with open(PAYLOADS_PATH, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        return data.get("payloads", []), data.get("error_signatures", [])

    def _detect_error(self, body: str) -> str | None:
        body_lower = body.lower()
        for signature in self.error_signatures:
            if signature.lower() in body_lower:
                return signature
        return None

    async def scan_endpoint(self, endpoint: Endpoint) -> list[Vulnerability]:
        vulnerabilities = []

        if endpoint.params:
            vulnerabilities.extend(await self._test_get_params(endpoint))

        for form in endpoint.forms:
            vulnerabilities.extend(await self._test_form(form))

        return vulnerabilities

    async def _test_get_params(self, endpoint: Endpoint) -> list[Vulnerability]:
        vulnerabilities = []
        base_url = endpoint.url.split("?")[0]

        for param in endpoint.params:
            # 1. Test error-based
            for payload in self.payloads:
                test_url = f"{base_url}?{param}={payload}"
                try:
                    async with self.session.get(test_url, timeout=10) as response:
                        body = await response.text()
                        signature = self._detect_error(body)
                        if signature:
                            vulnerabilities.append(Vulnerability(
                                name=f"Injection SQL détectée (paramètre GET '{param}')",
                                severity=Severity.CRITICAL,
                                endpoint=test_url,
                                description=f"Une erreur SQL a été déclenchée en injectant un payload dans le paramètre '{param}'.",
                                evidence=f"Payload: {payload} | Signature trouvée: '{signature}'",
                                remediation="Utiliser des requêtes paramétrées (prepared statements) au lieu de concaténer les entrées utilisateur."
                            ))
                            break
                except Exception as e:
                    print(f"[Erreur SQLi GET] {test_url} -> {e}")

            # 2. Test time-based (SLEEP) pour détecter les injections aveugles
            await self._test_time_based(base_url, param, vulnerabilities, is_form=False)

        return vulnerabilities

    async def _test_time_based(self, url, param_or_field, vulnerabilities, is_form=False, form=None):
        payload = "' AND SLEEP(5)-- "
        try:
            start = time.monotonic()
            if not is_form:
                test_url = f"{url}?{param_or_field}={payload}"
                async with self.session.get(test_url, timeout=15) as response:
                    await response.text()
            else:
                data = {f.name: (payload if f.name == param_or_field else f.value) for f in form.fields}
                if form.method.upper() == "POST":
                    async with self.session.post(form.action, data=data, timeout=15) as response:
                        await response.text()
                else:
                    async with self.session.get(form.action, params=data, timeout=15) as response:
                        await response.text()
            elapsed = time.monotonic() - start

            if elapsed >= 4.5:  # marge sous les 5s du SLEEP
                target = url if not is_form else form.action
                vulnerabilities.append(Vulnerability(
                    name=f"Injection SQL aveugle (time-based) détectée sur '{param_or_field}'",
                    severity=Severity.CRITICAL,
                    endpoint=target,
                    description=f"Le serveur a mis {elapsed:.1f}s à répondre après injection d'un payload SLEEP(5), suggérant une exécution SQL non filtrée.",
                    evidence=f"Payload: {payload} | Temps de réponse: {elapsed:.1f}s",
                    remediation="Utiliser des requêtes paramétrées (prepared statements) et valider strictement les entrées utilisateur."
                ))
        except Exception as e:
            print(f"[Erreur SQLi time-based] {url} -> {e}")

    async def _test_form(self, form) -> list[Vulnerability]:
        vulnerabilities = []

        for field in form.fields:
            if field.type in ("submit", "hidden", "button"):
                continue

            for payload in self.payloads:
                data = {f.name: (payload if f.name == field.name else f.value) for f in form.fields}
                try:
                    if form.method.upper() == "POST":
                        async with self.session.post(form.action, data=data, timeout=10) as response:
                            body = await response.text()
                    else:
                        async with self.session.get(form.action, params=data, timeout=10) as response:
                            body = await response.text()

                    signature = self._detect_error(body)
                    if signature:
                        vulnerabilities.append(Vulnerability(
                            name=f"Injection SQL détectée (champ formulaire '{field.name}')",
                            severity=Severity.CRITICAL,
                            endpoint=form.action,
                            description=f"Une erreur SQL a été déclenchée en injectant un payload dans le champ '{field.name}'.",
                            evidence=f"Payload: {payload} | Signature trouvée: '{signature}'",
                            remediation="Utiliser des requêtes paramétrées (prepared statements) au lieu de concaténer les entrées utilisateur."
                        ))
                        break
                except Exception as e:
                    print(f"[Erreur SQLi Form] {form.action} -> {e}")

            # Time-based sur les formulaires aussi
            await self._test_time_based(form.action, field.name, vulnerabilities, is_form=True, form=form)

        return vulnerabilities