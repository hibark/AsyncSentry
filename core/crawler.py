import asyncio
import aiohttp
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
from core.models import Endpoint, Form, FormField

class Crawler:
    def __init__(self, base_url: str, max_depth: int = 2, concurrency: int = 5):
        self.base_url = base_url
        self.domain = urlparse(base_url).netloc
        self.max_depth = max_depth
        self.visited = set()
        self.endpoints = []
        self.semaphore = asyncio.Semaphore(concurrency)

    def is_same_domain(self, url: str) -> bool:
        return urlparse(url).netloc == self.domain

    async def fetch(self, session: aiohttp.ClientSession, url: str) -> str | None:
        async with self.semaphore:
            try:
                async with session.get(url, timeout=10) as response:
                    if response.status == 200 and "text/html" in response.headers.get("Content-Type", ""):
                        return await response.text()
            except Exception as e:
                print(f"[Erreur] {url} -> {e}")
        return None

    def extract_links(self, html: str, current_url: str) -> list[str]:
        soup = BeautifulSoup(html, "lxml")
        links = []
        for tag in soup.find_all("a", href=True):
            full_url = urljoin(current_url, tag["href"])
            if self.is_same_domain(full_url):
                links.append(full_url.split("#")[0])
        return links

    def extract_params(self, url: str) -> list[str]:
        """Extrait les noms de paramètres GET depuis l'URL (?id=1&user=admin)"""
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        return list(query_params.keys())

    def extract_forms(self, html: str, current_url: str) -> list[Form]:
        """Extrait tous les formulaires d'une page avec leurs champs"""
        soup = BeautifulSoup(html, "lxml")
        forms = []

        for form_tag in soup.find_all("form"):
            action = form_tag.get("action", "")
            full_action = urljoin(current_url, action) if action else current_url
            method = form_tag.get("method", "GET").upper()

            fields = []
            # Champs <input>
            for input_tag in form_tag.find_all("input"):
                name = input_tag.get("name")
                if name:
                    fields.append(FormField(
                        name=name,
                        type=input_tag.get("type", "text"),
                        value=input_tag.get("value", "")
                    ))
            # Champs <textarea>
            for textarea in form_tag.find_all("textarea"):
                name = textarea.get("name")
                if name:
                    fields.append(FormField(name=name, type="textarea", value=textarea.text or ""))

            # Champs <select>
            for select in form_tag.find_all("select"):
                name = select.get("name")
                if name:
                    fields.append(FormField(name=name, type="select", value=""))

            if fields:
                forms.append(Form(action=full_action, method=method, fields=fields))

        return forms

    async def crawl(self, session: aiohttp.ClientSession, url: str, depth: int):
        if depth > self.max_depth or url in self.visited:
            return
        self.visited.add(url)

        html = await self.fetch(session, url)
        if html is None:
            return

        params = self.extract_params(url)
        forms = self.extract_forms(html, url)

        endpoint = Endpoint(url=url, method="GET", params=params, forms=forms)
        self.endpoints.append(endpoint)

        print(f"[+] Découvert : {url}")
        if params:
            print(f"    Paramètres : {params}")
        if forms:
            print(f"    Formulaires : {len(forms)} trouvé(s)")
            for f in forms:
                field_names = [fld.name for fld in f.fields]
                print(f"      -> action={f.action} method={f.method} champs={field_names}")

        links = self.extract_links(html, url)
        tasks = [self.crawl(session, link, depth + 1) for link in links]
        await asyncio.gather(*tasks)

    async def run(self):
        async with aiohttp.ClientSession() as session:
            await self.crawl(session, self.base_url, depth=0)
        return self.endpoints