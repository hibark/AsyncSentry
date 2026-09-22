import aiohttp
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
from core.models import Endpoint, Form, FormField
from core.scheduler import CrawlScheduler


class Crawler:
    def __init__(self, base_url: str, max_depth: int = 2, concurrency: int = 5, cookies: dict = None):
        self.base_url = base_url
        self.domain = urlparse(base_url).netloc
        self.max_depth = max_depth
        self.endpoints = []
        self.cookies = cookies or {}
        self.scheduler = CrawlScheduler(worker_count=concurrency)
        self.session: aiohttp.ClientSession | None = None

    def is_same_domain(self, url: str) -> bool:
        return urlparse(url).netloc == self.domain

    async def fetch(self, url: str) -> str | None:
        try:
            async with self.session.get(url, timeout=10) as response:
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
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        return list(query_params.keys())

    def extract_forms(self, html: str, current_url: str) -> list[Form]:
        soup = BeautifulSoup(html, "lxml")
        forms = []

        for form_tag in soup.find_all("form"):
            action = form_tag.get("action", "")
            full_action = urljoin(current_url, action) if action else current_url
            method = form_tag.get("method", "GET").upper()

            fields = []
            for input_tag in form_tag.find_all("input"):
                name = input_tag.get("name")
                if name:
                    fields.append(FormField(
                        name=name,
                        type=input_tag.get("type", "text"),
                        value=input_tag.get("value", "")
                    ))
            for textarea in form_tag.find_all("textarea"):
                name = textarea.get("name")
                if name:
                    fields.append(FormField(name=name, type="textarea", value=textarea.text or ""))
            for select in form_tag.find_all("select"):
                name = select.get("name")
                if name:
                    fields.append(FormField(name=name, type="select", value=""))

            if fields:
                forms.append(Form(action=full_action, method=method, fields=fields))

        return forms

    async def handle_url(self, url: str, depth: int):
        """Appelé par le scheduler pour chaque URL de la queue."""
        if depth > self.max_depth:
            return

        html = await self.fetch(url)
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

        links = self.extract_links(html, url)
        for link in links:
            await self.scheduler.add(link, depth + 1)

    async def run(self) -> list[Endpoint]:
        async with aiohttp.ClientSession(cookies=self.cookies) as session:
            self.session = session
            await self.scheduler.add(self.base_url, depth=0)
            await self.scheduler.run(self.handle_url)
        return self.endpoints