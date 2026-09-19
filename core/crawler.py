import asyncio
import aiohttp
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from core.models import Endpoint

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
                links.append(full_url.split("#")[0])  # enlever les ancres
        return links

    async def crawl(self, session: aiohttp.ClientSession, url: str, depth: int):
        if depth > self.max_depth or url in self.visited:
            return
        self.visited.add(url)

        html = await self.fetch(session, url)
        if html is None:
            return

        self.endpoints.append(Endpoint(url=url))
        print(f"[+] Découvert : {url}")

        links = self.extract_links(html, url)
        tasks = [self.crawl(session, link, depth + 1) for link in links]
        await asyncio.gather(*tasks)

    async def run(self):
        async with aiohttp.ClientSession() as session:
            await self.crawl(session, self.base_url, depth=0)
        return self.endpoints