import asyncio
from core.crawler import Crawler

async def main():
    print("Démarrage du test...")
    crawler = Crawler(base_url="http://localhost:8080", max_depth=1, concurrency=5)
    endpoints = await crawler.run()
    print(f"Endpoints trouvés : {len(endpoints)}")
    for ep in endpoints:
        print(f" - {ep.url}")
    print("Test terminé.")

if __name__ == "__main__":
    asyncio.run(main())