import asyncio
from core.crawler import Crawler

async def main():
    target = "http://localhost:8080"
    crawler = Crawler(base_url=target, max_depth=2, concurrency=5)
    endpoints = await crawler.run()

    print(f"\n=== Résumé ===")
    print(f"Total endpoints découverts : {len(endpoints)}")
    for ep in endpoints:
        print(f" - {ep.url}")

if __name__ == "__main__":
    asyncio.run(main())