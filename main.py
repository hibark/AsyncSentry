import asyncio
import aiohttp

async def check_target(url: str):
    async with aiohttp.ClientSession() as session:
        async with session.get(url) as response:
            print(f"Status: {response.status}")
            print("Headers:")
            for key, value in response.headers.items():
                print(f"  {key}: {value}")

if __name__ == "__main__":
    asyncio.run(check_target("http://localhost:8080"))
    