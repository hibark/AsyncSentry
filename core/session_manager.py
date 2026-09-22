import aiohttp


class SessionManager:
    """Gère la création et le cycle de vie des sessions HTTP asynchrones."""

    def __init__(self, cookies: dict = None, timeout: int = 10, headers: dict = None):
        self.cookies = cookies or {}
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.headers = headers or {
            "User-Agent": "AsyncSentry/1.0 (VAPT Security Scanner)"
        }
        self._session: aiohttp.ClientSession | None = None

    async def __aenter__(self) -> aiohttp.ClientSession:
        self._session = aiohttp.ClientSession(
            cookies=self.cookies,
            timeout=self.timeout,
            headers=self.headers
        )
        return self._session

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self._session:
            await self._session.close()

    async def create(self) -> aiohttp.ClientSession:
        """Alternative sans context manager, si besoin de garder la session ouverte plus longtemps."""
        self._session = aiohttp.ClientSession(
            cookies=self.cookies,
            timeout=self.timeout,
            headers=self.headers
        )
        return self._session

    async def close(self):
        if self._session and not self._session.closed:
            await self._session.close()