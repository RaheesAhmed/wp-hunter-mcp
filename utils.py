import asyncio
import random
from typing import Optional
import httpx

class HTTPClient:
    def __init__(self):
        self.ua_list = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
        ]
        self.client = httpx.AsyncClient(
            timeout=30.0,
            follow_redirects=True,
            http2=True,
        )
    
    async def get(self, url: str, headers: Optional[dict] = None) -> httpx.Response:
        """GET with random User-Agent"""
        ua = random.choice(self.ua_list)
        h = {"User-Agent": ua, "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"}
        if headers:
            h.update(headers)
        
        # Rate limiting
        await asyncio.sleep(0.5)
        return await self.client.get(url, headers=h)
    
    async def post(self, url: str, data: dict) -> httpx.Response:
        """POST with form data"""
        ua = random.choice(self.ua_list)
        
        await asyncio.sleep(1.0)  # Slower for POSTs
        return await self.client.post(
            url,
            data=data,
            headers={
                "User-Agent": ua,
                "Content-Type": "application/x-www-form-urlencoded",
            },
        )

def normalize_url(url: str) -> str:
    """Ensure URL has protocol and trailing slash"""
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"
    return url if url.endswith("/") else f"{url}/"

http = HTTPClient()
