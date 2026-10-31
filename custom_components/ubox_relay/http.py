"""Authenticated-by-secret export for go2rtc; no camera credentials in URLs."""

from __future__ import annotations

import asyncio
import hmac

import aiohttp
from aiohttp import web
from homeassistant.components.http import HomeAssistantView
from homeassistant.core import HomeAssistant

from .const import DOMAIN


class UBoxStreamView(HomeAssistantView):
    """Proxy one bounded local MPEG-TS subscription over the HA HTTP server."""

    url = f"/api/{DOMAIN}/{{entry_id}}/stream.ts"
    name = f"api:{DOMAIN}:stream"
    requires_auth = False

    def __init__(self, hass: HomeAssistant, session: aiohttp.ClientSession) -> None:
        self.hass = hass
        self.session = session

    async def get(self, request: web.Request, entry_id: str) -> web.StreamResponse:
        entry = self.hass.data.get(DOMAIN, {}).get("entries", {}).get(entry_id)
        supplied = request.query.get("token", "")
        expected = entry.data.get("export_token", "") if entry else ""
        if (
            not expected
            or not supplied
            or len(supplied) > 256
            or not hmac.compare_digest(supplied.encode(), expected.encode())
        ):
            raise web.HTTPNotFound()
        runtime = entry.runtime_data
        source = runtime.manager.stream_url
        if source is None:
            raise web.HTTPServiceUnavailable()
        task = asyncio.current_task()
        runtime.export_tasks.add(task)
        response = web.StreamResponse(
            headers={
                "Content-Type": "video/mp2t",
                "Cache-Control": "no-store",
                "X-Content-Type-Options": "nosniff",
                "Referrer-Policy": "no-referrer",
            }
        )
        try:
            timeout = aiohttp.ClientTimeout(total=None, sock_connect=5, sock_read=35)
            async with self.session.get(source, timeout=timeout) as upstream:
                if upstream.status != 200:
                    raise web.HTTPServiceUnavailable()
                await response.prepare(request)
                async for chunk in upstream.content.iter_chunked(32768):
                    await asyncio.wait_for(response.write(chunk), 5)
        except aiohttp.ClientError, TimeoutError, ConnectionError:
            if not response.prepared:
                raise web.HTTPServiceUnavailable() from None
        finally:
            runtime.export_tasks.discard(task)
        return response
