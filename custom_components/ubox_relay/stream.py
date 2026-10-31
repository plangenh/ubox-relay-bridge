"""On-demand, loopback-only camera transport and bounded FFmpeg pipelines.

No Home Assistant imports: the integration supplies its FFmpeg binary. A cold
snapshot may need a second request: caller cancellation leaves the bounded
shared snapshot job running so the next request can use its JPEG cache.
"""

from __future__ import annotations

import asyncio
import hmac
import secrets
import time
from collections.abc import Callable
from contextlib import suppress
from typing import Any

from aiohttp import web

_CHUNK = 32768
_QUEUE_CHUNKS = 128  # At most 4 MiB per consumer; never discard TS and continue.
_MAX_CLIENTS = 8
_EOF = object()


class StreamManager:
    """Share one relay/transcoder among viewers and temporary JPEG consumers."""

    def __init__(
        self,
        credentials: Any,
        ffmpeg_binary: str,
        relay_host: str | None = None,
        *,
        client_factory: Callable | None = None,
        idle_timeout: float = 12.0,
    ) -> None:
        self._credentials = credentials
        self._ffmpeg = ffmpeg_binary
        self._relay_host = relay_host
        if client_factory is None:
            from .protocol import RelayClient

            client_factory = RelayClient
        self._client_factory = client_factory
        self._idle_timeout = idle_timeout
        self._lock = asyncio.Lock()
        self._runner: web.AppRunner | None = None
        self._url: str | None = None
        self._token = ""
        self._closed = True
        self._worker: asyncio.Task | None = None
        self._idle_task: asyncio.Task | None = None
        self._stop = asyncio.Event()
        self._subscribers: set[asyncio.Queue] = set()
        self._snapshot_task: asyncio.Task | None = None
        self._last_image: bytes | None = None
        self._image_at = 0.0
        self.diagnostics: dict[str, int] = {}

    @property
    def stream_url(self) -> str | None:
        """Ephemeral secret URL, to pass directly to HA stream/FFmpeg only."""
        return self._url

    async def async_start(self) -> None:
        async with self._lock:
            if not self._closed:
                return
            self._token = secrets.token_urlsafe(32)
            app = web.Application()
            app.router.add_get("/{token}/stream.ts", self._handle_stream)
            runner = web.AppRunner(app, access_log=None, shutdown_timeout=1.0)
            try:
                await runner.setup()
                site = web.TCPSite(runner, "127.0.0.1", 0)
                await site.start()
                # AppRunner.addresses is public aiohttp API and includes the
                # actual ephemeral port, unlike TCPSite.name (requested port).
                port = runner.addresses[0][1]
            except BaseException:
                await runner.cleanup()
                self._token = ""
                raise
            self._runner = runner
            self._url = f"http://127.0.0.1:{port}/{self._token}/stream.ts"
            self._closed = False

    async def async_stop(self) -> None:
        async with self._lock:
            self._closed = True
            self._url = None
            self._token = ""
            await self._cancel(self._idle_task)
            self._idle_task = None
            # Snapshot cleanup unsubscribes under this lock. Cancel it here,
            # but await outside the lock to avoid unload deadlock.
            snapshot = self._snapshot_task
            if snapshot is not None:
                snapshot.cancel()
            self._finish_subscribers()
            await self._stop_worker()
            runner, self._runner = self._runner, None
        await self._cancel(snapshot)
        self._snapshot_task = None
        if runner is not None:
            await runner.cleanup()
        self._last_image = None
        self._image_at = 0.0

    async def _subscribe(self) -> asyncio.Queue:
        async with self._lock:
            if self._closed:
                raise RuntimeError("stream_stopped")
            if len(self._subscribers) >= _MAX_CLIENTS:
                raise RuntimeError("stream_client_limit")
            await self._cancel(self._idle_task)
            self._idle_task = None
            queue: asyncio.Queue = asyncio.Queue(maxsize=_QUEUE_CHUNKS)
            self._subscribers.add(queue)
            if self._worker is None or self._worker.done():
                self._stop = asyncio.Event()
                self._worker = asyncio.create_task(self._produce(), name="ubox-video")
            return queue

    async def _unsubscribe(self, queue: asyncio.Queue) -> None:
        async with self._lock:
            self._subscribers.discard(queue)
            if not self._closed and not self._subscribers and self._idle_task is None:
                self._idle_task = asyncio.create_task(self._idle(), name="ubox-idle")

    async def _idle(self) -> None:
        await asyncio.sleep(self._idle_timeout)
        async with self._lock:
            if not self._subscribers:
                await self._stop_worker()
            self._idle_task = None

    @staticmethod
    def _finish_queue(queue: asyncio.Queue) -> None:
        # A terminal EOF closes this consumer. It is never resumed after loss.
        while not queue.empty():
            queue.get_nowait()
        queue.put_nowait(_EOF)

    def _finish_subscribers(self) -> None:
        for queue in tuple(self._subscribers):
            self._finish_queue(queue)
        self._subscribers.clear()

    def _publish(self, chunk: bytes) -> None:
        for queue in tuple(self._subscribers):
            if queue.full():
                self._subscribers.discard(queue)
                self._finish_queue(queue)
                self.diagnostics["slow_consumers"] = (
                    self.diagnostics.get("slow_consumers", 0) + 1
                )
            else:
                queue.put_nowait(chunk)

    async def _handle_stream(self, request: web.Request) -> web.StreamResponse:
        token = request.match_info["token"].encode("utf-8")
        if self._closed or not hmac.compare_digest(token, self._token.encode()):
            raise web.HTTPNotFound()
        try:
            queue = await self._subscribe()
        except RuntimeError:
            raise web.HTTPServiceUnavailable() from None
        response = web.StreamResponse(
            headers={
                "Content-Type": "video/mp2t",
                "Cache-Control": "no-store",
                "X-Content-Type-Options": "nosniff",
            }
        )
        try:
            await response.prepare(request)
            while True:
                # Periodically notice a disconnected HTTP consumer even while
                # a cold relay is silent; otherwise it could hold the camera.
                try:
                    item = await asyncio.wait_for(queue.get(), 0.5)
                except TimeoutError:
                    if request.transport is None or request.transport.is_closing():
                        break
                    continue
                if item is _EOF:
                    break
                await asyncio.wait_for(response.write(item), 5.0)
        except ConnectionError, TimeoutError, RuntimeError:
            pass
        finally:
            await self._unsubscribe(queue)
        return response

    def _producer_command(self) -> list[str]:
        return [
            self._ffmpeg,
            "-hide_banner",
            "-loglevel",
            "error",
            "-fflags",
            "+genpts",
            "-f",
            "hevc",
            "-i",
            "pipe:0",
            "-an",
            "-c:v",
            "libx264",
            "-preset",
            "ultrafast",
            "-tune",
            "zerolatency",
            "-pix_fmt",
            "yuv420p",
            "-g",
            "15",
            "-keyint_min",
            "15",
            "-sc_threshold",
            "0",
            "-x264-params",
            "repeat-headers=1",
            "-f",
            "mpegts",
            "-mpegts_flags",
            "+resend_headers",
            "-muxdelay",
            "0",
            "-muxpreload",
            "0",
            "pipe:1",
        ]

    async def _produce(self) -> None:
        process = None
        tasks: list[asyncio.Task] = []
        try:
            process = await asyncio.create_subprocess_exec(
                *self._producer_command(),
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            client = self._client_factory(
                self._credentials,
                relay_host=self._relay_host,
                initial_timeout=15,
                inactivity_timeout=10,
            )

            async def on_video(frame: bytes) -> None:
                # FFmpeg blockage must never indefinitely stall UDP ACKs.
                if self._stop.is_set():
                    raise RuntimeError("stream_stopped")
                process.stdin.write(frame)
                await asyncio.wait_for(process.stdin.drain(), 2.0)

            async def relay() -> None:
                result = await client.run(on_video, self._stop)
                if isinstance(result, dict):
                    self.diagnostics.update(
                        {
                            k: v
                            for k, v in result.items()
                            if isinstance(k, str) and isinstance(v, int)
                        }
                    )

            async def output() -> None:
                while chunk := await process.stdout.read(_CHUNK):
                    self._publish(chunk)

            tasks = [
                asyncio.create_task(relay()),
                asyncio.create_task(output()),
                asyncio.create_task(self._discard(process.stderr)),
            ]
            done, _ = await asyncio.wait(tasks[:2], return_when=asyncio.FIRST_COMPLETED)
            for task in done:
                task.result()
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 - sanitize external protocol/FFmpeg failures
            # Never propagate raw subprocess/protocol exception content into
            # HA logs: errors can include paths, packets or credentials.
            self.diagnostics["producer_failures"] = (
                self.diagnostics.get("producer_failures", 0) + 1
            )
        finally:
            self._stop.set()
            for task in tasks:
                await self._cancel(task)
            await self._terminate(process)
            self._finish_subscribers()

    async def _stop_worker(self) -> None:
        self._stop.set()
        worker, self._worker = self._worker, None
        await self._cancel(worker)

    @staticmethod
    async def _cancel(task: asyncio.Task | None) -> None:
        if task is None or task is asyncio.current_task():
            return
        if not task.done():
            task.cancel()
        with suppress(asyncio.CancelledError, Exception):
            await asyncio.wait_for(task, 4.0)

    @staticmethod
    async def _discard(reader: asyncio.StreamReader) -> None:
        while await reader.read(_CHUNK):
            pass

    @staticmethod
    async def _terminate(process: asyncio.subprocess.Process | None) -> None:
        if process is None:
            return
        # asyncio Process.wait can wait for pipe transports even after SIGKILL
        # when an unread StreamReader has paused its OS pipe. The normal output
        # readers have already been canceled, so drain both pipes during reap.
        drains = [
            asyncio.create_task(StreamManager._discard(reader))
            for reader in (process.stdout, process.stderr)
            if reader is not None
        ]
        try:
            if process.stdin is not None:
                process.stdin.close()
            if process.returncode is None:
                with suppress(ProcessLookupError):
                    process.terminate()
                try:
                    await asyncio.wait_for(process.wait(), 2.0)
                except TimeoutError:
                    with suppress(ProcessLookupError):
                        process.kill()
                    await asyncio.wait_for(process.wait(), 2.0)
            else:
                await asyncio.wait_for(process.wait(), 2.0)
        finally:
            for task in drains:
                await StreamManager._cancel(task)

    async def async_snapshot(self) -> bytes | None:
        """Use shared MPEG-TS; keep a bounded capture alive after caller timeout.

        A previous JPEG is returned immediately while a refresh runs. Cold
        callers can cancel safely; a successful background capture warms cache.
        """
        if self._closed:
            return None
        if self._last_image is not None and time.monotonic() - self._image_at < 10:
            return self._last_image
        if self._snapshot_task is None or self._snapshot_task.done():
            self._snapshot_task = asyncio.create_task(
                self._capture_snapshot(), name="ubox-jpeg"
            )
        if self._last_image is not None:
            return self._last_image
        return await asyncio.shield(self._snapshot_task)

    async def _capture_snapshot(self) -> bytes | None:
        queue = None
        process = None
        tasks: list[asyncio.Task] = []
        try:
            async with asyncio.timeout(20):
                queue = await self._subscribe()
                process = await asyncio.create_subprocess_exec(
                    self._ffmpeg,
                    "-hide_banner",
                    "-loglevel",
                    "error",
                    "-f",
                    "mpegts",
                    "-i",
                    "pipe:0",
                    "-an",
                    "-frames:v",
                    "1",
                    "-f",
                    "image2pipe",
                    "-c:v",
                    "mjpeg",
                    "pipe:1",
                    stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )

                async def feed() -> None:
                    while True:
                        chunk = await queue.get()
                        if chunk is _EOF:
                            process.stdin.close()
                            return
                        process.stdin.write(chunk)
                        await asyncio.wait_for(process.stdin.drain(), 2.0)

                async def read_image() -> bytes:
                    image = bytearray()
                    while chunk := await process.stdout.read(_CHUNK):
                        image.extend(chunk)
                        if len(image) > 2_000_000:
                            raise RuntimeError("snapshot_limit")
                    return bytes(image)

                tasks = [
                    asyncio.create_task(feed()),
                    asyncio.create_task(self._discard(process.stderr)),
                ]
                image = await read_image()
                code = await process.wait()
                if (
                    code == 0
                    and image.startswith(b"\xff\xd8")
                    and image.endswith(b"\xff\xd9")
                ):
                    self._last_image = image
                    self._image_at = time.monotonic()
                    return image
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 - sanitize external protocol/FFmpeg failures
            self.diagnostics["snapshot_failures"] = (
                self.diagnostics.get("snapshot_failures", 0) + 1
            )
        finally:
            for task in tasks:
                await self._cancel(task)
            await self._terminate(process)
            if queue is not None:
                await self._unsubscribe(queue)
        return self._last_image
