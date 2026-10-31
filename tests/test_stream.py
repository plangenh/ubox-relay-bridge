"""Transport/lifecycle tests with synthetic video and fake FFmpeg processes."""

import asyncio
import importlib.util
from pathlib import Path

import aiohttp
import pytest

spec = importlib.util.spec_from_file_location(
    "ubox_stream_standalone",
    Path(__file__).parents[1] / "custom_components/ubox_relay/stream.py",
)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
StreamManager = module.StreamManager

# Only synthetic local HTTP traffic is used; camera/protocol and FFmpeg are fake.
pytestmark = pytest.mark.usefixtures("socket_enabled")


class FakeInput:
    def __init__(self, process):
        self.process = process
        self.closed = False

    def write(self, data):
        if self.closed:
            raise BrokenPipeError()
        if self.process.snapshot:
            self.process.stdout.feed_data(b"\xff\xd8synthetic-jpeg\xff\xd9")
            self.process.stdout.feed_eof()
            self.process.returncode = 0
        else:
            self.process.stdout.feed_data(b"GTS" + data)

    async def drain(self):
        await asyncio.sleep(0)

    def close(self):
        self.closed = True


class FakeProcess:
    def __init__(self, snapshot):
        self.snapshot = snapshot
        self.returncode = None
        self.stdout = asyncio.StreamReader()
        self.stderr = asyncio.StreamReader()
        self.stdin = FakeInput(self)
        self.finished = asyncio.Event()

    def terminate(self):
        self.returncode = -15
        self.stdout.feed_eof()
        self.stderr.feed_eof()
        self.finished.set()

    def kill(self):
        self.terminate()

    async def wait(self):
        if self.returncode is None:
            await self.finished.wait()
        return self.returncode


class FakeClient:
    active = 0
    runs = 0
    stopped = 0

    def __init__(self, credentials, **kwargs):
        pass

    async def run(self, on_video, stop):
        type(self).active += 1
        type(self).runs += 1
        try:
            while not stop.is_set():
                await on_video(b"video")
                await asyncio.sleep(0.01)
            return {"video_units": 1}
        finally:
            type(self).active -= 1
            type(self).stopped += 1


@pytest.fixture
def processes(monkeypatch):
    result = []
    FakeClient.active = FakeClient.runs = FakeClient.stopped = 0

    async def spawn(*args, **kwargs):
        process = FakeProcess("image2pipe" in args)
        result.append(process)
        return process

    monkeypatch.setattr(module.asyncio, "create_subprocess_exec", spawn)
    return result


def manager():
    return StreamManager(
        object(), "/synthetic/ffmpeg", client_factory=FakeClient, idle_timeout=0.02
    )


@pytest.mark.asyncio
async def test_http_shared_producer_auth_and_unload(processes):
    m = manager()
    await m.async_start()
    try:
        assert FakeClient.runs == 0  # Starting integration never wakes camera.
        async with aiohttp.ClientSession() as session:
            denied = await session.get(m.stream_url.replace(m._token, "wrong"))
            assert denied.status == 404
            denied.release()
            first, second = await asyncio.gather(
                session.get(m.stream_url), session.get(m.stream_url)
            )
            assert await first.content.read(8) == b"GTSvideo"
            assert await second.content.read(8) == b"GTSvideo"
            assert FakeClient.runs == 1
            assert len(processes) == 1
            first.close()
            second.close()
        await m.async_stop()
        assert FakeClient.active == 0
        assert processes[0].returncode is not None
        assert m.stream_url is None
        assert not m._subscribers
    finally:
        await m.async_stop()


@pytest.mark.asyncio
async def test_idle_cleanup_then_cold_restart(processes):
    m = manager()
    await m.async_start()
    try:
        q = await m._subscribe()
        await asyncio.wait_for(q.get(), 1)
        await m._unsubscribe(q)
        await asyncio.sleep(0.06)
        assert FakeClient.active == 0
        assert processes[0].returncode is not None
        q2 = await m._subscribe()
        await asyncio.wait_for(q2.get(), 1)
        assert FakeClient.runs == 2
        await m._unsubscribe(q2)
    finally:
        await m.async_stop()


@pytest.mark.asyncio
async def test_slow_consumer_closed_not_resumed_and_limit(processes):
    m = manager()
    await m.async_start()
    try:
        queues = [await m._subscribe() for _ in range(8)]
        with pytest.raises(RuntimeError, match="client_limit"):
            await m._subscribe()
        for _ in range(module._QUEUE_CHUNKS + 1):
            m._publish(b"x" * module._CHUNK)
        assert not m._subscribers
        for q in queues:
            assert q.qsize() == 1
            assert q.get_nowait() is module._EOF
        assert m.diagnostics["slow_consumers"] == 8
    finally:
        await m.async_stop()


@pytest.mark.asyncio
async def test_snapshot_shares_stream_and_uses_cache(processes):
    m = manager()
    await m.async_start()
    try:
        q = await m._subscribe()
        await asyncio.wait_for(q.get(), 1)
        first, second = await asyncio.gather(m.async_snapshot(), m.async_snapshot())
        assert first == second == b"\xff\xd8synthetic-jpeg\xff\xd9"
        assert FakeClient.runs == 1
        assert len([p for p in processes if p.snapshot]) == 1
        assert await m.async_snapshot() == first
        await m._unsubscribe(q)
    finally:
        await m.async_stop()
    assert FakeClient.active == 0
    assert m._last_image is None


@pytest.mark.asyncio
async def test_snapshot_caller_cancel_warms_cache(processes, monkeypatch):
    m = manager()
    await m.async_start()
    release = asyncio.Event()
    original = m._capture_snapshot

    async def delayed():
        await release.wait()
        return await original()

    monkeypatch.setattr(m, "_capture_snapshot", delayed)
    caller = asyncio.create_task(m.async_snapshot())
    await asyncio.sleep(0)
    caller.cancel()
    with pytest.raises(asyncio.CancelledError):
        await caller
    assert not m._snapshot_task.cancelled()
    release.set()
    try:
        assert await asyncio.wait_for(m._snapshot_task, 1)
        assert await m.async_snapshot() == m._last_image
    finally:
        await m.async_stop()


@pytest.mark.asyncio
async def test_unload_cancels_snapshot_without_deadlock(processes, monkeypatch):
    m = manager()
    await m.async_start()
    original = module.asyncio.create_subprocess_exec

    async def slow_spawn(*args, **kwargs):
        if "image2pipe" in args:
            await asyncio.Event().wait()
        return await original(*args, **kwargs)

    monkeypatch.setattr(module.asyncio, "create_subprocess_exec", slow_spawn)
    caller = asyncio.create_task(m.async_snapshot())
    await asyncio.sleep(0.02)
    await asyncio.wait_for(m.async_stop(), 1)
    with pytest.raises(asyncio.CancelledError):
        await caller
    assert FakeClient.active == 0


@pytest.mark.asyncio
async def test_startup_failure_closes_viewers_and_restarts(processes, monkeypatch):
    m = manager()
    await m.async_start()
    original = module.asyncio.create_subprocess_exec
    count = 0

    async def fail_once(*args, **kwargs):
        nonlocal count
        count += 1
        if count == 1:
            raise OSError("sensitive details that must never be logged")
        return await original(*args, **kwargs)

    monkeypatch.setattr(module.asyncio, "create_subprocess_exec", fail_once)
    try:
        q = await m._subscribe()
        assert await asyncio.wait_for(q.get(), 1) is module._EOF
        await m._unsubscribe(q)
        q = await m._subscribe()
        assert await asyncio.wait_for(q.get(), 1) == b"GTSvideo"
        assert m.diagnostics["producer_failures"] == 1
        await m._unsubscribe(q)
    finally:
        await m.async_stop()
