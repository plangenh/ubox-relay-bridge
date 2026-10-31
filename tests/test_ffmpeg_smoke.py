"""Optional real FFmpeg tests using generated video only, never a camera."""

import asyncio
import importlib.util
import os
from io import BytesIO
from pathlib import Path

import aiohttp
import pytest
from PIL import Image, ImageStat

spec = importlib.util.spec_from_file_location(
    "ubox_stream_smoke",
    Path(__file__).parents[1] / "custom_components/ubox_relay/stream.py",
)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
FFMPEG = os.environ.get("UBOX_TEST_FFMPEG")
pytestmark = [
    pytest.mark.usefixtures("socket_enabled"),
    pytest.mark.skipif(
        not FFMPEG, reason="Set UBOX_TEST_FFMPEG for real synthetic smoke"
    ),
]


async def synthetic_hevc():
    process = await asyncio.create_subprocess_exec(
        FFMPEG,
        "-hide_banner",
        "-loglevel",
        "error",
        "-f",
        "lavfi",
        "-i",
        "testsrc2=size=64x48:rate=10",
        "-frames:v",
        "20",
        "-an",
        "-c:v",
        "libx265",
        "-threads",
        "1",
        "-x265-params",
        "pools=1:frame-threads=1:wpp=0:log-level=error:repeat-headers=1:keyint=10",
        "-f",
        "hevc",
        "pipe:1",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        video, _ = await asyncio.wait_for(process.communicate(), 10)
        assert process.returncode == 0
        assert video
        return video
    finally:
        if process.returncode is None:
            process.kill()
            await process.wait()


@pytest.mark.asyncio
async def test_real_hevc_to_shared_ts_and_jpeg():
    video = await synthetic_hevc()

    class SyntheticRelay:
        runs = 0
        active = 0

        def __init__(self, credentials, **kwargs):
            pass

        async def run(self, on_video, stop):
            type(self).runs += 1
            type(self).active += 1
            try:
                while not stop.is_set():
                    await on_video(video)
                    await asyncio.sleep(0.05)
                return {}
            finally:
                type(self).active -= 1

    manager = module.StreamManager(object(), FFMPEG, client_factory=SyntheticRelay)
    await manager.async_start()
    producer = None
    try:
        async with aiohttp.ClientSession() as session:
            response = await session.get(manager.stream_url)
            image_job = asyncio.create_task(manager.async_snapshot())
            transport = await asyncio.wait_for(
                response.content.readexactly(188 * 30), 15
            )
            assert all(
                transport[offset] == 0x47 for offset in range(0, len(transport), 188)
            )
            image = await asyncio.wait_for(image_job, 20)
            assert image is not None and image.startswith(b"\xff\xd8")
            with Image.open(BytesIO(image)) as decoded:
                assert decoded.size == (64, 48)
                assert max(ImageStat.Stat(decoded.convert("RGB")).stddev) > 10
            assert SyntheticRelay.runs == 1
            assert SyntheticRelay.active == 1
            producer = manager._worker
            response.close()
    finally:
        await asyncio.wait_for(manager.async_stop(), 8)
    assert producer is not None and producer.done()
    assert SyntheticRelay.active == 0
    assert manager.stream_url is None


@pytest.mark.asyncio
async def test_real_full_stdout_pipe_shutdown():
    # Deliberately leave stdout/stderr unread until StreamManager termination.
    # Raw high-rate video fills asyncio's reader buffer and pauses the pipe.
    process = await asyncio.create_subprocess_exec(
        FFMPEG,
        "-hide_banner",
        "-loglevel",
        "error",
        "-f",
        "lavfi",
        "-i",
        "testsrc2=size=256x256:rate=120",
        "-threads",
        "1",
        "-f",
        "rawvideo",
        "-pix_fmt",
        "yuv420p",
        "pipe:1",
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        await asyncio.sleep(0.2)
        assert process.returncode is None
        await asyncio.wait_for(module.StreamManager._terminate(process), 6)
        assert process.returncode is not None
    finally:
        if process.returncode is None:
            process.kill()
            await process.communicate()
