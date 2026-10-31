"""Offline integration lifecycle and export authorization tests."""

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from homeassistant.core import Context
from homeassistant.exceptions import Unauthorized
from homeassistant.setup import async_setup_component
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.ubox_relay import CONF_EXPORT_TOKEN
from custom_components.ubox_relay.const import DOMAIN
from custom_components.ubox_relay.diagnostics import async_get_config_entry_diagnostics

TOKEN = "synthetic-export-token"
DATA = {
    "name": "Garden",
    "uid": "synthetic-camera-1",
    "password": "synthetic-secret",
    CONF_EXPORT_TOKEN: TOKEN,
}


@pytest.fixture
async def loaded(hass, enable_custom_integrations, hass_client_no_auth):
    """Load real HA entry/platform/view; replace camera transport only."""
    manager = SimpleNamespace(
        async_start=AsyncMock(),
        async_stop=AsyncMock(),
        async_snapshot=AsyncMock(return_value=b"jpeg"),
        stream_url="http://127.0.0.1:12345/video.ts",
        diagnostics={"video_units": 7, "secret": TOKEN},
    )
    upstream = MagicMock()
    assert await async_setup_component(hass, "http", {"http": {}})
    entry = MockConfigEntry(
        domain=DOMAIN, title="Garden", data=DATA, unique_id="synthetic-hashed-id"
    )
    entry.add_to_hass(hass)
    with (
        patch("custom_components.ubox_relay.StreamManager", return_value=manager),
        patch(
            "custom_components.ubox_relay.get_ffmpeg_manager",
            return_value=SimpleNamespace(binary="ffmpeg"),
        ),
        patch(
            "custom_components.ubox_relay.async_get_clientsession",
            return_value=upstream,
        ),
    ):
        assert await hass.config_entries.async_setup(entry.entry_id)
        await hass.async_block_till_done()
        client = await hass_client_no_auth()
        yield entry, manager, upstream, client
        if entry.entry_id in hass.data.get(DOMAIN, {}).get("entries", {}):
            await hass.config_entries.async_unload(entry.entry_id)
            await hass.async_block_till_done()


async def test_entry_lifecycle_and_privacy(hass, loaded):
    entry, manager, _, _ = loaded
    manager.async_start.assert_awaited_once()
    state = hass.states.get("camera.garden")
    assert state is not None
    for secret in (TOKEN, DATA["uid"], DATA["password"]):
        assert secret not in str(state.as_dict())
    diagnostics = await async_get_config_entry_diagnostics(hass, entry)
    assert diagnostics["counters"] == {"video_units": 7}
    assert TOKEN not in str(diagnostics)
    task = asyncio.create_task(asyncio.Event().wait())
    entry.runtime_data.export_tasks.add(task)
    await asyncio.sleep(0)
    assert await hass.config_entries.async_unload(entry.entry_id)
    assert task.cancelled()
    manager.async_stop.assert_awaited_once()
    assert not hass.services.has_service(DOMAIN, "get_stream_url")
    assert not hass.services.has_service(DOMAIN, "rotate_stream_token")


@pytest.mark.parametrize("denied_service", ["get_stream_url", "rotate_stream_token"])
async def test_admin_url_and_nonadmin_rejected(
    hass, loaded, hass_admin_user, hass_read_only_user, denied_service
):
    entry, _, _, _ = loaded
    data = {"entry_id": entry.entry_id, "base_url": "https://ha.example"}
    result = await hass.services.async_call(
        DOMAIN,
        "get_stream_url",
        data,
        blocking=True,
        return_response=True,
        context=Context(user_id=hass_admin_user.id),
    )
    assert result == {
        "stream_url": f"https://ha.example/api/{DOMAIN}/{entry.entry_id}/stream.ts?token={TOKEN}",
        "format": "mpegts",
    }
    with pytest.raises(Unauthorized):
        await hass.services.async_call(
            DOMAIN,
            denied_service,
            data,
            blocking=True,
            return_response=True,
            context=Context(user_id=hass_read_only_user.id),
        )


@pytest.mark.parametrize("suffix", ["", "?token=wrong", "?token=" + "x" * 257])
async def test_export_denies_bad_token_before_fetch(loaded, suffix):
    entry, _, upstream, client = loaded
    response = await client.get(f"/api/{DOMAIN}/{entry.entry_id}/stream.ts{suffix}")
    assert response.status == 404
    upstream.get.assert_not_called()


async def test_export_unknown_entry_denied(loaded):
    _, _, upstream, client = loaded
    response = await client.get(f"/api/{DOMAIN}/missing/stream.ts?token={TOKEN}")
    assert response.status == 404
    upstream.get.assert_not_called()


async def test_export_correct_token_proxies_bytes(loaded):
    entry, _, upstream, client = loaded

    async def chunks(_size):
        yield b"synthetic-ts-one"
        yield b"synthetic-ts-two"

    content = SimpleNamespace(iter_chunked=chunks)
    context = MagicMock()
    context.__aenter__ = AsyncMock(
        return_value=SimpleNamespace(status=200, content=content)
    )
    context.__aexit__ = AsyncMock(return_value=False)
    upstream.get.return_value = context
    response = await client.get(
        f"/api/{DOMAIN}/{entry.entry_id}/stream.ts?token={TOKEN}"
    )
    assert response.status == 200
    assert await response.read() == b"synthetic-ts-onesynthetic-ts-two"
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Content-Type"] == "video/mp2t"
    assert not entry.runtime_data.export_tasks
    upstream.get.assert_called_once()


async def test_rotate_revokes_old_token_and_cancels_exports(
    hass, loaded, hass_admin_user
):
    entry, _, upstream, client = loaded
    task = asyncio.create_task(asyncio.Event().wait())
    entry.runtime_data.export_tasks.add(task)
    await asyncio.sleep(0)
    with (
        patch(
            "custom_components.ubox_relay.secrets.token_urlsafe",
            return_value="synthetic-replacement-token",
        ),
        patch(
            "homeassistant.config_entries.ConfigEntries.async_reload",
            new=AsyncMock(return_value=True),
        ),
    ):
        result = await hass.services.async_call(
            DOMAIN,
            "rotate_stream_token",
            {"entry_id": entry.entry_id, "base_url": "https://ha.example"},
            blocking=True,
            return_response=True,
            context=Context(user_id=hass_admin_user.id),
        )
        await hass.async_block_till_done()
    assert task.cancelled()
    assert entry.data[CONF_EXPORT_TOKEN] == "synthetic-replacement-token"
    assert result["stream_url"].endswith("?token=synthetic-replacement-token")
    response = await client.get(
        f"/api/{DOMAIN}/{entry.entry_id}/stream.ts?token={TOKEN}"
    )
    assert response.status == 404
    upstream.get.assert_not_called()
