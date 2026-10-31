"""UBox camera reception inside Home Assistant, without an external bridge."""

from __future__ import annotations

import asyncio
import secrets
from dataclasses import dataclass, field
from urllib.parse import urlsplit

import voluptuous as vol
from homeassistant.components.ffmpeg import get_ffmpeg_manager
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import (
    CONF_PASSWORD,
    EVENT_HOMEASSISTANT_STOP,
    Platform,
)
from homeassistant.core import HomeAssistant, ServiceCall, SupportsResponse
from homeassistant.exceptions import ConfigEntryNotReady, ServiceValidationError
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.network import get_url
from homeassistant.helpers.selector import (
    ConfigEntrySelector,
    ConfigEntrySelectorConfig,
)
from homeassistant.helpers.service import async_register_admin_service

from .const import CONF_RELAY_HOST, CONF_UID, DOMAIN
from .http import UBoxStreamView
from .protocol import Credentials, ProtocolError
from .stream import StreamManager

CONF_EXPORT_TOKEN = "export_token"
PLATFORMS = [Platform.CAMERA]


@dataclass
class RuntimeData:
    """Entry-owned resources; no credentials in repr or exported diagnostics."""

    manager: StreamManager = field(repr=False)
    export_tasks: set[asyncio.Task] = field(default_factory=set, repr=False)


type UBoxConfigEntry = ConfigEntry[RuntimeData]


def _shared(hass: HomeAssistant) -> dict:
    return hass.data.setdefault(
        DOMAIN, {"entries": {}, "view": False, "services": False}
    )


def _base_url(hass: HomeAssistant, supplied: str | None) -> str:
    base = supplied or get_url(hass, allow_external=False)
    parsed = urlsplit(base)
    try:
        port = parsed.port
    except ValueError:
        raise ServiceValidationError("Use a valid Home Assistant base URL") from None
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
        or port == 0
    ):
        raise ServiceValidationError("Use only the Home Assistant base URL")
    return base.rstrip("/")


def _export_url(hass: HomeAssistant, entry: ConfigEntry, base: str | None) -> str:
    return (
        f"{_base_url(hass, base)}/api/{DOMAIN}/{entry.entry_id}/stream.ts"
        f"?token={entry.data[CONF_EXPORT_TOKEN]}"
    )


async def _close_exports(runtime: RuntimeData) -> None:
    tasks = list(runtime.export_tasks)
    for task in tasks:
        task.cancel()
    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)


def _register_services(hass: HomeAssistant, shared: dict) -> None:
    if shared["services"]:
        return

    schema = vol.Schema(
        {
            vol.Required("entry_id"): ConfigEntrySelector(
                ConfigEntrySelectorConfig(integration=DOMAIN)
            ),
            vol.Optional("base_url"): cv.string,
        }
    )

    async def stream_url(call: ServiceCall) -> dict:
        entry = _shared(hass)["entries"].get(call.data["entry_id"])
        if entry is None:
            raise ServiceValidationError("Choose a loaded UBox camera")
        # Validate before rotating so malformed input cannot revoke a valid URL.
        base = _base_url(hass, call.data.get("base_url"))
        if call.service == "rotate_stream_token":
            await _close_exports(entry.runtime_data)
            hass.config_entries.async_update_entry(
                entry, data={**entry.data, CONF_EXPORT_TOKEN: secrets.token_urlsafe(32)}
            )
        return {
            "stream_url": _export_url(hass, entry, base),
            "format": "mpegts",
        }

    for service in ("get_stream_url", "rotate_stream_token"):
        async_register_admin_service(
            hass, DOMAIN, service, stream_url, schema, SupportsResponse.ONLY
        )
    shared["services"] = True


def _remove_services_if_unused(hass: HomeAssistant) -> None:
    shared = _shared(hass)
    if not shared["entries"] and shared["services"]:
        for name in ("get_stream_url", "rotate_stream_token"):
            hass.services.async_remove(DOMAIN, name)
        shared["services"] = False


async def async_setup_entry(hass: HomeAssistant, entry: UBoxConfigEntry) -> bool:
    """Set up only loopback transport; the camera wakes on a stream request."""
    settings = entry.data | entry.options
    try:
        credentials = Credentials(settings[CONF_UID], settings[CONF_PASSWORD])
        manager = StreamManager(
            credentials,
            get_ffmpeg_manager(hass).binary,
            settings.get(CONF_RELAY_HOST) or None,
        )
        await manager.async_start()
    except (OSError, ValueError, ProtocolError) as err:
        raise ConfigEntryNotReady("Camera transport could not start") from err

    if not entry.data.get(CONF_EXPORT_TOKEN):
        hass.config_entries.async_update_entry(
            entry, data={**entry.data, CONF_EXPORT_TOKEN: secrets.token_urlsafe(32)}
        )
    entry.runtime_data = RuntimeData(manager)
    shared = _shared(hass)
    shared["entries"][entry.entry_id] = entry
    if not shared["view"]:
        hass.http.register_view(UBoxStreamView(hass, async_get_clientsession(hass)))
        shared["view"] = True
    _register_services(hass, shared)

    async def stop(_event) -> None:
        await _close_exports(entry.runtime_data)
        await manager.async_stop()

    entry.async_on_unload(hass.bus.async_listen_once(EVENT_HOMEASSISTANT_STOP, stop))
    entry.async_on_unload(entry.add_update_listener(_async_options_updated))
    try:
        await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    except BaseException:
        shared["entries"].pop(entry.entry_id, None)
        await manager.async_stop()
        _remove_services_if_unused(hass)
        raise
    return True


async def _async_options_updated(hass: HomeAssistant, entry: UBoxConfigEntry) -> None:
    await hass.config_entries.async_reload(entry.entry_id)


async def async_unload_entry(hass: HomeAssistant, entry: UBoxConfigEntry) -> bool:
    if not await hass.config_entries.async_unload_platforms(entry, PLATFORMS):
        return False
    _shared(hass)["entries"].pop(entry.entry_id, None)
    await _close_exports(entry.runtime_data)
    await entry.runtime_data.manager.async_stop()
    _remove_services_if_unused(hass)
    return True
