"""Home Assistant camera backed by the integration's own receiver."""

from __future__ import annotations

import hashlib

from homeassistant.components.camera import Camera, CameraEntityFeature
from homeassistant.const import CONF_NAME
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

from . import UBoxConfigEntry
from .const import CONF_UID, DEFAULT_NAME, DOMAIN


async def async_setup_entry(
    hass: HomeAssistant,
    entry: UBoxConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    async_add_entities([UBoxCamera(entry)])


class UBoxCamera(Camera):
    """One camera; it consumes no battery/data while no client is viewing."""

    _attr_has_entity_name = True
    _attr_name = None
    _attr_should_poll = False
    _attr_supported_features = CameraEntityFeature.STREAM

    def __init__(self, entry: UBoxConfigEntry) -> None:
        super().__init__()
        self._manager = entry.runtime_data.manager
        settings = entry.data | entry.options
        identity = (
            entry.unique_id
            or hashlib.sha256(settings[CONF_UID].encode("ascii")).hexdigest()
        )
        self._attr_unique_id = f"{identity}_camera"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, identity)},
            manufacturer="UBox / Ubia",
            name=settings.get(CONF_NAME, DEFAULT_NAME),
        )

    @property
    def available(self) -> bool:
        return self._manager.stream_url is not None

    @property
    def use_stream_for_stills(self) -> bool:
        return False

    async def stream_source(self) -> str | None:
        return self._manager.stream_url

    async def async_camera_image(
        self, width: int | None = None, height: int | None = None
    ) -> bytes | None:
        return await self._manager.async_snapshot()
