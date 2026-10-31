"""Configure UBox cameras manually or through temporary account discovery."""

from __future__ import annotations

import hashlib
import ipaddress
import re
from typing import Any

import voluptuous as vol
from homeassistant import config_entries
from homeassistant.const import CONF_NAME, CONF_PASSWORD
from homeassistant.core import callback
from homeassistant.helpers import selector
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from . import cloud
from .const import CONF_RELAY_HOST, CONF_UID, DEFAULT_NAME, DOMAIN


def valid_credential(value: Any) -> bool:
    """Wire credentials occupy fixed ASCII fields of at most twenty bytes."""
    return (
        isinstance(value, str)
        and 1 <= len(value) <= 20
        and value.isascii()
        and all(32 <= ord(c) < 127 for c in value)
    )


def valid_relay_host(value: Any) -> bool:
    """Accept a host or host:port, using DNS or IPv4 addresses."""
    if not isinstance(value, str) or not value or value != value.strip():
        return False
    host = value
    port = None
    if "[" in value or "]" in value or value.count(":") > 1:
        return False
    if ":" in value:
        host, port = value.rsplit(":", 1)
    if port is not None and (
        len(port) > 5
        or not port.isascii()
        or not port.isdecimal()
        or not 1 <= int(port) <= 65535
    ):
        return False
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if len(host) > 253 or not host or re.fullmatch(r"[0-9.]+", host):
            return False
        if not all(
            re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
            for label in host.rstrip(".").split(".")
        ):
            return False
    return True


def _errors(data: dict[str, Any], *, options: bool = False) -> dict[str, str]:
    errors = {}
    if not isinstance(data.get(CONF_NAME), str) or not data[CONF_NAME].strip():
        errors[CONF_NAME] = "invalid_name"
    if not options and (
        not valid_credential(data.get(CONF_UID))
        or data[CONF_UID] != data[CONF_UID].strip()
    ):
        errors[CONF_UID] = "invalid_uid"
    password = data.get(CONF_PASSWORD, "")
    if (not options or password != "") and not valid_credential(password):
        errors[CONF_PASSWORD] = "invalid_password"
    relay = data.get(CONF_RELAY_HOST, "")
    if relay and not valid_relay_host(relay):
        errors[CONF_RELAY_HOST] = "invalid_relay_host"
    return errors


def _schema(data: dict[str, Any], *, options: bool = False) -> vol.Schema:
    fields = {vol.Required(CONF_NAME, default=data.get(CONF_NAME, DEFAULT_NAME)): str}
    if not options:
        fields[vol.Required(CONF_UID, default=data.get(CONF_UID, ""))] = str
    password_key = (
        vol.Optional(CONF_PASSWORD) if options else vol.Required(CONF_PASSWORD)
    )
    fields[password_key] = selector.TextSelector(
        selector.TextSelectorConfig(type=selector.TextSelectorType.PASSWORD)
    )
    fields[vol.Optional(CONF_RELAY_HOST, default=data.get(CONF_RELAY_HOST, ""))] = str
    return vol.Schema(fields)


class UBoxConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Discover a camera or enter its device credentials manually."""

    VERSION = 1

    def __init__(self) -> None:
        self._devices: dict[str, cloud.CloudDevice] = {}

    async def async_step_user(self, user_input: dict[str, Any] | None = None):
        return self.async_show_menu(step_id="user", menu_options=["account", "manual"])

    async def _create_camera(self, data: dict[str, Any]):
        await self.async_set_unique_id(
            hashlib.sha256(data[CONF_UID].encode("ascii")).hexdigest()
        )
        self._abort_if_unique_id_configured()
        data = dict(data)
        data[CONF_NAME] = data[CONF_NAME].strip()
        if not data.get(CONF_RELAY_HOST):
            data.pop(CONF_RELAY_HOST, None)
        self._devices.clear()
        return self.async_create_entry(title=data[CONF_NAME], data=data)

    async def async_step_manual(self, user_input: dict[str, Any] | None = None):
        errors = {}
        if user_input is not None:
            errors = _errors(user_input)
            if not errors:
                return await self._create_camera(user_input)
        return self.async_show_form(
            step_id="manual", data_schema=_schema(user_input or {}), errors=errors
        )

    async def async_step_account(self, user_input: dict[str, Any] | None = None):
        errors = {}
        if user_input is not None:
            if not user_input.get("email", "").strip() or not user_input.get(
                CONF_PASSWORD
            ):
                errors["base"] = "invalid_auth"
            else:
                try:
                    devices = await cloud.async_discover_devices(
                        async_get_clientsession(self.hass),
                        user_input["email"].strip(),
                        user_input[CONF_PASSWORD],
                    )
                except cloud.CloudChallengeRequired:
                    errors["base"] = "challenge_required"
                except cloud.CloudAuthError:
                    errors["base"] = "invalid_auth"
                except cloud.CloudConnectionError:
                    errors["base"] = "cannot_connect"
                except cloud.CloudResponseError:
                    errors["base"] = "invalid_response"
                else:
                    self._devices = {str(i): device for i, device in enumerate(devices)}
                    if not self._devices:
                        return self.async_abort(reason="no_devices")
                    return await self.async_step_camera()
        return self.async_show_form(
            step_id="account",
            data_schema=vol.Schema(
                {
                    vol.Required(
                        "email", default=(user_input or {}).get("email", "")
                    ): str,
                    vol.Required(CONF_PASSWORD): selector.TextSelector(
                        selector.TextSelectorConfig(
                            type=selector.TextSelectorType.PASSWORD
                        )
                    ),
                }
            ),
            errors=errors,
        )

    async def async_step_camera(self, user_input: dict[str, Any] | None = None):
        if not self._devices:
            return self.async_abort(reason="no_devices")
        errors = {}
        if user_input is not None:
            device = self._devices.get(user_input.get("device"))
            if device is None:
                errors["device"] = "invalid_device"
            else:
                data = {
                    CONF_UID: device.uid,
                    CONF_PASSWORD: device.password,
                    CONF_NAME: user_input.get(CONF_NAME, "").strip()
                    or device.name
                    or DEFAULT_NAME,
                    CONF_RELAY_HOST: user_input.get(CONF_RELAY_HOST, ""),
                }
                errors = _errors(data)
                if CONF_UID in errors or CONF_PASSWORD in errors:
                    errors = {"base": "invalid_response"}
                if not errors:
                    return await self._create_camera(data)
        labels = {
            key: device.name.strip() or f"{DEFAULT_NAME} {int(key) + 1}"
            for key, device in self._devices.items()
        }
        return self.async_show_form(
            step_id="camera",
            data_schema=vol.Schema(
                {
                    vol.Required(
                        "device",
                        default=(user_input or {}).get("device", next(iter(labels))),
                    ): selector.SelectSelector(
                        selector.SelectSelectorConfig(
                            options=[
                                selector.SelectOptionDict(value=key, label=label)
                                for key, label in labels.items()
                            ],
                            mode=selector.SelectSelectorMode.DROPDOWN,
                        )
                    ),
                    vol.Optional(
                        CONF_NAME, default=(user_input or {}).get(CONF_NAME, "")
                    ): str,
                    vol.Optional(
                        CONF_RELAY_HOST,
                        default=(user_input or {}).get(CONF_RELAY_HOST, ""),
                    ): str,
                }
            ),
            errors=errors,
        )

    @staticmethod
    @callback
    def async_get_options_flow(config_entry):
        return UBoxOptionsFlow()


class UBoxOptionsFlow(config_entries.OptionsFlow):
    """Change settings without revealing the saved device password."""

    async def async_step_init(self, user_input: dict[str, Any] | None = None):
        current = self.config_entry.data | self.config_entry.options
        errors = {}
        if user_input is not None:
            errors = _errors(user_input, options=True)
            if not errors:
                data = {
                    CONF_NAME: user_input[CONF_NAME].strip(),
                    CONF_RELAY_HOST: user_input.get(CONF_RELAY_HOST, ""),
                }
                data[CONF_PASSWORD] = (
                    user_input.get(CONF_PASSWORD) or current[CONF_PASSWORD]
                )
                return self.async_create_entry(title="", data=data)
        visible = {
            CONF_NAME: current.get(CONF_NAME, DEFAULT_NAME),
            CONF_RELAY_HOST: current.get(CONF_RELAY_HOST, ""),
        }
        if user_input is not None:
            visible.update({k: v for k, v in user_input.items() if k != CONF_PASSWORD})
        return self.async_show_form(
            step_id="init", data_schema=_schema(visible, options=True), errors=errors
        )
