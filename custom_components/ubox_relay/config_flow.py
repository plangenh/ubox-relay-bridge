"""Local configuration for UBox cameras, without waking the camera."""

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
    """Set up a camera using locally entered device credentials."""

    VERSION = 1

    async def async_step_user(self, user_input: dict[str, Any] | None = None):
        errors = {}
        if user_input is not None:
            errors = _errors(user_input)
            if not errors:
                await self.async_set_unique_id(
                    hashlib.sha256(user_input[CONF_UID].encode("ascii")).hexdigest()
                )
                self._abort_if_unique_id_configured()
                data = dict(user_input)
                data[CONF_NAME] = data[CONF_NAME].strip()
                if not data.get(CONF_RELAY_HOST):
                    data.pop(CONF_RELAY_HOST, None)
                return self.async_create_entry(title=data[CONF_NAME], data=data)
        return self.async_show_form(
            step_id="user", data_schema=_schema(user_input or {}), errors=errors
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
