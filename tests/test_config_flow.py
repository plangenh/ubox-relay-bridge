"""Exercise real HA flows without connecting to or waking a camera."""

from unittest.mock import AsyncMock, patch

import pytest
import voluptuous as vol
from homeassistant import data_entry_flow
from homeassistant.const import CONF_NAME, CONF_PASSWORD
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.ubox_relay.config_flow import valid_credential, valid_relay_host
from custom_components.ubox_relay.const import CONF_RELAY_HOST, CONF_UID, DOMAIN

DATA = {
    CONF_NAME: "Garden",
    CONF_UID: "synthetic-camera-1",
    CONF_PASSWORD: "synthetic-secret",
}


@pytest.fixture(autouse=True)
def enable_integration(enable_custom_integrations):
    """Allow discovery of the local custom integration."""


@pytest.mark.parametrize("value", ["camera", "A" * 20])
def test_credential_valid(value):
    assert valid_credential(value)


@pytest.mark.parametrize("value", ["", "A" * 21, "cäméra", "abc\n", None])
def test_credential_invalid(value):
    assert not valid_credential(value)


@pytest.mark.parametrize(
    "value",
    [
        "relay.example",
        "relay.example:20001",
        "192.0.2.1",
        "192.0.2.1:65535",
    ],
)
def test_relay_valid(value):
    assert valid_relay_host(value)


@pytest.mark.parametrize(
    "value",
    [
        "",
        "https://relay.example",
        "relay:0",
        "relay:65536",
        "relay:",
        "relay:abc",
        "relay:１２",
        "[invalid]:20001",
        "[2001:db8::1]:20001",
        "2001:db8::1",
        "192.0.2.999",
        " relay.example",
        "relay/path",
        "relay:999999999999999",
    ],
)
def test_relay_invalid(value):
    assert not valid_relay_host(value)


@pytest.mark.asyncio
async def test_user_flow_local_only(hass):
    with (
        patch(
            "homeassistant.config_entries.ConfigEntries.async_setup",
            new=AsyncMock(return_value=True),
        ),
        patch(
            "custom_components.ubox_relay.protocol.RelayClient",
            side_effect=AssertionError(
                "A config flow must never open a camera connection"
            ),
        ),
    ):
        result = await hass.config_entries.flow.async_init(
            DOMAIN, context={"source": "user"}
        )
        assert result["type"] is data_entry_flow.FlowResultType.MENU
        result = await hass.config_entries.flow.async_configure(
            result["flow_id"], {"next_step_id": "manual"}
        )
        result = await hass.config_entries.flow.async_configure(result["flow_id"], DATA)
        await hass.async_block_till_done()
    assert result["type"] is data_entry_flow.FlowResultType.CREATE_ENTRY
    assert result["title"] == "Garden"
    assert result["data"] == DATA
    assert result["result"].unique_id != DATA[CONF_UID]
    assert len(result["result"].unique_id) == 64


@pytest.mark.asyncio
async def test_duplicate_camera(hass):
    import hashlib

    entry = MockConfigEntry(
        domain=DOMAIN,
        data=DATA,
        unique_id=hashlib.sha256(DATA[CONF_UID].encode()).hexdigest(),
    )
    entry.add_to_hass(hass)
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": "user"}
    )
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {"next_step_id": "manual"}
    )
    result = await hass.config_entries.flow.async_configure(result["flow_id"], DATA)
    assert result["type"] is data_entry_flow.FlowResultType.ABORT
    assert result["reason"] == "already_configured"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("field", "value", "error"),
    [
        (CONF_UID, "☃", "invalid_uid"),
        (CONF_UID, " ", "invalid_uid"),
        (CONF_UID, " padded ", "invalid_uid"),
        (CONF_PASSWORD, "", "invalid_password"),
        (CONF_NAME, " ", "invalid_name"),
        (CONF_RELAY_HOST, "https://invalid", "invalid_relay_host"),
    ],
)
async def test_invalid_input(hass, field, value, error):
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": "user"}
    )
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {"next_step_id": "manual"}
    )
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], DATA | {field: value}
    )
    assert result["type"] is data_entry_flow.FlowResultType.FORM
    assert result["errors"][field] == error
    assert DATA[CONF_PASSWORD] not in str(result["data_schema"])


@pytest.mark.asyncio
async def test_options_preserve_password_and_clear_relay(hass):
    entry = MockConfigEntry(
        domain=DOMAIN,
        data=DATA | {CONF_RELAY_HOST: "relay.example"},
        options={CONF_PASSWORD: "newer-secret"},
    )
    entry.add_to_hass(hass)
    result = await hass.config_entries.options.async_init(entry.entry_id)
    schema = result["data_schema"]
    defaults = {
        key.schema: key.default()
        for key in schema.schema
        if callable(key.default) and key.default is not vol.UNDEFINED
    }
    assert CONF_PASSWORD not in defaults
    assert CONF_UID not in [key.schema for key in schema.schema]
    result = await hass.config_entries.options.async_configure(
        result["flow_id"],
        {CONF_NAME: "Updated", CONF_PASSWORD: "", CONF_RELAY_HOST: ""},
    )
    assert result["type"] is data_entry_flow.FlowResultType.CREATE_ENTRY
    assert result["data"] == {
        CONF_NAME: "Updated",
        CONF_PASSWORD: "newer-secret",
        CONF_RELAY_HOST: "",
    }


@pytest.mark.asyncio
async def test_options_update_password(hass):
    entry = MockConfigEntry(domain=DOMAIN, data=DATA)
    entry.add_to_hass(hass)
    result = await hass.config_entries.options.async_init(entry.entry_id)
    result = await hass.config_entries.options.async_configure(
        result["flow_id"],
        {
            CONF_NAME: "Updated",
            CONF_PASSWORD: "replacement",
            CONF_RELAY_HOST: "relay.example:20001",
        },
    )
    assert result["data"][CONF_PASSWORD] == "replacement"


@pytest.mark.asyncio
async def test_account_discovery_selection_keeps_only_device_credentials(hass):
    from custom_components.ubox_relay import cloud

    devices = [
        cloud.CloudDevice(
            uid="synthetic-camera-1", password="device-secret-one", name="Garden"
        ),
        cloud.CloudDevice(
            uid="synthetic-camera-2", password="device-secret-two", name="Driveway"
        ),
    ]
    with (
        patch(
            "custom_components.ubox_relay.config_flow.cloud.async_discover_devices",
            new=AsyncMock(return_value=devices),
        ) as discover,
        patch(
            "homeassistant.config_entries.ConfigEntries.async_setup",
            new=AsyncMock(return_value=True),
        ),
        patch(
            "custom_components.ubox_relay.protocol.RelayClient",
            side_effect=AssertionError("Discovery must never wake a camera"),
        ),
    ):
        result = await hass.config_entries.flow.async_init(
            DOMAIN, context={"source": "user"}
        )
        assert result["menu_options"] == ["account", "manual"]
        result = await hass.config_entries.flow.async_configure(
            result["flow_id"], {"next_step_id": "account"}
        )
        result = await hass.config_entries.flow.async_configure(
            result["flow_id"],
            {"email": "owner@example.test", CONF_PASSWORD: "account-secret"},
        )
        assert result["step_id"] == "camera"
        assert "device-secret" not in str(result["data_schema"])
        assert "synthetic-camera" not in str(result["data_schema"])
        flow = hass.config_entries.flow.async_get(result["flow_id"])
        assert "account-secret" not in repr(flow)
        result = await hass.config_entries.flow.async_configure(
            result["flow_id"],
            {"device": "1", CONF_NAME: "", CONF_RELAY_HOST: "relay.example:20001"},
        )
        await hass.async_block_till_done()
    assert result["type"] is data_entry_flow.FlowResultType.CREATE_ENTRY
    assert result["data"] == {
        CONF_NAME: "Driveway",
        CONF_UID: "synthetic-camera-2",
        CONF_PASSWORD: "device-secret-two",
        CONF_RELAY_HOST: "relay.example:20001",
    }
    assert "owner@example.test" not in repr(result)
    assert "account-secret" not in repr(result)
    assert discover.await_args.args[1:] == ("owner@example.test", "account-secret")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("exception_name", "error"),
    [
        ("CloudAuthError", "invalid_auth"),
        ("CloudConnectionError", "cannot_connect"),
        ("CloudResponseError", "invalid_response"),
        ("CloudChallengeRequired", "challenge_required"),
    ],
)
async def test_account_error_is_sanitized(hass, exception_name, error):
    from custom_components.ubox_relay import cloud

    with patch(
        "custom_components.ubox_relay.config_flow.cloud.async_discover_devices",
        new=AsyncMock(side_effect=getattr(cloud, exception_name)()),
    ):
        result = await hass.config_entries.flow.async_init(
            DOMAIN, context={"source": "user"}
        )
        result = await hass.config_entries.flow.async_configure(
            result["flow_id"], {"next_step_id": "account"}
        )
        result = await hass.config_entries.flow.async_configure(
            result["flow_id"],
            {"email": "owner@example.test", CONF_PASSWORD: "account-secret"},
        )
    assert result["errors"] == {"base": error}
    assert "account-secret" not in str(result["data_schema"])
    defaults = {
        key.schema: key.default()
        for key in result["data_schema"].schema
        if callable(key.default) and key.default is not vol.UNDEFINED
    }
    assert CONF_PASSWORD not in defaults


@pytest.mark.asyncio
async def test_account_empty_discovery(hass):
    with patch(
        "custom_components.ubox_relay.config_flow.cloud.async_discover_devices",
        new=AsyncMock(return_value=[]),
    ):
        result = await hass.config_entries.flow.async_init(
            DOMAIN, context={"source": "user"}
        )
        result = await hass.config_entries.flow.async_configure(
            result["flow_id"], {"next_step_id": "account"}
        )
        result = await hass.config_entries.flow.async_configure(
            result["flow_id"],
            {"email": "owner@example.test", CONF_PASSWORD: "account-secret"},
        )
    assert result["type"] is data_entry_flow.FlowResultType.ABORT
    assert result["reason"] == "no_devices"


@pytest.mark.asyncio
async def test_discovered_camera_duplicate_and_relay_validation(hass):
    import hashlib

    from custom_components.ubox_relay import cloud

    entry = MockConfigEntry(
        domain=DOMAIN,
        data=DATA,
        unique_id=hashlib.sha256(DATA[CONF_UID].encode()).hexdigest(),
    )
    entry.add_to_hass(hass)
    with patch(
        "custom_components.ubox_relay.config_flow.cloud.async_discover_devices",
        new=AsyncMock(
            return_value=[
                cloud.CloudDevice(
                    uid=DATA[CONF_UID], password=DATA[CONF_PASSWORD], name="Garden"
                )
            ]
        ),
    ):
        result = await hass.config_entries.flow.async_init(
            DOMAIN, context={"source": "user"}
        )
        result = await hass.config_entries.flow.async_configure(
            result["flow_id"], {"next_step_id": "account"}
        )
        result = await hass.config_entries.flow.async_configure(
            result["flow_id"],
            {"email": "owner@example.test", CONF_PASSWORD: "account-secret"},
        )
        result = await hass.config_entries.flow.async_configure(
            result["flow_id"], {"device": "0", CONF_RELAY_HOST: "https://bad"}
        )
        assert result["errors"] == {CONF_RELAY_HOST: "invalid_relay_host"}
        result = await hass.config_entries.flow.async_configure(
            result["flow_id"], {"device": "0", CONF_NAME: "Garden", CONF_RELAY_HOST: ""}
        )
    assert result["type"] is data_entry_flow.FlowResultType.ABORT
    assert result["reason"] == "already_configured"


@pytest.mark.asyncio
async def test_empty_account_input_does_not_call_cloud(hass):
    with patch(
        "custom_components.ubox_relay.config_flow.cloud.async_discover_devices",
        new=AsyncMock(),
    ) as discover:
        result = await hass.config_entries.flow.async_init(
            DOMAIN, context={"source": "user"}
        )
        result = await hass.config_entries.flow.async_configure(
            result["flow_id"], {"next_step_id": "account"}
        )
        result = await hass.config_entries.flow.async_configure(
            result["flow_id"], {"email": " ", CONF_PASSWORD: ""}
        )
    assert result["errors"] == {"base": "invalid_auth"}
    discover.assert_not_awaited()
