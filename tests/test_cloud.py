"""Synthetic account API responses; never contact the vendor or a camera."""

import asyncio
import json
from unittest.mock import MagicMock

import aiohttp
import pytest

from custom_components.ubox_relay import cloud


class Response:
    def __init__(self, body, status=200):
        self.body = json.dumps(body).encode() if not isinstance(body, bytes) else body
        self.status = status
        self.content = self

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        return False

    async def iter_chunked(self, _):
        for i in range(0, len(self.body), 7):
            yield self.body[i : i + 7]


def session_for(*responses):
    return MagicMock(post=MagicMock(side_effect=responses))


def success(data):
    return Response({"code": 0, "data": data})


def login(**extra):
    return success(
        {"Token": "synthetic-session-token", "uuid": "synthetic-user-id", **extra}
    )


async def test_discovery_request_contract_and_secret_boundaries():
    session = session_for(
        login(),
        success(
            {
                "infos": [
                    {
                        "device_uid": "camera-one",
                        "device_pwd": "device-secret",
                        "device_name": "Garden",
                    }
                ]
            }
        ),
    )
    devices = await cloud.async_discover_devices(
        session, " account@example.invalid ", "account-secret"
    )
    assert len(devices) == 1
    assert devices[0].uid == "camera-one"
    assert devices[0].password == "device-secret"
    assert devices[0].name == "Garden"
    for value in ("camera-one", "device-secret", "Garden"):
        assert value not in repr(devices[0])
    first, second = session.post.call_args_list
    assert first.args[0] == "https://portal-uni.ubianet.com/api/pub/account/login/v3"
    assert first.kwargs["json"]["account"] == "account@example.invalid"
    # Independent OpenSSL HMAC-SHA1 vector with the native Base64 substitution.
    assert first.kwargs["json"]["password"] == "SAmU5Q1Vl07eIHlw1teG3YQcWgc,"
    assert first.kwargs["json"]["device_type"] == 2
    assert "X-Ubia-Auth-UserToken" not in first.kwargs["headers"]
    assert (
        second.args[0] == "https://portal-uni.ubianet.com/api/user/qry/device/list/v2"
    )
    assert (
        second.kwargs["headers"]["X-Ubia-Auth-UserToken"] == "synthetic-session-token"
    )
    assert "uid=synthetic-user-id" in second.kwargs["headers"]["X-UbiaAPI-CallContext"]
    assert second.kwargs["json"] == {}
    assert "account-secret" not in str(session.post.call_args_list)
    for call in (first, second):
        assert call.kwargs["allow_redirects"] is False
        assert call.kwargs["timeout"].total == 25


@pytest.mark.parametrize(
    "body,error",
    [
        (
            {"code": 20005, "data": {}, "msg": "private server content"},
            cloud.CloudAuthError,
        ),
        ({"code": 10004, "data": ""}, cloud.CloudAuthError),
        ({"code": 99999, "data": {}}, cloud.CloudResponseError),
        ({"code": False, "data": {}}, cloud.CloudResponseError),
        ({"code": "0", "data": {}}, cloud.CloudResponseError),
        ({"code": 0, "data": []}, cloud.CloudResponseError),
        ([], cloud.CloudResponseError),
        (b"not-json", cloud.CloudResponseError),
    ],
)
async def test_response_errors_are_sanitized(body, error):
    session = session_for(Response(body))
    with pytest.raises(error) as exc:
        await cloud.async_discover_devices(session, "account@example.invalid", "secret")
    assert str(exc.value) == ""
    assert session.post.call_count == 1


@pytest.mark.parametrize(
    "status,error",
    [
        (401, cloud.CloudAuthError),
        (403, cloud.CloudAuthError),
        (429, cloud.CloudConnectionError),
        (503, cloud.CloudConnectionError),
        (302, cloud.CloudResponseError),
        (400, cloud.CloudResponseError),
    ],
)
async def test_http_failure_and_redirect_policy(status, error):
    with pytest.raises(error):
        await cloud.async_discover_devices(
            session_for(Response({}, status)), "account@example.invalid", "secret"
        )


@pytest.mark.parametrize(
    "exception",
    [
        aiohttp.ClientConnectionError("private"),
        TimeoutError("private"),
        OSError("private"),
    ],
)
async def test_network_errors_hide_request_details(exception):
    with pytest.raises(cloud.CloudConnectionError) as exc:
        await cloud.async_discover_devices(
            session_for(exception), "account@example.invalid", "secret"
        )
    assert str(exc.value) == ""


async def test_cancellation_propagates():
    with pytest.raises(asyncio.CancelledError):
        await cloud.async_discover_devices(
            session_for(asyncio.CancelledError()), "account@example.invalid", "secret"
        )


async def test_body_bound_applies_across_short_chunks(monkeypatch):
    monkeypatch.setattr(cloud, "_MAX_RESPONSE", 30)
    with pytest.raises(cloud.CloudResponseError):
        await cloud.async_discover_devices(
            session_for(Response(b"x" * 31)), "account@example.invalid", "secret"
        )


@pytest.mark.parametrize(
    "data",
    [{"Token": ""}, {"Token": "x\r\ny"}, {"Token": 1}, {"uuid": ""}, {"uuid": 1}],
)
async def test_session_values_are_validated_before_use(data):
    session = session_for(login(**data))
    with pytest.raises(cloud.CloudResponseError):
        await cloud.async_discover_devices(session, "account@example.invalid", "secret")
    assert session.post.call_count == 1


def test_device_list_duplicates_missing_credentials_and_empty():
    assert cloud._devices({"infos": []}) == []
    devices = cloud._devices(
        {
            "infos": [
                {"device_uid": "a", "device_pwd": "secret", "device_name": "Garden"},
                {"device_uid": "a", "device_pwd": "other", "device_name": "Duplicate"},
                {"device_uid": "b"},
                {"device_uid": "c", "device_pwd": "secret", "device_name": None},
            ]
        }
    )
    assert [(d.uid, d.name) for d in devices] == [("a", "Garden"), ("c", "UBox camera")]


@pytest.mark.parametrize("data", [{}, {"infos": {}}, {"infos": [None]}])
def test_malformed_device_list(data):
    with pytest.raises(cloud.CloudResponseError):
        cloud._devices(data)


async def test_regional_host_from_login_is_used():
    session = session_for(
        login(svcloc={"api_dn": "https://portal-us.ubianet.com/"}),
        success({"infos": []}),
    )
    assert (
        await cloud.async_discover_devices(session, "account@example.invalid", "secret")
        == []
    )
    assert (
        session.post.call_args_list[1].args[0]
        == "https://portal-us.ubianet.com/api/user/qry/device/list/v2"
    )


@pytest.mark.parametrize(
    "host",
    [
        "http://portal-us.ubianet.com",
        "https://evil.example.invalid",
        "https://ubianet.com.evil.example.invalid",
        "https://user@portal-us.ubianet.com",
        "https://portal-us.ubianet.com:8123",
        "https://portal-us.ubianet.com/path",
        "https://portal-us.ubianet.com?token=value",
        "https://127.0.0.1",
        "https://[broken",
        "https://portal-us.ubianet.com/#fragment",
        12,
    ],
)
async def test_untrusted_routing_never_receives_token(host):
    session = session_for(login(svcloc={"api_dn": host}))
    with pytest.raises(cloud.CloudResponseError):
        await cloud.async_discover_devices(session, "account@example.invalid", "secret")
    assert session.post.call_count == 1
