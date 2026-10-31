"""Transient UBox account discovery; never persist account passwords or tokens."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from dataclasses import dataclass
from urllib.parse import urlencode, urlsplit

import aiohttp

_BASE_URL = "https://portal-uni.ubianet.com"
_LOGIN_PATH = "/api/pub/account/login/v3"
_DEVICES_PATH = "/api/user/qry/device/list/v2"
_MAX_RESPONSE = 2 * 1024 * 1024
_TIMEOUT = aiohttp.ClientTimeout(total=25, connect=10)


class CloudAuthError(Exception):
    """Account or session was rejected, without retaining server messages."""


class CloudConnectionError(Exception):
    """The vendor service could not be reached."""


class CloudResponseError(Exception):
    """The vendor returned an unsupported or malformed response."""


class CloudChallengeRequired(Exception):
    """An interactive verification step is required."""


@dataclass(frozen=True, repr=False)
class CloudDevice:
    """Only the credentials necessary for one camera."""

    uid: str
    password: str
    name: str


def _password_digest(password: str) -> str:
    # Native Utilities.hmacsha1:secret: uses an empty key and this Base64 alphabet.
    raw = hmac.new(b"", password.encode("utf-8"), hashlib.sha1).digest()
    return base64.b64encode(raw).decode("ascii").translate(str.maketrans("+/=", "-_,"))


async def _post(
    session: aiohttp.ClientSession,
    path: str,
    payload: dict,
    headers: dict[str, str],
    *,
    base_url: str = _BASE_URL,
) -> dict:
    try:
        async with session.post(
            base_url + path,
            json=payload,
            headers=headers,
            timeout=_TIMEOUT,
            allow_redirects=False,
        ) as response:
            if response.status in {401, 403}:
                raise CloudAuthError from None
            if response.status == 429:
                raise CloudConnectionError from None
            if response.status >= 500:
                raise CloudConnectionError from None
            if response.status != 200:
                raise CloudResponseError from None
            # A single read(n) may return a short network chunk before EOF.
            body = bytearray()
            async for chunk in response.content.iter_chunked(65536):
                body.extend(chunk)
                if len(body) > _MAX_RESPONSE:
                    raise CloudResponseError from None
            try:
                result = json.loads(body)
            except (ValueError, UnicodeError):
                raise CloudResponseError from None
    except (aiohttp.ClientError, TimeoutError, OSError):
        raise CloudConnectionError from None
    if not isinstance(result, dict):
        raise CloudResponseError
    code = result.get("code")
    if type(code) is not int:
        raise CloudResponseError
    if code in {10004, 20005}:
        raise CloudAuthError
    if code != 0:
        raise CloudResponseError
    data = result.get("data")
    if not isinstance(data, dict):
        raise CloudResponseError
    return data


def _api_host(login: dict) -> str:
    """Honor the regional API host without sending tokens to arbitrary URLs."""
    location = login.get("svcloc")
    if location is None:
        return _BASE_URL
    if not isinstance(location, dict):
        raise CloudResponseError
    host = location.get("api_dn")
    if host in (None, ""):
        return _BASE_URL
    if not isinstance(host, str):
        raise CloudResponseError
    try:
        parsed = urlsplit(host)
        valid = (
            parsed.scheme == "https"
            and parsed.hostname is not None
            and (
                parsed.hostname == "ubianet.com"
                or parsed.hostname.endswith(".ubianet.com")
            )
            and parsed.username is None
            and parsed.password is None
            and parsed.port in (None, 443)
            and parsed.path in ("", "/")
            and not parsed.query
            and not parsed.fragment
        )
    except ValueError:
        raise CloudResponseError from None
    if not valid:
        raise CloudResponseError
    return host.rstrip("/")


def _devices(data: dict) -> list[CloudDevice]:
    infos = data.get("infos")
    if not isinstance(infos, list):
        raise CloudResponseError
    devices: list[CloudDevice] = []
    seen: set[str] = set()
    for info in infos:
        if not isinstance(info, dict):
            raise CloudResponseError
        uid, password = info.get("device_uid"), info.get("device_pwd")
        # Shared/restricted devices without receiver credentials cannot be added.
        if not isinstance(uid, str) or not isinstance(password, str):
            continue
        if not uid or not password or uid in seen:
            continue
        name = info.get("device_name")
        if not isinstance(name, str) or not name.strip():
            name = "UBox camera"
        devices.append(CloudDevice(uid=uid, password=password, name=name))
        seen.add(uid)
    return devices


async def async_discover_devices(
    session: aiohttp.ClientSession, email: str, password: str
) -> list[CloudDevice]:
    """Log in once and discard account/session data after camera discovery."""
    if not email.strip() or not password:
        raise CloudAuthError
    context = urlencode(
        {
            "source": "app",
            "app": "UBoxPro",
            "ver": "1.1.30",
            "os": "ios",
            "osver": "18.0",
        }
    )
    headers = {
        "User-Agent": "UBoxRelay/0.2.0",
        "X-UbiaAPI-CallContext": context,
    }
    login = await _post(
        session,
        _LOGIN_PATH,
        {
            "account": email.strip(),
            "password": _password_digest(password),
            "app": "UBoxPro",
            "app_version": "1.1.30",
            "device_type": 2,
            "device_token": "",
            "brand": "Home Assistant",
            "lang": "en",
        },
        headers,
    )
    token = login.get("Token")
    user_id = login.get("uuid")
    if not isinstance(token, str) or not token or len(token) > 8192:
        raise CloudResponseError
    if any(ord(c) < 32 or ord(c) == 127 for c in token):
        raise CloudResponseError
    if not isinstance(user_id, str) or not user_id or len(user_id) > 256:
        raise CloudResponseError
    headers = {
        **headers,
        "X-Ubia-Auth-UserToken": token,
        "X-UbiaAPI-CallContext": context
        + "&"
        + urlencode({"uid": user_id, "lang": "en", "region": "US"}),
    }
    devices = await _post(
        session, _DEVICES_PATH, {}, headers, base_url=_api_host(login)
    )
    return _devices(devices)
