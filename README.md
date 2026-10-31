# UBox Relay for Home Assistant and go2rtc

**Version 0.2.0:** a HACS custom integration that receives an authorized
UBox/Ubia camera directly inside Home Assistant. No separate Go binary,
previous `ubox_p4p` integration or go2rtc add-on is needed for reception.

Configure the camera in Home Assistant, then copy its protected stream URL
into go2rtc. go2rtc remains available for distribution, browser playback,
RTSP, HLS and IPTV players such as APTV.

## What runs where

```text
UBox camera → vendor P4P relay → HACS integration → protected MPEG-TS URL → go2rtc
                                          └→ Home Assistant camera
```

The integration uses Python and Home Assistant's FFmpeg. One on-demand
receiver/transcoder is shared by viewers and snapshots. It stops after the
last subscriber and an idle grace period. It does not poll battery cameras
continually or create a permanent viewing session.

Device UID and device password are stored in HA's config entry. The exported
URL contains an independent random access token, not those credentials.
Only HA administrators can retrieve or rotate that URL. Treat the URL as a
camera password: anyone who can reach HA and knows the URL can view that
camera. Rotation revokes old URLs and disconnects existing exported streams.

## Requirements and current limits

- Home Assistant 2026.10 or newer, with working FFmpeg (included with HA OS/
  the official HA container; custom Core installations need FFmpeg installed).
- A UBox email/password account for camera discovery, or camera device UID
  and **device password** for manual setup. Direct Apple sign-in is not supported.
- Network access to the vendor relays; this is not a cloud-independent solution.
- go2rtc is optional for external distribution, not required for the HA camera.

The established protocol variant was observed with an XG-S20-EU4G camera.
Other firmware/devices are not guaranteed. Audio, PTZ, recording playback
and battery telemetry are not implemented. Setup validates inputs locally;
it does not wake the camera. A connection is attempted when viewing starts.
Cold starts can take several seconds and the first snapshot may need a retry.

## Installation

Install from this public GitHub repository as a custom HACS repository.
The project is not listed in the default HACS catalog. For manual installation,
extract the release ZIP into your HA configuration directory so that
`custom_components/ubox_relay` is present, then restart HA.

1. In HACS, add this repository as a custom repository, category **Integration**.
2. Download **UBox Relay** and restart Home Assistant.
3. Add **UBox Relay** in **Settings → Devices & services → Add integration**.
4. Choose **Sign in to UBox account**, enter your email and account password,
   then select a camera by name. Alternatively choose manual device credentials.
   An optional name overrides the selected camera name; relay override is optional.
5. Open the created camera to view it in HA.

Account discovery signs in once over verified HTTPS and fetches the camera list.
The account password and session token are discarded after discovery. Only the
selected device UID/password and camera name are saved in the HA config entry.
Repeat Add integration to add another camera. Existing manual entries continue
working; selecting an already configured camera is rejected as a duplicate.
Shared/restricted cameras without device credentials cannot be added.

The account path follows the observed UBox Pro 1.1.30 request/model contract.
A live account test confirmed login and camera selection through the verified
HTTPS login-gateway fallback. Offline tests cover request/response handling,
secret non-persistence and rejection of untrusted token destinations.
If the vendor changes its API or requires interactive verification, use manual
setup. The integration does not enroll push notifications or poll the account.

The Go receiver at the root is retained as a standalone reference and does
not run as part of HACS. Do not run two receivers for the same camera while
migrating from an older setup; disable the old reader before testing the new
one. Keep your working setup as a rollback until live testing is complete.

## Add the camera in go2rtc

1. In HA's developer **Actions**, choose **UBox Relay: Get stream URL**.
2. Select the camera's configuration entry. Optionally enter the HA base URL
   that go2rtc can reach (for example a LAN/private-VPN hostname).
3. Execute the action with response enabled and copy `stream_url` from its
   response. It is deliberately not exposed in ordinary entity attributes.
4. In go2rtc, add that HTTP URL as a new stream source, or insert it in YAML:

```yaml
streams:
  ubox_camera: "http://homeassistant.example.invalid:8123/api/ubox_relay/REPLACE_ENTRY_ID/stream.ts?token=REPLACE_TOKEN"
```

Use the actual URL returned by HA. The example host and placeholders are
intentionally unusable. The source is already H.264 video in MPEG-TS, so
another transcode is normally unnecessary. Use your existing go2rtc player,
RTSP or HLS outputs as usual. This is a standard HTTP source and does not
require a custom go2rtc binary, an `exec:` source or its command permissions.

To invalidate a copied/leaked URL, run **UBox Relay: Rotate stream token** and
update the source in go2rtc with the new response. Changing the device password
in the integration's options reconnects the receiver. Removing the integration
also removes the exported stream and stops its worker.

The exported endpoint is available through HA's normal HTTP server. It
requires the URL token even though go2rtc is not logged into HA. Prefer a
trusted LAN or private VPN; this project does not configure public access,
TLS certificates or router forwarding. HTTPS requires valid TLS on your HA
base URL. Client-supplied source URLs are not fetched by the export handler;
it proxies only its own token-protected loopback transport.

## Tests and privacy

```sh
python -m pip install -r requirements-test.txt
python -m pytest
ruff check custom_components tests scripts/check_privacy.py
ruff format --check custom_components tests scripts/check_privacy.py
python scripts/check_privacy.py
```

Tests cover the native packet formats/CRC, cancellation and bounds, shared
FFmpeg lifecycle, HA configuration/options, export authorization and token
rotation. Synthetic FFmpeg smoke tests can run with `UBOX_TEST_FFMPEG=ffmpeg`.
The 125 automated tests do not contact a real camera or account. Separate live
checks on one HA OS installation confirmed snapshots, HA HLS, protected MPEG-TS
export and H.264/MP4 output through go2rtc. A later account check confirmed the
camera-selection screen. These checks do not establish long-term reliability
or compatibility with other camera firmware. Validate on your own installation
before replacing a working receiver.

A separate bounded hardware check of the Python receiver delivered 229 video
units in a 20-second run, with 719 valid media CRCs and no mismatch. That check
did not install the integration in HA and does not establish long-term or
whole-installation reliability.

The repository contains no personal camera names, deployment addresses,
account/device credentials, recordings or captures. Test credentials and
fixtures are synthetic. Vendor relay endpoints and the fixed legacy wire
constant are protocol data. The one included PNG is an original, code-generated
camera icon with no metadata or photographic content; its reviewed hash is
checked by the privacy guard.

See [SECURITY.md](SECURITY.md), [CONTRIBUTING.md](CONTRIBUTING.md) and
[protocol notes](docs/PROTOCOL.md). This project is independent of UBox/Ubia.
MIT licensing and upstream attribution are in [LICENSE](LICENSE) and
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

## Standalone Go receiver

The root Go command remains available for the previously validated standalone
workflow. Build with `go build -trimpath -o bin/ubox-relay-bridge .` and use
`--native-handshake --config-root /config --entry-id REPLACE_WITH_ENTRY_ID`.
It still expects an existing `ubox_p4p` config entry. See the original
[go2rtc example](examples/go2rtc.example.yaml), which is separate from the
HACS workflow described above. Offline Go checks: `go test -race ./...` and
`go vet ./...`.
