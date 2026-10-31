# UBox Relay Bridge

Experimental Go receiver for video from an authorized UBox/Ubia camera. It
receives HEVC through the vendor's P4P relay protocol and writes raw video to
stdout. go2rtc can expose that video as RTSP, HLS or HTTP MP4 and transcode it
to H.264 for Home Assistant and other players.

This is an independent interoperability project. It is not affiliated with
UBox or Ubia and does not include vendor binaries, firmware or app packages.

## Scope

- Standard-library-only Go implementation.
- Native relay handshake with request/session correlation.
- Receive-side KCP ACKs, ordering, duplicate handling and bounded buffers.
- Correct wire-transform handling for partial blocks.
- Native media CRC checks; corrupted media frames are discarded.
- Bounded retries and signal-triggered logout.
- No account password or camera credentials in command-line arguments.

This is **not** a Home Assistant add-on or HACS integration. The current
credential adapter expects an existing `ubox_p4p` Home Assistant config entry
containing `data.uid` and `data.password`. That integration and account/device
discovery are not included. There is no standalone credentials-file adapter.
Do not edit a running Home Assistant instance's `.storage` files to create
an entry.

The receiver still depends on vendor relays and network access. It is not a
cloud-independent camera interface. Relay endpoints may change, and devices
or firmware versions may use different protocol variants.

## Build and test

Go 1.22 or later is required. Development validation used Go 1.27.3.

```sh
go test ./...
go test -race ./...
go vet ./...
mkdir -p bin
go build -trimpath -ldflags='-s -w' -o bin/ubox-relay-bridge .
```

Cross-compile for a Linux ARM64 host:

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build \
  -trimpath -ldflags='-s -w' -o bin/ubox-relay-bridge-linux-arm64 .
```

## Receive video

Install the matching binary on the receiving host. The process must be able
to read the Home Assistant config directory. Select exactly one existing
camera by config entry ID or by its exact, unique title:

```sh
./bin/ubox-relay-bridge --native-handshake \
  --config-root /config --entry-id REPLACE_WITH_ENTRY_ID > video.h265
```

`--native-handshake` is required for the validated deployment path. Without
it, the program retains an older experimental handshake for comparison.

Useful options:

| Option | Purpose |
| --- | --- |
| `--duration 30s` | Bound the whole session, including handshake and retries |
| `--initial-timeout 15s` | Maximum initial wait for video |
| `--inactivity-timeout 10s` | Maximum gap after video has started |
| `--stats-file PATH` | Save aggregate diagnostic counters |
| `--relay HOST[:PORT]` | Restrict relay selection |
| `--local-ip IPv4` | Override the advertised local address |

Stdout is video only. Stderr contains fixed error codes and aggregate counters.
SIGINT/SIGTERM trigger best-effort relay logout. A battery camera can take
several seconds to wake up; the first preview request can time out.

## go2rtc and Home Assistant

See [examples/go2rtc.example.yaml](examples/go2rtc.example.yaml). Merge the two
example streams into your own configuration, replace the entry ID, and set
the executable/config paths for the go2rtc container. Preserve any existing
streams. The host needs FFmpeg for the H.264 conversion.

The example exposes:

```text
rtsp://go2rtc.example.invalid:8554/camera_h264
http://go2rtc.example.invalid:1984/api/stream.mp4?src=camera_h264
http://go2rtc.example.invalid:1984/api/stream.m3u8?src=camera_h264
```

Replace `go2rtc.example.invalid` with your receiving host's reachable name or
address. In Home Assistant, add a **Generic Camera** with the HTTP MP4 URL as
its stream source. An HTTP source can avoid the short RTSP startup timeout
of Home Assistant's internal Generic Camera media helper. Preview timeouts
can still occur while the camera wakes up.

For APTV or another M3U player, edit and import
[examples/camera.example.m3u](examples/camera.example.m3u). A browser player
page is not a media playlist. Keep streams on a trusted LAN or private VPN;
these examples do not configure HTTPS, player authentication or public access.

Keep the source `ubox_p4p` entry because the bridge reads its credentials.
Concurrent polling by another camera receiver can interfere with a session.

## Validation and limits

The protocol path was checked against UBox Pro 1.1.30 and tested with an
authorized XG-S20-EU4G camera. A bounded test delivered 60 seconds of H.264
at 640 × 360 / approximately 15 fps; 3,079 media frames passed the native
CRC check. Reconnection, a Home Assistant image, and a Home Assistant HLS
segment were also checked. These are single-device observations, not a
compatibility or 24/7 reliability guarantee.

Audio output, battery telemetry, PTZ, recording playback and account login
are not implemented. Automated tests are offline and use synthetic data;
they never connect to a camera or the vendor's servers.

## Privacy and contributions

No personal camera names, account credentials, device IDs, private network
addresses, recordings or investigation captures are distributed here.
`golden.json` and test credentials are synthetic. Vendor relay addresses
and the fixed legacy wire-transform constant are protocol data, not user
credentials. The legacy transform is not modern authenticated encryption.

Do not upload your HA configuration, logs, media or packet captures in an
issue. See [SECURITY.md](SECURITY.md) and [CONTRIBUTING.md](CONTRIBUTING.md).
Run the tracked-file privacy check before publishing:

```sh
python3 scripts/check_privacy.py
```

This check detects common accidental disclosures; it does not replace a
manual review. Sensitive files are also excluded by `.gitignore`.

## License and attribution

MIT; see [LICENSE](LICENSE) and
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). The receiver builds on the
MIT-licensed `mahumadad/ubox-p4p` protocol work, with corrections informed by
independent native-code analysis. Only implementation source, synthetic
fixtures and documentation are distributed.
