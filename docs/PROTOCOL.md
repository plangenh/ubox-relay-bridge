# Protocol implementation

The Python HACS integration implements its own on-demand receiver. The Go
receiver at the repository root remains a reference/standalone tool; it is
not executed or downloaded by the integration.

The port preserves the corrected protocol behavior established against UBox
Pro 1.1.30:

1. Send `1201` wake requests at 500-ms intervals for at most ten seconds.
2. A `1202` response must identify the requested UID and report status 2.
   Its source is selected as the relay endpoint for registration.
3. Send `1205` with the native capability/version fields, a random request ID
   and the device password/login fields. Accept only complete `1206` records
   matching client SID, request ID and any response sequence.
4. `1406` is liveness only. It cannot establish a session. The KCP conversation
   is the random ID from the receiver's own request.
5. Build `1405`, `1409` and `1207` using their distinct SID/routing layouts.
6. Decode the fixed transform, including partial-block permutations for 2,
   4 and 8 bytes. The XOR key restarts at zero for the partial block.
7. Order/acknowledge KCP data, validate bounded RDT framing and check native
   media CRC before forwarding HEVC. The CRC is reflected IEEE polynomial
   with seed zero and no initial/final complement, not standard `ChecksumIEEE`.
8. Bound output waits and buffers, reject foreign session packets, and send
   best-effort logout on cancellation and teardown.

The protocol still depends on vendor relay infrastructure. Its legacy
transform and CRC are not modern authenticated encryption. Device/firmware
compatibility is limited to the observed protocol variant. Account login,
device discovery, audio and battery telemetry are not implemented.

Automated protocol tests use synthetic data. No vendor app, disassembly,
captured video, device identifier or packet capture is distributed.

## Account discovery (0.2)

The installed UBox Pro 1.1.30 constructs a LoginV3 request at
`/api/pub/account/login/v3` with an account and password-derived value. Native
`Utilities.hmacsha1:secret:` uses HMAC-SHA1 with an empty key and the UTF-8
password as the message; its Base64 output substitutes `+`, `/`, `=` with `-`,
`_`, `,`. This is vendor compatibility, not a password storage scheme.

The login success path passes reply `Token` and `uuid` unmodified into its API
context. Subsequent calls use `X-Ubia-Auth-UserToken` and a URL-encoded
`X-UbiaAPI-CallContext`. The current camera endpoint is
`/api/user/qry/device/list/v2`, whose reply `data.infos` is an array of
DeviceInfoV2 records containing `device_uid`, `device_name`, `device_user` and
`device_pwd`. This differs from the older device-list endpoint found in strings.

The account path is not required for ongoing reception. Tokens and account
credentials are transient; only a selected device's reception credentials are
retained. Static request/model analysis and bounded unauthenticated validation
responses corroborate the current contract. A live account check subsequently
confirmed authentication and camera selection via the verified login gateway.

The native login success path updates the service host from `svcloc.api_dn`;
outside China its default is `https://portal-uni.ubianet.com`. The integration
restricts any returned host to the Ubia HTTPS domain and never follows redirects.
Malformed or off-domain hints never receive session tokens. Unsupported hints
fall back to the same verified HTTPS gateway used for login. Standard HTTP
origins on the vendor domain are upgraded to HTTPS; vendor base paths are
preserved. No token-bearing request uses plaintext HTTP.
