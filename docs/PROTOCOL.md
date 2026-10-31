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
