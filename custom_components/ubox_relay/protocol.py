"""Native UBox Pro relay protocol, without Home Assistant dependencies.

Wire layouts and fixed transform follow the inspected UBox Pro 1.1.30 ARM64
artifact; see the repository's reverse-engineering provenance. No credentials,
packet contents, addresses or session tags are logged by this module.
"""

from __future__ import annotations

import asyncio
import ipaddress
import secrets
import socket
import struct
import zlib
from collections import Counter
from collections.abc import Awaitable, Callable
from contextlib import suppress
from dataclasses import dataclass, field

MAGIC = 0x00101807
KEY = b"I believe 1 ^ill win the battle!"
PERMUTATION = (11, 9, 8, 15, 13, 10, 12, 14, 2, 1, 5, 0, 6, 4, 7, 3)
TAILS = {2: (1, 0), 4: (2, 3, 0, 1), 8: (7, 4, 3, 2, 1, 6, 5, 0)}
RELAYS = (
    "172.111.37.9",
    "38.60.221.99",
    "51.195.255.1",
    "170.101.97.156",
    "149.56.108.231",
    "43.173.75.192",
    "45.125.216.146",
    "170.101.97.155",
    "51.222.110.215",
    "49.51.188.113",
    "43.156.14.205",
    *(f"a{i}.ubianet.com" for i in range(1, 7)),
)
PUSH, ACK, WASK, WINS = 81, 82, 83, 84
WINDOW, MAX_PENDING, MAX_RDT = 512, 4_000_000, 2_000_000
KCP_HEADER = struct.Struct("<IBBHIIII")


class ProtocolError(RuntimeError):
    """A fixed, nonsecret protocol failure code."""


@dataclass(frozen=True, repr=False)
class Credentials:
    uid: str = field(repr=False)
    password: str = field(repr=False)

    def __post_init__(self) -> None:
        try:
            uid, password = self.uid.encode("ascii"), self.password.encode("ascii")
        except UnicodeError, AttributeError:
            raise ProtocolError("credentials_invalid") from None
        if not uid or not password or len(uid) > 20 or len(password) > 20:
            raise ProtocolError("credentials_invalid")


def _u32(b: bytes | bytearray, offset: int = 0) -> int:
    return struct.unpack_from("<I", b, offset)[0]


def _rol(value: int, count: int) -> int:
    count %= 32
    return ((value << count) | (value >> ((32 - count) % 32))) & 0xFFFFFFFF


def transform(data: bytes, decrypt: bool = False) -> bytes:
    """Legacy fixed wire encoding, including native 2/4/8-byte tails."""
    out = bytearray()
    full = len(data) // 16 * 16
    for offset in range(0, full, 16):
        block = bytearray(data[offset : offset + 16])
        if decrypt:
            for w in range(4):
                struct.pack_into(
                    "<I", block, w * 4, _rol(_u32(block, w * 4), w * 4 + 3)
                )
            tmp = bytearray(16)
            for i, j in enumerate(PERMUTATION):
                tmp[j] = block[i]
            block = bytearray(v ^ KEY[i] for i, v in enumerate(tmp))
            for w in range(4):
                struct.pack_into(
                    "<I", block, w * 4, _rol(_u32(block, w * 4), w * 4 + 1)
                )
        else:
            for w in range(4):
                struct.pack_into(
                    "<I", block, w * 4, _rol(_u32(block, w * 4), -(w * 4 + 1))
                )
            tmp = bytes(v ^ KEY[i] for i, v in enumerate(block))
            block = bytearray(tmp[j] for j in PERMUTATION)
            for w in range(4):
                struct.pack_into(
                    "<I", block, w * 4, _rol(_u32(block, w * 4), -(w * 4 + 3))
                )
        out.extend(block)
    tail = data[full:]
    order = TAILS.get(len(tail), tuple(range(len(tail))))
    out.extend(tail[j] ^ KEY[i if decrypt else j] for i, j in enumerate(order))
    return bytes(out)


def decode(data: bytes) -> bytes:
    return data if len(data) >= 4 and _u32(data) == MAGIC else transform(data, True)


def native_crc(data: bytes) -> int:
    """Reflected polynomial EDB88320, raw seed zero, no final XOR."""
    return zlib.crc32(data, 0xFFFFFFFF) ^ 0xFFFFFFFF


def _packet(length: int, kind: int, sid: int = 0, route: int = 0) -> bytearray:
    b = bytearray(length)
    struct.pack_into("<IHHIHH", b, 0, MAGIC, length - 16, sid, kind, route, 0)
    return b


def knock(credentials: Credentials) -> bytes:
    b = _packet(60, 0x00241201)
    struct.pack_into("<I", b, 16, 0x101)
    b[20:40] = credentials.uid.encode().ljust(20, b"\0")
    return transform(b)


def login(credentials: Credentials, tag: int, ip: str, port: int) -> bytes:
    b = _packet(124, 0x00241205)
    b[16:20] = bytes((1, 0, 6, 1))
    b[28:32] = socket.inet_aton(ip)
    struct.pack_into(">H", b, 32, port)
    b[40:60] = credentials.uid.encode().ljust(20, b"\0")
    b[60:80] = credentials.password.encode().ljust(20, b"\0")
    b[82] = 1
    struct.pack_into("<I", b, 88, tag)
    b[92:108] = b"admin".ljust(16, b"\0")
    b[108], b[111], b[116], b[117] = 9, 1, 0x2D, 0x9C
    return transform(b)


@dataclass(frozen=True)
class Session:
    client_sid: int
    server_sid: int
    route_a: int
    route_b: int
    conv: int


def parse_wake(packet: bytes, credentials: Credentials) -> int | None:
    b = decode(packet)
    if (
        len(b) < 57
        or _u32(b) != MAGIC
        or _u32(b, 8) != 0x00421202
        or not 1 <= b[16] <= 16
    ):
        return None
    if b[36:56] != credentials.uid.encode().ljust(20, b"\0"):
        return None
    return b[56]


def parse_response(
    packet: bytes, tag: int, sid: int = 1, sequence: int = 1
) -> Session | None:
    b = decode(packet)
    if len(b) < 40 or _u32(b) != MAGIC or _u32(b, 8) != 0x00421206:
        return None
    count = b[16]
    if not 1 <= count <= 16 or len(b) < 40 + count * 428 or b[19] not in (0, sequence):
        return None
    for i in range(count):
        r = b[40 + i * 428 : 40 + (i + 1) * 428]
        if struct.unpack_from("<h", r)[0] or r[30] != sid or _u32(r, 36) != tag:
            continue
        a, route = struct.unpack_from("<HH", r, 32)
        return Session(sid, r[31], a, route, tag)
    return None


def bind(session: Session) -> bytes:
    b = _packet(36, 0x00241405, session.client_sid, session.route_b)
    b[17], b[18] = session.client_sid, session.server_sid
    struct.pack_into("<HHI", b, 20, session.route_a, session.route_b, session.conv)
    return transform(b)


def wrap(payload: bytes, session: Session) -> bytes:
    if len(payload) > 1400:
        raise ProtocolError("outgoing_packet_limit")
    b = _packet(16 + len(payload), 0x00241409, session.server_sid, session.route_b)
    b[16:] = payload
    return transform(b)


def logout(session: Session) -> bytes:
    b = _packet(100, 0x00241207, session.server_sid, session.route_b)
    b[16], b[17] = 1, 1
    b[74], b[75] = session.client_sid, session.server_sid
    struct.pack_into("<HHI", b, 76, session.route_a, session.route_b, session.conv)
    return transform(b)


@dataclass(frozen=True)
class Segment:
    conv: int
    cmd: int
    frg: int = 0
    wnd: int = 0
    ts: int = 0
    sn: int = 0
    una: int = 0
    data: bytes = b""

    def pack(self) -> bytes:
        return (
            KCP_HEADER.pack(
                self.conv,
                self.cmd,
                self.frg,
                self.wnd,
                self.ts,
                self.sn,
                self.una,
                len(self.data),
            )
            + self.data
        )


def parse_segments(data: bytes) -> list[Segment]:
    segments = []
    while data:
        if len(data) < 24:
            raise ProtocolError("kcp_header")
        conv, cmd, frg, wnd, ts, sn, una, size = KCP_HEADER.unpack_from(data)
        if (
            size > 65535
            or size > len(data) - 24
            or cmd not in (PUSH, ACK, WASK, WINS)
            or (cmd != PUSH and size)
        ):
            raise ProtocolError("kcp_segment")
        segments.append(Segment(conv, cmd, frg, wnd, ts, sn, una, data[24 : 24 + size]))
        data = data[24 + size :]
    return segments


def start_segments(conv: int) -> list[Segment]:
    result = []
    for sn, command in enumerate((0x2122, 0x2112, 0x2122)):
        b = bytearray(36)
        struct.pack_into("<H", b, 0, 3)
        struct.pack_into("<II", b, 8, 20, command)
        result.append(Segment(conv, PUSH, wnd=512, sn=sn, data=bytes(b)))
    return result


def _difference(a: int, b: int) -> int:
    return ((a - b + 0x80000000) & 0xFFFFFFFF) - 0x80000000


class ReceiveWindow:
    def __init__(self, conv: int, stats: Counter[str]) -> None:
        self.conv, self.next, self.size = conv, 0, 0
        self.pending: dict[int, bytes] = {}
        self.start = {0, 1, 2}
        self.stats = stats

    def available(self) -> int:
        return max(
            0, min(WINDOW - len(self.pending), (MAX_PENDING - self.size) // 65535)
        )

    def accept(self, segments: list[Segment]) -> tuple[bytes, list[bytes]]:
        output = bytearray()
        acknowledgments = []
        probe = False
        for s in segments:
            if s.conv != self.conv:
                self.stats["wrong_conv"] += 1
                continue
            self.start.difference_update(
                sn for sn in tuple(self.start) if _difference(sn, s.una) < 0
            )
            if s.cmd == ACK:
                self.start.discard(s.sn)
                self.stats["acks_received"] += 1
            elif s.cmd == WASK:
                probe = True
            elif s.cmd == PUSH:
                delta = _difference(s.sn, self.next)
                if delta >= WINDOW:
                    self.stats["outside_window"] += 1
                    continue
                if delta < 0 or s.sn in self.pending:
                    self.stats["duplicates"] += 1
                elif self.size + len(s.data) > MAX_PENDING - (
                    65535 if delta > 0 else 0
                ):
                    self.stats["buffer_drops"] += 1
                    continue
                else:
                    self.pending[s.sn] = s.data
                    self.size += len(s.data)
                acknowledgments.append(s)
                while self.next in self.pending:
                    data = self.pending.pop(self.next)
                    self.size -= len(data)
                    output.extend(data)
                    self.next = (self.next + 1) & 0xFFFFFFFF
        replies = [
            Segment(
                self.conv, ACK, wnd=self.available(), ts=s.ts, sn=s.sn, una=self.next
            ).pack()
            for s in acknowledgments
        ]
        if probe:
            replies.append(
                Segment(self.conv, WINS, wnd=self.available(), una=self.next).pack()
            )
        return bytes(output), replies


class RDTParser:
    def __init__(self, stats: Counter[str]) -> None:
        self.buffer = bytearray()
        self.stats = stats

    def feed(self, data: bytes) -> list[bytes]:
        if len(self.buffer) + len(data) > MAX_RDT + 32 + 65535:
            raise ProtocolError("rdt_buffer_limit")
        self.buffer.extend(data)
        output = []
        offset = 0
        while len(self.buffer) - offset >= 32:
            size = _u32(self.buffer, offset + 8) - 16
            if not 0 <= size <= MAX_RDT:
                offset += 1
                self.stats["rdt_resync_bytes"] += 1
                continue
            total = size + 32
            if len(self.buffer) - offset < total:
                break
            frame = bytes(self.buffer[offset : offset + total])
            offset += total
            typ, checksum = _u32(frame), _u32(frame, 12)
            if typ in (0x11, 0x13) and checksum:
                self.stats["rdt_crc_present"] += 1
                if native_crc(frame[16:]) != checksum:
                    self.stats["rdt_crc_mismatch"] += 1
                    self.stats["rdt_crc_dropped"] += 1
                    continue
                self.stats["rdt_crc_match"] += 1
            if typ == 0x11 and size:
                output.append(frame[32:])
        del self.buffer[:offset]
        return output


class RelayClient:
    """One bounded async relay receiver; callbacks are awaited with backpressure."""

    def __init__(
        self,
        credentials: Credentials,
        relay_host: str | None = None,
        initial_timeout: float = 15,
        inactivity_timeout: float = 10,
    ) -> None:
        if initial_timeout <= 0 or inactivity_timeout <= 0:
            raise ProtocolError("invalid_timeout")
        self.credentials = credentials
        self.relay_host = relay_host
        self.initial_timeout = initial_timeout
        self.inactivity_timeout = inactivity_timeout
        self.stats: Counter[str] = Counter()

    async def _resolve(self) -> list[tuple[str, int]]:
        loop = asyncio.get_running_loop()
        hosts = [self.relay_host] if self.relay_host else RELAYS
        result: list[tuple[str, int]] = []
        for candidate in hosts:
            host, port = candidate, 20001
            if ":" in host:
                host, raw_port = host.rsplit(":", 1)
                try:
                    port = int(raw_port)
                except ValueError:
                    raise ProtocolError("relay_invalid") from None
            if not 1 <= port <= 65535:
                raise ProtocolError("relay_invalid")
            try:
                ip = str(ipaddress.IPv4Address(host))
                addresses = [(ip, port)]
            except ipaddress.AddressValueError:
                try:
                    rows = await asyncio.wait_for(
                        loop.getaddrinfo(
                            host, port, family=socket.AF_INET, type=socket.SOCK_DGRAM
                        ),
                        0.5,
                    )
                    addresses = [row[4] for row in rows]
                except OSError, TimeoutError:
                    continue
            for address in addresses:
                if address not in result:
                    result.append(address)
        if not result:
            raise ProtocolError("relay_resolution_failed")
        return result

    async def _receive(
        self, sock: socket.socket
    ) -> tuple[bytes, tuple[str, int]] | None:
        try:
            return await asyncio.wait_for(
                asyncio.get_running_loop().sock_recvfrom(sock, 65535), 0.05
            )
        except TimeoutError:
            return None

    async def _send(
        self, sock: socket.socket, packet: bytes, address: tuple[str, int]
    ) -> None:
        try:
            await asyncio.wait_for(
                asyncio.get_running_loop().sock_sendto(sock, packet, address), 0.2
            )
        except OSError, TimeoutError:
            raise ProtocolError("socket_send_failed") from None

    async def _deliver(
        self, on_video: Callable[[bytes], Awaitable[None]], video: bytes
    ) -> None:
        try:
            await asyncio.wait_for(on_video(video), 2)
        except asyncio.CancelledError:
            raise
        except Exception:
            raise ProtocolError("video_output_failed") from None

    async def _attempt(
        self,
        relays: list[tuple[str, int]],
        on_video: Callable[[bytes], Awaitable[None]],
    ) -> None:
        loop = asyncio.get_running_loop()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        session = None
        selected = None
        try:
            sock.setblocking(False)
            sock.bind(("0.0.0.0", 0))
            tag = secrets.randbits(32)
            deadline, next_send = loop.time() + 10, 0.0
            while selected is None and loop.time() < deadline:
                if loop.time() >= next_send:
                    for address in relays:
                        await self._send(sock, knock(self.credentials), address)
                    next_send = loop.time() + 0.5
                received = await self._receive(sock)
                if not received or received[1] not in relays:
                    continue
                status = parse_wake(received[0], self.credentials)
                if status == 3:
                    raise ProtocolError("wake_rejected")
                if status == 2:
                    selected = received[1]
            if selected is None:
                raise ProtocolError("wake_response_timeout")
            # UDP connect performs route selection without sending a packet.
            route = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                route.connect(selected)
                local_ip = route.getsockname()[0]
            finally:
                route.close()
            request = login(self.credentials, tag, local_ip, sock.getsockname()[1])
            deadline, next_send = loop.time() + 5, 0.0
            while session is None and loop.time() < deadline:
                if loop.time() >= next_send:
                    await self._send(sock, request, selected)
                    next_send = loop.time() + 0.7
                received = await self._receive(sock)
                if received and received[1] == selected:
                    session = parse_response(received[0], tag)
            if session is None:
                raise ProtocolError("relay_response_timeout")
            self.stats["session_matched"] += 1
            await self._send(sock, bind(session), selected)
            window, parser = ReceiveWindow(tag, self.stats), RDTParser(self.stats)
            starts = start_segments(tag)
            await self._send(
                sock, wrap(b"".join(s.pack() for s in starts), session), selected
            )
            began = last_video = last_keepalive = last_retry = loop.time()
            retries = 0
            while True:
                now = loop.time()
                limit = (
                    self.initial_timeout
                    if last_video == began
                    else self.inactivity_timeout
                )
                if now - last_video >= limit:
                    raise ProtocolError("video_inactivity")
                if now - last_keepalive >= 1:
                    await self._send(sock, bind(session), selected)
                    last_keepalive = now
                if window.start and retries < 8 and now - last_retry >= 0.5:
                    await self._send(
                        sock,
                        wrap(
                            b"".join(s.pack() for s in starts if s.sn in window.start),
                            session,
                        ),
                        selected,
                    )
                    retries += 1
                    self.stats["start_retries"] += 1
                    last_retry = now
                received = await self._receive(sock)
                if not received:
                    continue
                packet, source = received
                if source != selected:
                    self.stats["other_source"] += 1
                    continue
                plain = decode(packet)
                if (
                    len(plain) < 16
                    or _u32(plain) != MAGIC
                    or _u32(plain, 8) != 0x0042140A
                ):
                    continue
                self.stats["datagrams"] += 1
                try:
                    segments = parse_segments(plain[16:])
                except ProtocolError:
                    self.stats["malformed_datagrams"] += 1
                    continue
                ordered, replies = window.accept(segments)
                for offset in range(0, len(replies), 40):
                    await self._send(
                        sock,
                        wrap(b"".join(replies[offset : offset + 40]), session),
                        selected,
                    )
                for video in parser.feed(ordered):
                    await self._deliver(on_video, video)
                    self.stats["video_units"] += 1
                    self.stats["video_bytes"] += len(video)
                    last_video = loop.time()
        except OSError:
            raise ProtocolError("socket_failed") from None
        finally:
            if session is not None and selected is not None:
                for _ in range(3):
                    with suppress(ProtocolError, OSError):
                        await self._send(sock, logout(session), selected)
            sock.close()

    async def _worker(self, on_video: Callable[[bytes], Awaitable[None]]) -> None:
        relays = await self._resolve()
        for attempt in range(3):
            self.stats["session_attempts"] += 1
            try:
                await self._attempt(relays, on_video)
            except ProtocolError as err:
                self.stats["session_failures"] += 1
                if str(err) == "video_output_failed" or attempt == 2:
                    raise
                await asyncio.sleep(0.7)

    async def run(
        self,
        on_video: Callable[[bytes], Awaitable[None]],
        stop: asyncio.Event,
        duration: float | None = None,
    ) -> dict[str, int]:
        if duration is not None and duration <= 0:
            raise ProtocolError("invalid_duration")
        self.stats.clear()
        if stop.is_set():
            return {}
        worker = asyncio.create_task(self._worker(on_video))
        stopped = asyncio.create_task(stop.wait())
        try:
            done, _ = await asyncio.wait(
                (worker, stopped), timeout=duration, return_when=asyncio.FIRST_COMPLETED
            )
            if worker in done:
                await worker
            return dict(self.stats)
        finally:
            worker.cancel()
            stopped.cancel()
            await asyncio.gather(worker, stopped, return_exceptions=True)
