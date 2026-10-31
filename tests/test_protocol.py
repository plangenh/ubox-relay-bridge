"""Offline native-wire tests; never open a real socket or import HA."""

import asyncio
import importlib.util
import struct
import sys
import unittest
from collections import Counter
from pathlib import Path
from unittest.mock import AsyncMock, patch

MODULE_PATH = Path(__file__).parents[1] / "custom_components/ubox_relay/protocol.py"
spec = importlib.util.spec_from_file_location("ubox_protocol_under_test", MODULE_PATH)
p = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = p
spec.loader.exec_module(p)


def response(tag=0xDEADBEEF):
    b = p._packet(468, 0x00421206)
    b[16], b[19] = 1, 1
    b[70], b[71] = 1, 9
    struct.pack_into("<HHI", b, 72, 0x1234, 0x5678, tag)
    return bytes(b)


def wake():
    b = p._packet(60, 0x00421202)
    b[16] = 1
    b[36:56] = b"test-uid".ljust(20, b"\0")
    b[56] = 2
    return bytes(b)


def frame(typ=17, crc=True):
    b = bytearray(36)
    struct.pack_into("<I", b, 0, typ)
    struct.pack_into("<I", b, 8, 20)
    b[32:] = b"test"
    struct.pack_into("<I", b, 12, p.native_crc(b[16:]) if crc else 0)
    return bytes(b)


class WireTests(unittest.TestCase):
    def test_native_tail_independent_vectors(self):
        prefix = "b4348c80685c1822242b791cacc8ba88b5358d90795c1923253b781dadd9ba89"
        for full, tail, expected in (
            (0, 2, "2149"),
            (0, 4, "60664921"),
            (0, 8, "7168666021636c49"),
            (32, 2, "0169"),
            (32, 4, "40466901"),
            (32, 8, "5148464001434c69"),
        ):
            plain = bytes(range(full + tail))
            encoded = bytes.fromhex((prefix if full else "") + expected)
            self.assertEqual(p.transform(plain), encoded)
            self.assertEqual(p.transform(encoded, True), plain)
        for length in range(80):
            plain = bytes(range(length))
            self.assertEqual(p.transform(p.transform(plain), True), plain)

    def test_native_crc_independent_vector(self):
        self.assertEqual(p.native_crc(b"123456789"), 0x2DFD2D88)
        self.assertEqual(p.native_crc(b""), 0)

    def test_response_correlation_and_bounds(self):
        expected = p.Session(1, 9, 0x1234, 0x5678, 0xDEADBEEF)
        self.assertEqual(
            p.parse_response(p.transform(response()), expected.conv), expected
        )
        for offset, value in ((19, 2), (70, 2), (76, 0), (40, 1), (16, 17)):
            b = bytearray(response())
            b[offset] = value
            self.assertIsNone(p.parse_response(bytes(b), expected.conv))
        for length in (0, 16, 39, 467):
            self.assertIsNone(p.parse_response(response()[:length], expected.conv))
        b = bytearray(response())
        struct.pack_into("<I", b, 8, 0x00421406)
        self.assertIsNone(p.parse_response(bytes(b), expected.conv))
        self.assertEqual(p.parse_wake(wake(), p.Credentials("test-uid", "password")), 2)
        self.assertIsNone(p.parse_wake(wake(), p.Credentials("another", "password")))
        # A matching later record must be selected without interpreting the
        # unrelated first record's metadata as session fields.
        multiple = bytearray(response() + response()[40:])
        multiple[16], multiple[70] = 2, 99
        self.assertEqual(p.parse_response(bytes(multiple), expected.conv), expected)

    def test_native_packet_offsets(self):
        s = p.Session(3, 9, 0x1234, 0x5678, 0xDEADBEEF)
        self.assertEqual(
            p.decode(p.bind(s)).hex(),
            "071810001400030005142400785600000003090034127856efbeadde0000000000000000",
        )
        self.assertEqual(
            p.decode(p.wrap(b"\xaa\xbb", s)).hex(),
            "07181000020009000914240078560000aabb",
        )
        b = p.decode(p.logout(s))
        self.assertEqual(b[74:84].hex(), "030934127856efbeadde")
        credentials = p.Credentials("test-uid", "12345678901234567890")
        b = p.decode(p.login(credentials, 0xDEADBEEF, "192.0.2.1", 20001))
        self.assertEqual(b[60:80], b"12345678901234567890")
        self.assertEqual(b[92:108], b"admin" + bytes(11))
        self.assertNotIn("test-uid", repr(credentials))
        with self.assertRaisesRegex(p.ProtocolError, "outgoing_packet_limit"):
            p.wrap(bytes(1401), s)

    def test_window_reorder_duplicate_ack_probe_and_wrap(self):
        stats = Counter()
        w = p.ReceiveWindow(7, stats)
        data, ack = w.accept([p.Segment(7, p.PUSH, sn=1, ts=123, data=b"B")])
        self.assertEqual(data, b"")
        self.assertEqual(p.parse_segments(ack[0])[0].ts, 123)
        data, _ = w.accept(
            [
                p.Segment(7, p.PUSH, sn=1, data=b"B"),
                p.Segment(7, p.PUSH, sn=0, data=b"A"),
            ]
        )
        self.assertEqual(data, b"AB")
        self.assertEqual(stats["duplicates"], 1)
        _, replies = w.accept([p.Segment(7, p.WASK)])
        self.assertEqual(p.parse_segments(replies[0])[0].cmd, p.WINS)
        w.next = 0xFFFFFFFF
        data, _ = w.accept(
            [
                p.Segment(7, p.PUSH, sn=0, data=b"D"),
                p.Segment(7, p.PUSH, sn=0xFFFFFFFF, data=b"C"),
            ]
        )
        self.assertEqual(data, b"CD")
        self.assertEqual(w.next, 1)
        w.accept([p.Segment(8, p.PUSH, data=b"bad")])
        w.accept([p.Segment(7, p.PUSH, sn=513, data=b"far")])
        self.assertEqual(stats["wrong_conv"], 1)
        self.assertEqual(stats["outside_window"], 1)

    def test_window_memory_bound_and_malformed_wire(self):
        w = p.ReceiveWindow(7, Counter())
        for sn in range(1, 512):
            w.accept([p.Segment(7, p.PUSH, sn=sn, data=bytes(65535))])
        self.assertLessEqual(w.size, p.MAX_PENDING - 65535)
        self.assertGreater(w.stats["buffer_drops"], 0)
        with self.assertRaises(p.ProtocolError):
            p.parse_segments(b"short")
        with self.assertRaises(p.ProtocolError):
            p.parse_segments(p.Segment(1, p.ACK, data=b"invalid").pack())

    def test_rdt_crc_drop_zero_control_and_fragmentation(self):
        stats = Counter()
        parser = p.RDTParser(stats)
        good = frame()
        bad = bytearray(good)
        bad[-1] ^= 1
        self.assertEqual(parser.feed(good[:20]), [])
        self.assertEqual(
            parser.feed(good[20:] + bad + frame(crc=False)), [b"test", b"test"]
        )
        self.assertEqual(stats["rdt_crc_match"], 1)
        self.assertEqual(stats["rdt_crc_dropped"], 1)
        control = bytearray(frame(3))
        struct.pack_into("<I", control, 12, 0x12345678)
        parser.feed(control)
        self.assertEqual(stats["rdt_crc_present"], 2)
        with self.assertRaisesRegex(p.ProtocolError, "rdt_buffer_limit"):
            parser.feed(bytes(p.MAX_RDT + 32 + 65536))


class AsyncTests(unittest.IsolatedAsyncioTestCase):
    async def test_sink_backpressure_is_awaited_and_bounded(self):
        client = p.RelayClient(p.Credentials("test-uid", "password"))
        entered, release = asyncio.Event(), asyncio.Event()

        async def callback(video):
            self.assertEqual(video, b"frame")
            entered.set()
            await release.wait()

        task = asyncio.create_task(client._deliver(callback, b"frame"))
        await entered.wait()
        self.assertFalse(task.done())
        release.set()
        await task

        # Patch only the timeout wrapper, avoiding a two-second test sleep.
        async def timeout(awaitable, seconds):
            self.assertEqual(seconds, 2)
            awaitable.close()
            raise TimeoutError()

        with patch.object(p.asyncio, "wait_for", timeout):
            with self.assertRaisesRegex(p.ProtocolError, "video_output_failed"):
                await client._deliver(callback, b"frame")

    async def test_stopped_run_never_resolves_or_opens_socket(self):
        client = p.RelayClient(p.Credentials("test-uid", "password"))
        stop = asyncio.Event()
        stop.set()
        with patch.object(client, "_resolve", new_callable=AsyncMock) as resolve:
            self.assertEqual(await client.run(AsyncMock(), stop), {})
            resolve.assert_not_called()

    async def test_stop_and_cancellation_wait_for_cleanup(self):
        client = p.RelayClient(p.Credentials("test-uid", "password"))
        entered, cleaned, stop = asyncio.Event(), asyncio.Event(), asyncio.Event()

        async def worker(callback):
            try:
                entered.set()
                await asyncio.Event().wait()
            finally:
                cleaned.set()

        with patch.object(client, "_worker", worker):
            task = asyncio.create_task(client.run(AsyncMock(), stop))
            await entered.wait()
            stop.set()
            await task
            self.assertTrue(cleaned.is_set())

            entered.clear()
            cleaned.clear()
            stop.clear()
            task = asyncio.create_task(client.run(AsyncMock(), stop))
            await entered.wait()
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
            self.assertTrue(cleaned.is_set())

    async def test_duration_cancels_and_awaits_cleanup(self):
        client = p.RelayClient(p.Credentials("test-uid", "password"))
        cleaned = asyncio.Event()

        async def worker(callback):
            try:
                await asyncio.Event().wait()
            finally:
                cleaned.set()

        with patch.object(client, "_worker", worker):
            self.assertEqual(
                await client.run(AsyncMock(), asyncio.Event(), duration=0.001), {}
            )
        self.assertTrue(cleaned.is_set())

    async def test_retry_bound_and_output_failure_not_retried(self):
        client = p.RelayClient(p.Credentials("test-uid", "password"))
        with (
            patch.object(
                client, "_resolve", AsyncMock(return_value=[("192.0.2.1", 20001)])
            ),
            patch.object(
                client,
                "_attempt",
                AsyncMock(side_effect=p.ProtocolError("video_inactivity")),
            ) as attempt,
            patch.object(p.asyncio, "sleep", AsyncMock()),
        ):
            with self.assertRaisesRegex(p.ProtocolError, "video_inactivity"):
                await client._worker(AsyncMock())
            self.assertEqual(attempt.await_count, 3)
        with (
            patch.object(client, "_resolve", AsyncMock(return_value=[])),
            patch.object(
                client,
                "_attempt",
                AsyncMock(side_effect=p.ProtocolError("video_output_failed")),
            ) as attempt,
        ):
            with self.assertRaisesRegex(p.ProtocolError, "video_output_failed"):
                await client._worker(AsyncMock())
            self.assertEqual(attempt.await_count, 1)

    async def test_native_start_retries_are_bounded_and_logout_is_sent(self):
        client = p.RelayClient(
            p.Credentials("test-uid", "password"), initial_timeout=12
        )
        address = ("192.0.2.1", 20001)
        clock = [0.0]
        reads = [wake(), response(123)]
        sent = []

        class FakeSocket:
            def setblocking(self, value):
                pass

            def bind(self, address):
                pass

            def connect(self, address):
                pass

            def getsockname(self):
                return ("192.0.2.2", 12345)

            def close(self):
                pass

        class FakeLoop:
            def time(self):
                return clock[0]

        async def receive(sock):
            clock[0] += 0.5
            return (reads.pop(0), address) if reads else None

        async def send(sock, packet, destination):
            sent.append(p.decode(packet))

        with (
            patch.object(p.socket, "socket", return_value=FakeSocket()),
            patch.object(p.asyncio, "get_running_loop", return_value=FakeLoop()),
            patch.object(p.secrets, "randbits", return_value=123),
            patch.object(client, "_receive", receive),
            patch.object(client, "_send", send),
        ):
            with self.assertRaisesRegex(p.ProtocolError, "video_inactivity"):
                await client._attempt([address], AsyncMock())
        self.assertEqual(client.stats["start_retries"], 8)
        self.assertEqual(sum(p._u32(b, 8) == 0x00241207 for b in sent), 3)
        self.assertEqual(sum(p._u32(b, 8) == 0x00241409 for b in sent), 9)


if __name__ == "__main__":
    unittest.main()
