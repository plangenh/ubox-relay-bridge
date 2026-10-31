"""Render the original geometric camera icon; no images or metadata as input."""

import argparse
import struct
import zlib
from pathlib import Path


def render() -> bytes:
    pixels = bytearray()
    for y in range(256):
        pixels.append(0)
        for x in range(256):
            body = 30 <= y < 256 and (
                20 <= x < 236
                or 50 <= y < 236
                or (x - (20 if x < 128 else 235)) ** 2
                + (y - (50 if y < 128 else 235)) ** 2
                <= 400
            )
            top = 40 <= x < 136 and 0 <= y < 46
            color = (22, 102, 172, 255) if body or top else (0, 0, 0, 0)
            radius = (x - 128) ** 2 + (y - 142) ** 2
            if radius <= 72**2:
                color = (255, 255, 255, 255)
            if radius <= 51**2:
                color = (22, 102, 172, 255)
            if radius <= 30**2:
                color = (90, 210, 230, 255)
            if (x - 211) ** 2 + (y - 69) ** 2 <= 11**2:
                color = (255, 255, 255, 255)
            pixels.extend(color)

    def chunk(kind: bytes, data: bytes) -> bytes:
        return (
            struct.pack(">I", len(data))
            + kind
            + data
            + struct.pack(">I", zlib.crc32(kind + data))
        )

    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", 256, 256, 8, 6, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(bytes(pixels), 9))
        + chunk(b"IEND", b"")
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    path = (
        Path(__file__).resolve().parents[1]
        / "custom_components/ubox_relay/brand/icon.png"
    )
    if args.check:
        if path.read_bytes() != render():
            raise SystemExit("Brand icon differs from its geometric source")
    else:
        path.write_bytes(render())
