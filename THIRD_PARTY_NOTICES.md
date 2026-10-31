# Third-party notices

## ubox-p4p

Source: https://github.com/mahumadad/ubox-p4p

Reviewed/adapted revision: `6f9f87fc31da4eb86531a81b08b3b1ffa4db5fa8`.

This Go implementation derives its legacy packet transform, relay packet
construction, initial control commands and parts of its receive framing from
the upstream MIT-licensed protocol implementation, via an intermediate Python
Home Assistant adaptation. Those portions are principally in `crypto.go`,
`main.go` and `kcp.go`. The intermediate Python files are not distributed.

Changes include continuous KCP ACK/reordering/window handling, bounded resource
use, cancellation/logout, native handshake correlation, corrected packet
layouts and partial-block transforms, native media CRC verification, aggregate
diagnostics and offline tests. The bridge does not implement cloud account
login. Vendor relay endpoints are protocol defaults, not deployment addresses.

Preserved upstream license notice:

```text
MIT License

Copyright (c) 2026

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

UBox and Ubia names identify interoperable products. This project is independent
and is intended for use with owned or explicitly authorized devices. No vendor
app, library, firmware, decompiled code listing, media or packet capture is
included in this distribution.
