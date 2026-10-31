package main

import (
	"bytes"
	"net"
	"testing"
)

func TestNativeLoginCredentialBounds(t *testing.T) {
	for _, stream := range []bool{false, true} {
		b := decode(nativeLogin(camera{UID: "test-uid", Password: "12345678901234567890"}, []byte{1, 2, 3, 4}, net.IPv4(192, 0, 2, 1), 20001, stream))
		if len(b) != 124 || string(b[60:80]) != "12345678901234567890" || string(b[92:97]) != "admin" || !bytes.Equal(b[97:108], make([]byte, 11)) {
			t.Fatal("native credential bounds mismatch")
		}
		if b[16] != 1 || b[17] != 0 || b[18] != 6 || b[19] != 1 || b[82] != 1 || !bytes.Equal(b[88:92], []byte{1, 2, 3, 4}) {
			t.Fatal("native request identity mismatch")
		}
	}
}

// Synthetic fixtures encode only independently recovered native offsets.
// They are not captures and carry no camera identifiers or credentials.
func nativeResponseFixture() []byte {
	b := make([]byte, 40+2*428)
	le.PutUint32(b, magic)
	le.PutUint16(b[4:], uint16(len(b)-16))
	le.PutUint32(b[8:], 0x00421206)
	b[16], b[19] = 2, 7
	// First record deliberately belongs to another client.
	b[40+30] = 99
	r := b[40+428:]
	r[30], r[31] = 3, 9
	le.PutUint16(r[32:], 0x1234)
	le.PutUint16(r[34:], 0x5678)
	le.PutUint32(r[36:], 0xdeadbeef)
	return b
}

func TestNativeResponseSelection(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		b := nativeResponseFixture()
		if encrypted {
			b = transform(b, false)
		}
		r := parseNativeResponse(b, 3, 0xdeadbeef, 7)
		if r == nil || r.clientSID != 3 || r.serverSID != 9 || r.routeA != 0x1234 || r.routeB != 0x5678 || r.randomID != 0xdeadbeef {
			t.Fatalf("native record selection failed, encoded=%v: %+v", encrypted, r)
		}
	}
}

func TestNativeResponseRejectsUnrelatedAndTruncated(t *testing.T) {
	cases := map[string]func([]byte) []byte{
		"liveness alias":   func(b []byte) []byte { le.PutUint32(b[8:], 0x00421406); return b },
		"wrong random tag": func(b []byte) []byte { b[40+428+36] ^= 1; return b },
		"wrong SID":        func(b []byte) []byte { b[40+428+30]++; return b },
		"wrong sequence":   func(b []byte) []byte { b[19]++; return b },
		"failed status":    func(b []byte) []byte { le.PutUint16(b[40+428:], 0xffff); return b },
		"truncated record": func(b []byte) []byte { return b[:len(b)-1] },
		"too many records": func(b []byte) []byte { b[16] = 17; return b },
		"no records":       func(b []byte) []byte { b[16] = 0; return b },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			if parseNativeResponse(mutate(nativeResponseFixture()), 3, 0xdeadbeef, 7) != nil {
				t.Fatal("accepted unrelated or malformed response")
			}
		})
	}
	for n := 0; n < 40; n++ {
		if parseNativeResponse(nativeResponseFixture()[:n], 3, 0xdeadbeef, 7) != nil {
			t.Fatalf("accepted short header %d", n)
		}
	}
}

func TestNativeResponseUnspecifiedSequence(t *testing.T) {
	b := nativeResponseFixture()
	b[19] = 0
	if parseNativeResponse(b, 3, 0xdeadbeef, 7) == nil {
		t.Fatal("native unspecified sequence rejected")
	}
}

func TestNativeDiagnosticsBounds(t *testing.T) {
	d := nativeHandshakeDiagnostics{}
	s := map[string]uint64{}
	for i := 0; i < 100; i++ {
		b := make([]byte, 16)
		le.PutUint32(b, magic)
		le.PutUint32(b[8:], uint32(i))
		d.observe(b, "wake", s)
	}
	if len(d.types) != 16 || s["native_message_type_overflow"] != 84 || s["native_datagrams_wake"] != 100 || s["native_min_length"] != 16 || s["native_max_length"] != 16 {
		t.Fatal("diagnostic cap or aggregate mismatch")
	}
	d.observe([]byte{1, 2}, "stream", s)
	if s["native_invalid_envelope"] != 1 || s["native_min_length"] != 2 {
		t.Fatal("invalid datagram was not counted")
	}
}

func TestNativeWakeFirstRecordOnly(t *testing.T) {
	b := make([]byte, 57)
	le.PutUint32(b, magic)
	le.PutUint32(b[8:], 0x00421202)
	b[16] = 2
	fixed(b[36:56], "test-uid")
	b[56] = 2
	if status, ok := parseNativeWake(b, "test-uid"); !ok || status != 2 {
		t.Fatal("valid first wake record rejected")
	}
	if _, ok := parseNativeWake(b, "different-uid"); ok {
		t.Fatal("unrelated UID accepted")
	}
	if _, ok := parseNativeWake(b[:56], "test-uid"); ok {
		t.Fatal("truncated wake accepted")
	}
	b[16] = 17
	if _, ok := parseNativeWake(b, "test-uid"); ok {
		t.Fatal("invalid count accepted")
	}
}

func TestNativeBindOffsets(t *testing.T) {
	s := &nativeSession{3, 9, 0x1234, 0x5678, 0xdeadbeef}
	b := decode(nativeBind(s))
	want := []byte{
		0x07, 0x18, 0x10, 0x00, 0x14, 0x00, 0x03, 0x00,
		0x05, 0x14, 0x24, 0x00, 0x78, 0x56, 0x00, 0x00,
		0x00, 0x03, 0x09, 0x00, 0x34, 0x12, 0x78, 0x56,
		0xef, 0xbe, 0xad, 0xde, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
	}
	if !bytes.Equal(b, want) {
		t.Fatalf("bind wire mismatch: %x", b)
	}
}

func TestNativeKCPEnvelopeOffsetsAndLimit(t *testing.T) {
	s := &nativeSession{3, 9, 0x1234, 0x5678, 0xdeadbeef}
	b := decode(nativeWrapKCP([]byte{0xaa, 0xbb}, s, 2))
	want := []byte{0x07, 0x18, 0x10, 0x00, 0x02, 0x00, 0x09, 0x00,
		0x09, 0x14, 0x24, 0x00, 0x78, 0x56, 0x02, 0x00, 0xaa, 0xbb}
	if !bytes.Equal(b, want) {
		t.Fatalf("KCP wire mismatch: %x", b)
	}
	if nativeWrapKCP(make([]byte, 1400), s, 0) == nil {
		t.Fatal("valid native maximum rejected")
	}
	if nativeWrapKCP(make([]byte, 1401), s, 0) != nil {
		t.Fatal("oversized native payload accepted")
	}
}

func TestNativeLogoutOffsets(t *testing.T) {
	s := &nativeSession{3, 9, 0x1234, 0x5678, 0xdeadbeef}
	b := decode(nativeLogout(s, 7))
	if len(b) != 100 || le.Uint32(b) != magic || le.Uint16(b[4:]) != 84 || le.Uint16(b[6:]) != 9 || le.Uint32(b[8:]) != 0x00241207 || le.Uint16(b[12:]) != 0x5678 || b[16] != 1 || b[17] != 7 || b[74] != 3 || b[75] != 9 || le.Uint16(b[76:]) != 0x1234 || le.Uint16(b[78:]) != 0x5678 || le.Uint32(b[80:]) != 0xdeadbeef {
		t.Fatal("native logout field mismatch")
	}
	for _, span := range [][]byte{b[18:74], b[84:]} {
		for _, v := range span {
			if v != 0 {
				t.Fatal("unexpected uninitialized logout field")
			}
		}
	}
}
