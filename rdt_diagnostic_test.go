package main

import (
	"bytes"
	"testing"
)

func TestNativeCRC32KnownVector(t *testing.T) {
	if got := nativeCRC32([]byte("123456789")); got != 0x2dfd2d88 {
		t.Fatalf("native raw CRC: %08x", got)
	}
	if nativeCRC32(nil) != 0 {
		t.Fatal("native zero seed changed for empty input")
	}
}

func diagnosticRDT() []byte {
	b := make([]byte, 36)
	le.PutUint32(b, 0x11)
	le.PutUint32(b[8:], 20)
	le.PutUint16(b[16:], 5)
	b[18] = 7
	b[19] = 2
	copy(b[32:], []byte{1, 2, 3, 4})
	le.PutUint32(b[12:], nativeCRC32(b[16:]))
	return b
}

func TestRDTDiagnosticsDoNotChangePayload(t *testing.T) {
	b := diagnosticRDT()
	stats := map[string]uint64{}
	var sample bytes.Buffer
	p := rdtParser{stats: stats, sample: &sample}
	out, err := p.feed(b)
	if err != nil || len(out) != 1 || !bytes.Equal(out[0], b[32:]) || !bytes.Equal(sample.Bytes(), b) || stats["rdt_crc_match"] != 1 || stats["rdt_codec_5"] != 1 || stats["rdt_cam_index_2"] != 1 {
		t.Fatal("RDT diagnostics mismatch")
	}
	b[35] ^= 1
	out, err = p.feed(b)
	if err != nil || len(out) != 1 || !bytes.Equal(out[0], b[32:]) || stats["rdt_crc_mismatch"] != 1 {
		t.Fatal("CRC diagnostics altered payload handling")
	}
	le.PutUint32(b[12:], 0)
	p.feed(b)
	if stats["rdt_crc_present"] != 2 {
		t.Fatal("absent CRC counted")
	}
}

func TestRDTSampleCapAcrossParsers(t *testing.T) {
	stats := map[string]uint64{}
	var sample bytes.Buffer
	b := diagnosticRDT()
	for i := 0; i < 12; i++ {
		p := rdtParser{stats: stats, sample: &sample}
		p.feed(b)
	}
	if stats["rdt_sample_frames"] != 10 || sample.Len() != 10*len(b) {
		t.Fatal("sample frame bound failed")
	}
	stats["rdt_sample_bytes"] = 1_999_999
	p := rdtParser{stats: stats, sample: &sample}
	stats["rdt_sample_frames"] = 0
	p.feed(b)
	if sample.Len() != 10*len(b) {
		t.Fatal("sample byte bound failed")
	}
}

func TestNativeMediaCRCEnforcement(t *testing.T) {
	b := diagnosticRDT()
	stats := map[string]uint64{}
	p := rdtParser{stats: stats, verifyCRC: true}
	out, err := p.feed(b)
	if err != nil || len(out) != 1 {
		t.Fatal("valid native CRC rejected")
	}
	b[35] ^= 1
	out, err = p.feed(b)
	if err != nil || len(out) != 0 || stats["rdt_crc_dropped"] != 1 {
		t.Fatal("corrupt video not dropped")
	}
	le.PutUint32(b[12:], 0)
	out, err = p.feed(b)
	if err != nil || len(out) != 1 {
		t.Fatal("optional zero CRC rejected")
	}
	bad := diagnosticRDT()
	bad[35] ^= 1
	out, err = p.feed(append(bad, diagnosticRDT()...))
	if err != nil || len(out) != 1 || !bytes.Equal(out[0], diagnosticRDT()[32:]) {
		t.Fatal("corrupt frame drop damaged following frame")
	}
	audio := diagnosticRDT()
	le.PutUint32(audio, 0x13)
	audio[35] ^= 1
	p.feed(audio)
	if stats["rdt_crc_dropped"] != 3 {
		t.Fatal("corrupt audio not checked")
	}
	control := diagnosticRDT()
	le.PutUint32(control, 3)
	le.PutUint32(control[12:], 0x12345678)
	before := stats["rdt_crc_present"]
	p.feed(control)
	if stats["rdt_crc_present"] != before || stats["rdt_crc_dropped"] != 3 {
		t.Fatal("control command misinterpreted as CRC")
	}
}
