package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPythonGolden(t *testing.T) {
	b, e := os.ReadFile("golden.json")
	if e != nil {
		t.Fatal(e)
	}
	var golden map[string]string
	if e = json.Unmarshal(b, &golden); e != nil {
		t.Fatal(e)
	}
	input := make([]byte, 47)
	for i := range input {
		input[i] = byte(i)
	}
	tag := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	cases := map[string][]byte{"transform": transform(input, false), "knock": knock("TEST-UID-123"), "login": login("TEST-UID-123", "fake-password", tag, net.ParseIP("192.0.2.10"), 34567, false), "request": login("TEST-UID-123", "fake-password", tag[:4], net.ParseIP("192.0.2.10"), 34567, true)}
	for name, actual := range cases {
		if hex.EncodeToString(actual) != golden[name] {
			t.Errorf("%s differs from Python", name)
		}
	}
	if !bytes.Equal(transform(transform(input, false), true), input) {
		t.Fatal("roundtrip")
	}
}
func TestKCPReorderDuplicateACK(t *testing.T) {
	w := newWindow(7)
	data, replies := w.accept([]segment{{conv: 7, cmd: push, sn: 1, ts: 10, data: []byte("B")}})
	if len(data) != 0 {
		t.Fatal("premature output")
	}
	segments, e := parseSegments(replies[0])
	if e != nil || segments[0].una != 0 || segments[0].ts != 10 {
		t.Fatal("ACK timestamp/UNA")
	}
	data, replies = w.accept([]segment{{conv: 7, cmd: push, sn: 1, ts: 11, data: []byte("B")}, {conv: 7, cmd: push, sn: 0, ts: 12, data: []byte("A")}})
	if string(data) != "AB" || len(replies) != 2 {
		t.Fatal("reorder")
	}
	for _, raw := range replies {
		s, _ := parseSegments(raw)
		if s[0].una != 2 {
			t.Fatal("UNA")
		}
	}
	data, _ = w.accept([]segment{{conv: 7, cmd: push, sn: 0, data: []byte("A")}})
	if len(data) != 0 || w.stats["duplicates"] != 2 {
		t.Fatal("duplicate")
	}
}
func TestKCPWrapBoundsAndProbe(t *testing.T) {
	w := newWindow(9)
	w.next = 0xffffffff
	data, _ := w.accept([]segment{{conv: 9, cmd: push, sn: 0, data: []byte("B")}, {conv: 9, cmd: push, sn: 0xffffffff, data: []byte("A")}})
	if string(data) != "AB" || w.next != 1 {
		t.Fatal("wrap")
	}
	w = newWindow(9)
	for sn := uint32(1); sn < 512; sn++ {
		w.accept([]segment{{conv: 9, cmd: push, sn: sn, data: make([]byte, 65535)}})
	}
	if w.size > maxPending-65535 || w.stats["buffer_drops"] == 0 {
		t.Fatal("buffer bound/reserve")
	}
	_, reply := w.accept([]segment{{conv: 9, cmd: wask}})
	s, _ := parseSegments(reply[0])
	if s[0].cmd != wins {
		t.Fatal("probe")
	}
	w.accept([]segment{{conv: 9, cmd: push, sn: 512, data: []byte("x")}})
	if w.stats["outside_window"] != 1 {
		t.Fatal("window")
	}
	w.accept([]segment{{conv: 9, cmd: ack, sn: 1, una: 3}})
	if len(w.start) != 0 {
		t.Fatal("start acknowledged")
	}
}
func TestWireInvalidAndRDT(t *testing.T) {
	s := segment{conv: 1, cmd: push, data: []byte("abc")}
	b := s.pack()
	if _, e := parseSegments(b[:len(b)-1]); e == nil {
		t.Fatal("truncation")
	}
	b = make([]byte, 35)
	le.PutUint32(b, 0x11)
	le.PutUint32(b[8:], 19)
	copy(b[32:], []byte("abc"))
	p := rdtParser{}
	v, e := p.feed(b[:33])
	if e != nil || len(v) != 0 {
		t.Fatal("partial")
	}
	v, e = p.feed(append(b[33:], b...))
	if e != nil || len(v) != 2 || string(v[0]) != "abc" {
		t.Fatal("rdt")
	}
}
func TestConfigSelection(t *testing.T) {
	root := t.TempDir()
	os.Mkdir(filepath.Join(root, ".storage"), 0700)
	config := `{"data":{"entries":[{"domain":"ubox_p4p","entry_id":"id1","title":"Camera A","data":{"uid":"test","password":"fake"}},{"domain":"other","entry_id":"id2","title":"Camera A","data":{}}]}}`
	os.WriteFile(filepath.Join(root, ".storage", "core.config_entries"), []byte(config), 0600)
	for _, selector := range [][2]string{{"id1", ""}, {"", "Camera A"}} {
		c, e := loadCamera(root, selector[0], selector[1])
		if e != nil || c.UID != "test" {
			t.Fatal("selection")
		}
	}
	if _, e := loadCamera(root, "missing", ""); e == nil {
		t.Fatal("missing selection")
	}
}

func TestOutgoingKCPEncoding(t *testing.T) {
	r := &response{routing: []byte{1, 2}, conv: 7}
	raw := startSegments(7)[0].pack()
	plain := wrapKCP(raw, r, "plain")
	legacy := wrapKCP(raw, r, "legacy")
	if bytes.Equal(plain, legacy) || !bytes.Equal(decode(legacy), plain) {
		t.Fatal("KCP envelope transform")
	}
	s, e := parseSegments(decode(legacy)[16:])
	if e != nil || s[0].ts != 0 || s[0].sn != 0 {
		t.Fatal("start timestamp changed")
	}
}

func TestOtherSourceDiagnosticsNoAcceptance(t *testing.T) {
	d := packetDiagnostics{}
	stats := map[string]uint64{}
	r := &response{routing: []byte{1, 2}}
	video := func(conv uint32) []byte {
		b := wrap(segment{conv: conv, cmd: push, sn: 0, data: []byte("not consumed")}.pack(), r)
		le.PutUint32(b[8:], msgVideo)
		return transform(b, false)
	}
	d.observe(video(9), false, 9, stats)
	d.observe(video(10), false, 9, stats)
	d.observe(video(9), true, 9, stats)
	if stats["other_source_video_msg"] != 2 || stats["other_source_video_matching_conv"] != 1 || stats["other_source_video_matching_push"] != 1 || stats["selected_source_video_msg"] != 1 {
		t.Fatal("classification", stats)
	}
	// observe is diagnostics only and has no ReceiveWindow / output side effect.
	for i := uint32(0); i < 100; i++ {
		b := make([]byte, 16)
		le.PutUint32(b, magic)
		le.PutUint32(b[8:], i)
		d.observe(b, false, 9, stats)
	}
	if len(d.messageTypes) > 16 || stats["message_type_overflow"] == 0 {
		t.Fatal("unbounded message types")
	}
	b := make([]byte, 17)
	le.PutUint32(b, magic)
	le.PutUint32(b[8:], msgVideo)
	d.observe(b, false, 9, stats)
	if stats["other_source_video_malformed_kcp"] != 1 {
		t.Fatal("malformed diagnosis")
	}
}
func TestRelayResponseAlias(t *testing.T) {
	for _, typ := range []uint32{0x00421206, 0x00421406} {
		b := make([]byte, 36)
		le.PutUint32(b, magic)
		le.PutUint32(b[8:], typ)
		le.PutUint32(b[24:], 123)
		r := parseResponse(transform(b, false))
		if r == nil || r.conv != 123 || r.aliveAlias != (typ == 0x00421406) {
			t.Fatal("response alias")
		}
	}
}

func TestRetryBoundAndSharedOutput(t *testing.T) {
	stats := map[string]uint64{}
	calls := 0
	out := &bytes.Buffer{}
	fake := func(ctx context.Context, r []*net.UDPAddr, c camera, w io.Writer, d, g time.Duration, enc, hs string, one map[string]uint64) error {
		calls++
		if d != 0 || g != 10*time.Second || hs != "fresh" {
			t.Fatal("attempt options")
		}
		one["video_units"] = 1
		one["start_unacknowledged"] = uint64(4 - calls)
		w.Write([]byte{byte(calls)})
		return errors.New("video_inactivity")
	}
	e := retrySessions(context.Background(), nil, camera{}, out, 0, 10*time.Second, "legacy", "fresh", stats, fake, 0)
	if e == nil || calls != 3 || stats["session_attempts"] != 3 || stats["video_units"] != 3 || stats["start_unacknowledged"] != 1 || !bytes.Equal(out.Bytes(), []byte{1, 2, 3}) {
		t.Fatal("retry policy", stats)
	}
}
func TestRetryOutputFailureAndCancellation(t *testing.T) {
	for _, mode := range []string{"output", "cancel", "success"} {
		ctx, cancel := context.WithCancel(context.Background())
		calls := 0
		stats := map[string]uint64{}
		fake := func(context.Context, []*net.UDPAddr, camera, io.Writer, time.Duration, time.Duration, string, string, map[string]uint64) error {
			calls++
			if mode == "cancel" {
				cancel()
				return errors.New("video_inactivity")
			}
			if mode == "success" {
				return nil
			}
			return errors.New("video_output_failed")
		}
		e := retrySessions(ctx, nil, camera{}, io.Discard, 0, time.Second, "legacy", "fresh", stats, fake, 0)
		cancel()
		if calls != 1 || (mode == "output" && e == nil) || (mode != "output" && e != nil) {
			t.Fatal("stop policy", mode, e, calls)
		}
	}
}
func TestRetryTotalDuration(t *testing.T) {
	calls := 0
	stats := map[string]uint64{}
	fake := func(ctx context.Context, _ []*net.UDPAddr, _ camera, _ io.Writer, _ time.Duration, _ time.Duration, _, _ string, _ map[string]uint64) error {
		calls++
		<-ctx.Done()
		return ctx.Err()
	}
	e := retrySessions(context.Background(), nil, camera{}, io.Discard, time.Millisecond, time.Second, "legacy", "fresh", stats, fake, 0)
	if e != nil || calls != 1 || stats["duration_limit"] != 1 {
		t.Fatal("duration", e, stats)
	}
}

func TestAliveCandidateSelection(t *testing.T) {
	a := aliveCandidates{}
	addr := &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 20001}
	other := &net.UDPAddr{IP: net.ParseIP("192.0.2.2"), Port: 20001}
	explicit := &response{conv: 1}
	alive := &response{conv: 2, aliveAlias: true}
	stats := map[string]uint64{}
	a.remember(alive, other)
	if a.selectFor(explicit, addr, stats) != nil {
		t.Fatal("foreign relay alias selected")
	}
	a.remember(explicit, addr)
	if a.selectFor(explicit, addr, stats) != nil {
		t.Fatal("explicit treated as alias")
	}
	a.remember(alive, addr)
	if a.selectFor(explicit, addr, stats) != alive || stats["handshake_alive_conv_differs_explicit"] != 1 {
		t.Fatal("matching relay alias not selected")
	}
	for i := 0; i < 100; i++ {
		a.remember(alive, &net.UDPAddr{IP: net.IPv4(192, 0, 2, byte(i)), Port: 20002})
	}
	if len(a) > 32 {
		t.Fatal("unbounded candidates")
	}
}
func TestAliveControlMediaDiagnostic(t *testing.T) {
	d := packetDiagnostics{}
	stats := map[string]uint64{}
	control := make([]byte, 36)
	le.PutUint32(control, magic)
	le.PutUint32(control[8:], 0x00421406)
	le.PutUint32(control[24:], 42)
	d.observe(control, true, 7, stats)
	video := wrap(segment{conv: 42, cmd: push}.pack(), &response{})
	le.PutUint32(video[8:], msgVideo)
	d.observe(video, true, 7, stats)
	if stats["selected_source_alive_conv_differs_chosen"] != 1 || stats["selected_source_video_matches_alive_control"] != 1 || stats["selected_source_video_matching_conv"] != 0 {
		t.Fatal("alive/media conversation diagnostic", stats)
	}
}

func TestBoundResponseMetadataComparison(t *testing.T) {
	stats := map[string]uint64{}
	a := &response{conv: 1, routing: []byte{1}, payload: []byte{2}}
	b := &response{conv: 2, routing: []byte{1}, payload: []byte{3}, aliveAlias: true}
	compareBoundResponse(a, b, stats)
	if stats["postbind_conv_different"] != 1 || stats["postbind_routing_equal"] != 1 || stats["postbind_payload_different"] != 1 {
		t.Fatal("redacted metadata comparison", stats)
	}
}

func TestMalformedInnerBodyDiagnostic(t *testing.T) {
	d := packetDiagnostics{}
	stats := map[string]uint64{}
	inner := segment{conv: 7, cmd: push, data: []byte("synthetic")}.pack()
	outer := wrap(transform(inner, false), &response{})
	le.PutUint32(outer[8:], msgVideo)
	d.observe(outer, true, 7, stats)
	if stats["selected_source_video_malformed_kcp"] != 1 || stats["selected_source_malformed_inner_decode_valid_kcp"] != 1 || stats["selected_source_malformed_inner_decode_matches_chosen"] != 1 {
		t.Fatal("nested diagnostic", stats)
	}
}

func TestRelayScopeOffline(t *testing.T) {
	for _, value := range []string{"192.0.2.1", "relay.example", "192.0.2.1:23456"} {
		host, port, e := relayHostPort(value)
		if e != nil || host == "" || port == 0 {
			t.Fatal("relay argument")
		}
	}
	for _, value := range []string{"", "host:0", "host:65536", "host:bad", "https://relay.example", "host name"} {
		if _, _, e := relayHostPort(value); e == nil {
			t.Fatal("invalid relay accepted", value)
		}
	}
	relays, e := resolveSingleRelay(context.Background(), "192.0.2.1:20001")
	if e != nil || len(relays) != 1 {
		t.Fatal("literal relay resolution")
	}
	if !allowedRelay(&net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 20001}, relays) || allowedRelay(&net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 20002}, relays) || allowedRelay(&net.UDPAddr{IP: net.ParseIP("192.0.2.2"), Port: 20001}, relays) {
		t.Fatal("endpoint source filter")
	}
}
