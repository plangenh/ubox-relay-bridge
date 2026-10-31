package main

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

func nativeLogin(c camera, tag []byte, ip net.IP, port int, stream bool) []byte {
	b := decode(login(c.UID, c.Password, tag, ip, port, stream))
	b[16], b[17], b[18], b[19], b[82] = 1, 0, 6, 1, 1
	for i := 60; i < 80; i++ {
		b[i] = 0
	}
	fixed(b[60:80], c.Password)
	for i := 92; i < 108; i++ {
		b[i] = 0
	}
	fixed(b[92:108], "admin")
	return transform(b, false)
}

// Experimental native handshake is opt-in until its complete video path has
// been verified. A 1406 packet can never select its session.
func runNativeAttempt(ctx context.Context, relays []*net.UDPAddr, c camera, out io.Writer, duration, inactivity time.Duration, stats map[string]uint64) error {
	s, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	if e != nil {
		return errors.New("socket_open_failed")
	}
	defer s.Close()
	tag := make([]byte, 4)
	if _, e = rand.Read(tag); e != nil {
		return errors.New("random_failed")
	}
	ip := c.LocalIP
	if ip == nil {
		ip = localIP()
	}
	port := s.LocalAddr().(*net.UDPAddr).Port
	diagnostics := nativeHandshakeDiagnostics{}
	buf := make([]byte, 65535)
	var session *nativeSession
	var addr *net.UDPAddr
	var awakeAddr *net.UDPAddr
	read := func(phase string) {
		s.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
		n, source, err := s.ReadFromUDP(buf)
		if err != nil {
			return
		}
		diagnostics.observe(buf[:n], phase, stats)
		if !allowedRelay(source, relays) {
			stats["native_disallowed_source"]++
			return
		}
		nativeObserveStatus(buf[:n], le.Uint32(tag), stats)
		if status, ok := parseNativeWake(buf[:n], c.UID); ok {
			switch status {
			case 0:
				stats["native_wake_status0"]++
			case 1:
				stats["native_wake_status1"]++
			case 2:
				stats["native_wake_status2"]++
				if awakeAddr == nil {
					awakeAddr = source
				}
			case 3:
				stats["native_wake_status3"]++
			default:
				stats["native_wake_status_other"]++
			}
		}
		candidate := parseNativeResponse(buf[:n], 1, le.Uint32(tag), 1)
		if phase == "stream" && awakeAddr != nil && !sameAddr(source, awakeAddr) {
			stats["native_nonselected_response_source"]++
			return
		}
		if candidate != nil && session == nil {
			session = candidate
			addr = source
			stats["native_session_selected_"+phase]++
		}
	}
	deadline := time.Now().Add(10 * time.Second)
	nextWake := time.Time{}
	for ctx.Err() == nil && time.Now().Before(deadline) && session == nil && awakeAddr == nil {
		if time.Now().After(nextWake) {
			sendAll(ctx, s, relays, knock(c.UID))
			nextWake = time.Now().Add(500 * time.Millisecond)
		}
		read("wake")
	}
	if session == nil && awakeAddr == nil {
		if ctx.Err() != nil {
			return nil
		}
		return errors.New("native_wake_response_timeout")
	}
	request := nativeLogin(c, tag, ip, port, true)
	deadline = time.Now().Add(5 * time.Second)
	next := time.Time{}
	for ctx.Err() == nil && time.Now().Before(deadline) && session == nil {
		if time.Now().After(next) {
			s.WriteToUDP(request, awakeAddr)
			next = time.Now().Add(700 * time.Millisecond)
		}
		read("stream")
	}
	if session != nil {
		stats["native_session_matched"]++
		r := &response{native: session, conv: session.randomID}
		defer func() {
			for i := 0; i < 3; i++ {
				s.WriteToUDP(logout(r), addr)
			}
		}()
		if _, err := s.WriteToUDP(bind(r), addr); err != nil {
			return errors.New("relay_bind_failed")
		}
		var start []byte
		for _, seg := range startSegments(r.conv) {
			start = append(start, seg.pack()...)
		}
		if _, err := s.WriteToUDP(wrapKCP(start, r, "legacy"), addr); err != nil {
			return errors.New("start_send_failed")
		}
		initialTimeout := c.InitialTimeout
		if initialTimeout <= 0 {
			initialTimeout = 15 * time.Second
		}
		return receive(ctx, s, addr, r, out, duration, inactivity, initialTimeout, "legacy", stats, c.RDTSample)
	}
	if ctx.Err() != nil {
		return nil
	}
	return errors.New("native_relay_response_timeout")
}

func nativeObserveStatus(packet []byte, tag uint32, stats map[string]uint64) {
	b := decode(packet)
	if len(b) < 40 || le.Uint32(b) != magic || le.Uint32(b[8:]) != 0x00421206 || b[16] > 16 || len(b) < 40+int(b[16])*428 || (b[19] != 0 && b[19] != 1) {
		return
	}
	for i := 0; i < int(b[16]); i++ {
		r := b[40+i*428:]
		if r[30] != 1 || le.Uint32(r[36:]) != tag {
			continue
		}
		stats["native_records_matching_request"]++
		switch int16(le.Uint16(r)) {
		case 0:
			stats["native_status_success"]++
		case -2005:
			stats["native_status_minus2005"]++
		case -2010:
			stats["native_status_minus2010"]++
		default:
			stats["native_status_other"]++
		}
	}
}

// Observe every incoming datagram before source filtering. Only bounded type
// counts and aggregate lengths are retained; never packet bytes or addresses.
type nativeHandshakeDiagnostics struct{ types map[string]bool }

func (d *nativeHandshakeDiagnostics) observe(packet []byte, phase string, stats map[string]uint64) {
	stats["native_datagrams_"+phase]++
	n := uint64(len(packet))
	if stats["native_min_length"] == 0 || n < stats["native_min_length"] {
		stats["native_min_length"] = n
	}
	if n > stats["native_max_length"] {
		stats["native_max_length"] = n
	}
	b := decode(packet)
	if len(b) < 12 || le.Uint32(b) != magic {
		stats["native_invalid_envelope"]++
		return
	}
	typ := le.Uint32(b[8:])
	key := fmt.Sprintf("native_%s_msg_%08x", phase, typ)
	if d.types == nil {
		d.types = map[string]bool{}
	}
	if d.types[key] || len(d.types) < 16 {
		d.types[key] = true
		stats[key]++
	} else {
		stats["native_message_type_overflow"]++
	}
	if typ == 0x00421406 {
		stats["native_liveness_ignored"]++
	}
	if typ != 0x00421206 {
		return
	}
	stats["native_1206_packets"]++
	if stats["native_1206_min_length"] == 0 || n < stats["native_1206_min_length"] {
		stats["native_1206_min_length"] = n
	}
	if n > stats["native_1206_max_length"] {
		stats["native_1206_max_length"] = n
	}
	if len(b) >= 468 {
		stats["native_1206_full_length"]++
	}
}
