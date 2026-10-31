// Experimental UBox relay -> raw video stdout bridge; see README.md.
package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

type camera struct {
	RDTSample      io.Writer     `json:"-"`
	UID            string        `json:"uid"`
	Password       string        `json:"password"`
	LocalIP        net.IP        `json:"-"`
	InitialTimeout time.Duration `json:"-"`
	Relay          string        `json:"-"`
}
type configEntry struct {
	ID     string `json:"entry_id"`
	Domain string `json:"domain"`
	Title  string `json:"title"`
	Data   camera `json:"data"`
}

func loadCamera(root, id, title string) (camera, error) {
	var store struct {
		Data struct {
			Entries []configEntry `json:"entries"`
		} `json:"data"`
	}
	b, e := os.ReadFile(filepath.Join(root, ".storage", "core.config_entries"))
	if e != nil {
		return camera{}, errors.New("config_read_failed")
	}
	if json.Unmarshal(b, &store) != nil {
		return camera{}, errors.New("config_json_invalid")
	}
	var matches []camera
	for _, entry := range store.Data.Entries {
		if entry.Domain == "ubox_p4p" && ((id != "" && entry.ID == id) || (title != "" && entry.Title == title)) {
			matches = append(matches, entry.Data)
		}
	}
	if len(matches) != 1 {
		return camera{}, errors.New("camera_selection_not_unique")
	}
	c := matches[0]
	if c.UID == "" || c.Password == "" {
		return camera{}, errors.New("camera_credentials_missing")
	}
	for _, s := range []string{c.UID, c.Password} {
		for _, b := range []byte(s) {
			if b > 127 {
				return camera{}, errors.New("camera_credentials_non_ascii")
			}
		}
	}
	return c, nil
}

var relayHosts = []string{"172.111.37.9", "38.60.221.99", "51.195.255.1", "170.101.97.156", "149.56.108.231", "43.173.75.192", "45.125.216.146", "170.101.97.155", "51.222.110.215", "49.51.188.113", "43.156.14.205", "a1.ubianet.com", "a2.ubianet.com", "a3.ubianet.com", "a4.ubianet.com", "a5.ubianet.com", "a6.ubianet.com"}

func resolveRelays(ctx context.Context) []*net.UDPAddr {
	var out []*net.UDPAddr
	for _, host := range relayHosts {
		if ctx.Err() != nil {
			break
		}
		if ip := net.ParseIP(host); ip != nil {
			out = append(out, &net.UDPAddr{IP: ip, Port: 20001})
			continue
		}
		lookup, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
		ips, _ := net.DefaultResolver.LookupIP(lookup, "ip4", host)
		cancel()
		for _, ip := range ips {
			out = append(out, &net.UDPAddr{IP: ip, Port: 20001})
		}
	}
	return out
}
func localIP() net.IP {
	c, e := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(8, 8, 8, 8), Port: 80})
	if e != nil {
		return net.IPv4zero
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).IP
}
func sendAll(ctx context.Context, s *net.UDPConn, relays []*net.UDPAddr, b []byte) {
	for _, a := range relays {
		if ctx.Err() != nil {
			return
		}
		s.WriteToUDP(b, a)
	}
}
func waitResponse(ctx context.Context, s *net.UDPConn, relays []*net.UDPAddr, packet []byte, duration, interval time.Duration, explicitOnly bool) (*response, *net.UDPAddr) {
	deadline := time.Now().Add(duration)
	next := time.Time{}
	b := make([]byte, 65535)
	for ctx.Err() == nil && time.Now().Before(deadline) {
		if time.Now().After(next) {
			sendAll(ctx, s, relays, packet)
			next = time.Now().Add(interval)
		}
		s.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
		n, a, e := s.ReadFromUDP(b)
		if e != nil {
			if ne, ok := e.(net.Error); ok && ne.Timeout() {
				continue
			}
			return nil, nil
		}
		if !allowedRelay(a, relays) {
			continue
		}
		if r := parseResponse(b[:n]); r != nil && (!explicitOnly || !r.aliveAlias) {
			return r, a
		}
	}
	return nil, nil
}
func sameAddr(a, b *net.UDPAddr) bool { return a.Port == b.Port && a.IP.Equal(b.IP) }
func writeFull(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, e := w.Write(b)
		if e != nil {
			return e
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		b = b[n:]
	}
	return nil
}

func receive(ctx context.Context, s *net.UDPConn, addr *net.UDPAddr, r *response, out io.Writer, duration, inactivity, initialTimeout time.Duration, kcpEncoding string, stats map[string]uint64, rdtSample io.Writer) error {
	w := newWindow(r.conv)
	diagnostics := packetDiagnostics{}
	if r.aliveAlias {
		diagnostics.aliveConvs = map[uint32]bool{r.conv: true}
	}
	p := rdtParser{stats: stats, sample: rdtSample, verifyCRC: r.native != nil}
	started := time.Now()
	lastVideo, lastKeepalive, lastRetry := started, started, started
	retries := 0
	b := make([]byte, 65535)
	keepalive := bind(r)
	defer func() {
		for k, v := range w.stats {
			stats[k] += v
		}
		stats["start_unacknowledged"] = uint64(len(w.start))
		stats["pending_segments"] = uint64(len(w.pending))
		stats["pending_bytes"] = uint64(w.size)
		stats["rdt_pending_bytes"] = uint64(len(p.buffer))
		stats["resync_bytes"] = p.resync
		stats["elapsed_ms"] = uint64(time.Since(started).Milliseconds())
	}()
	for ctx.Err() == nil {
		now := time.Now()
		if duration > 0 && now.Sub(started) >= duration {
			stats["duration_limit"]++
			return nil
		}
		videoTimeout := inactivity
		if stats["video_units"] == 0 {
			videoTimeout = initialTimeout
		}
		if now.Sub(lastVideo) >= videoTimeout {
			stats["inactivity_timeout"]++
			return errors.New("video_inactivity")
		}
		if now.Sub(lastKeepalive) >= time.Second {
			if _, e := s.WriteToUDP(keepalive, addr); e != nil {
				return errors.New("keepalive_failed")
			}
			lastKeepalive = now
		}
		if len(w.start) > 0 && retries < 8 && now.Sub(lastRetry) >= 500*time.Millisecond {
			var raw []byte
			for _, seg := range startSegments(r.conv) {
				if w.start[seg.sn] {
					raw = append(raw, seg.pack()...)
				}
			}
			if _, e := s.WriteToUDP(wrapKCP(raw, r, kcpEncoding), addr); e != nil {
				return errors.New("start_retry_failed")
			}
			lastRetry = now
			retries++
			stats["start_retries"]++
		}
		s.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
		n, source, e := s.ReadFromUDP(b)
		if e != nil {
			if ne, ok := e.(net.Error); ok && ne.Timeout() {
				continue
			}
			return errors.New("socket_read_failed")
		}
		selected := sameAddr(source, addr)
		plain := diagnostics.observe(b[:n], selected, r.conv, stats)
		if !selected {
			stats["other_source"]++
			if source.IP.Equal(addr.IP) {
				stats["other_source_same_ip"]++
			}
			continue
		}
		stats["datagrams"]++
		if len(plain) < 16 || le.Uint32(plain) != magic || le.Uint32(plain[8:]) != msgVideo {
			continue
		}
		segments, e := parseSegments(plain[16:])
		if e != nil {
			stats["malformed_datagrams"]++
			continue
		}
		ordered, replies := w.accept(segments)
		for i := 0; i < len(replies); i += 40 {
			end := i + 40
			if end > len(replies) {
				end = len(replies)
			}
			var raw []byte
			for _, reply := range replies[i:end] {
				raw = append(raw, reply...)
			}
			packet := wrapKCP(raw, r, kcpEncoding)
			if _, e := s.WriteToUDP(packet, addr); e != nil {
				return errors.New("ack_send_failed")
			}
		}
		videos, e := p.feed(ordered)
		if e != nil {
			return e
		}
		for _, v := range videos {
			if e := writeFull(out, v); e != nil {
				return errors.New("video_output_failed")
			}
			stats["video_units"]++
			stats["video_bytes"] += uint64(len(v))
			lastVideo = time.Now()
		}
	}
	stats["cancelled"]++
	return nil
}
func runAttempt(ctx context.Context, relays []*net.UDPAddr, c camera, out io.Writer, duration, inactivity time.Duration, kcpEncoding, handshake string, stats map[string]uint64) error {
	if handshake == "native" {
		return runNativeAttempt(ctx, relays, c, out, duration, inactivity, stats)
	}
	if ctx.Err() != nil {
		return nil
	}
	s, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	if e != nil {
		return errors.New("socket_open_failed")
	}
	defer s.Close()
	tag := make([]byte, 8)
	if _, e = rand.Read(tag); e != nil {
		return errors.New("random_failed")
	}
	ip := c.LocalIP
	if ip == nil {
		ip = localIP()
	}
	port := s.LocalAddr().(*net.UDPAddr).Port
	sendAll(ctx, s, relays, login(c.UID, c.Password, tag[:4], ip, port, false))
	r, addr := waitResponse(ctx, s, relays, knock(c.UID), 2*time.Second, 50*time.Millisecond, false)
	if (r == nil || handshake != "original") && ctx.Err() == nil {
		if handshake != "original" {
			stats["handshake_drained"] += uint64(drainSocket(s))
		}
		if handshake != "original" {
			r, addr = waitFreshResponse(ctx, s, relays, login(c.UID, c.Password, tag[:4], ip, port, true), handshake == "fresh-alive", stats)
		} else {
			r, addr = waitResponse(ctx, s, relays, login(c.UID, c.Password, tag[:4], ip, port, true), 3*time.Second, 700*time.Millisecond, false)
		}
	}
	if ctx.Err() != nil {
		return nil
	}
	if r == nil {
		return errors.New("relay_response_timeout")
	}
	for index, candidate := range relays {
		if sameAddr(addr, candidate) {
			stats["relay_candidate_index"] = uint64(index + 1)
			break
		}
	}
	if r.aliveAlias {
		stats["response_alive_alias"] = 1
	} else {
		stats["response_alive_alias"] = 0
	}
	defer func() {
		packet := logout(r)
		for i := 0; i < 3; i++ {
			s.WriteToUDP(packet, addr)
		}
	}()
	if _, e = s.WriteToUDP(bind(r), addr); e != nil {
		return errors.New("relay_bind_failed")
	}
	if handshake == "fresh-alive" {
		previous := r
		r = confirmBoundAlive(ctx, s, addr, r, stats)
		if ctx.Err() != nil {
			return nil
		}
		if r != previous {
			stats["response_alive_alias"] = 1
			if _, e = s.WriteToUDP(bind(r), addr); e != nil {
				return errors.New("relay_rebind_failed")
			}
		}
	}
	var start []byte
	for _, seg := range startSegments(r.conv) {
		start = append(start, seg.pack()...)
	}
	if _, e = s.WriteToUDP(wrapKCP(start, r, kcpEncoding), addr); e != nil {
		return errors.New("start_send_failed")
	}
	initialTimeout := c.InitialTimeout
	if initialTimeout <= 0 {
		initialTimeout = 15 * time.Second
	}
	return receive(ctx, s, addr, r, out, duration, inactivity, initialTimeout, kcpEncoding, stats, c.RDTSample)
}

// stdout is exclusively RDT video payloads. All operational failures are fixed
// codes: never include OS errors, config content, UID, password or camera title.
func main() { os.Exit(cli()) }
func cli() int {
	signal.Ignore(syscall.SIGPIPE)
	fs := flag.NewFlagSet("ubox-relay-bridge", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	root := fs.String("config-root", "/config", "Home Assistant config root")
	id := fs.String("entry-id", "", "exact ubox_p4p entry ID")
	title := fs.String("camera", "", "exact ubox_p4p entry title")
	duration := fs.Duration("duration", 0, "optional session duration, e.g. 30s")
	initialTimeout := fs.Duration("initial-timeout", 15*time.Second, "maximum time without first complete video unit")
	inactivity := fs.Duration("inactivity-timeout", 10*time.Second, "maximum time without complete video unit")
	relay := fs.String("relay", "", "optional single relay IPv4 or hostname, optionally host:port")
	localAddress := fs.String("local-ip", "", "optional advertised IPv4 override; default uses route-selected address")
	preferAlive := fs.Bool("prefer-alive", true, "prefer same-relay alive response after explicit fresh handshake")
	handshake := fs.String("handshake", "fresh", "relay handshake: fresh explicit request or original wake response")
	nativeHandshake := fs.Bool("native-handshake", false, "experimental strictly matched native 1206 handshake")
	kcpEncoding := fs.String("kcp-encoding", "legacy", "outgoing KCP envelope: plain or legacy")
	statsPath := fs.String("stats-file", "", "optional redacted JSON statistics file")
	samplePath := fs.String("sample-file", "", "optional raw-video copy (sensitive camera content)")
	rdtSamplePath := fs.String("rdt-sample-file", "", "optional first ten full RDT frames, capped at 2 MB (sensitive camera content)")
	if fs.Parse(os.Args[1:]) != nil {
		return 2
	}
	if fs.NArg() != 0 || (*id == "") == (*title == "") || *duration < 0 || *inactivity <= 0 || *initialTimeout <= 0 || (*kcpEncoding != "plain" && *kcpEncoding != "legacy") || (*handshake != "fresh" && *handshake != "original") {
		fmt.Fprintln(os.Stderr, "invalid_arguments: choose exactly one --entry-id or --camera")
		return 2
	}
	c, e := loadCamera(*root, *id, *title)
	if e != nil {
		fmt.Fprintln(os.Stderr, e.Error())
		return 1
	}
	c.InitialTimeout = *initialTimeout
	if *rdtSamplePath != "" {
		f, err := os.OpenFile(*rdtSamplePath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			fmt.Fprintln(os.Stderr, "rdt_sample_file_open_failed")
			return 1
		}
		defer f.Close()
		c.RDTSample = f
	}
	c.Relay = *relay
	if *localAddress != "" {
		c.LocalIP = net.ParseIP(*localAddress).To4()
		if c.LocalIP == nil {
			fmt.Fprintln(os.Stderr, "invalid_local_ip")
			return 2
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var out io.Writer = os.Stdout
	// A blocked stdout pipe must not prevent SIGTERM cleanup. Closing the file
	// unblocks a pending write, while the UDP socket remains open for logout.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			os.Stdout.Close()
		case <-done:
		}
	}()
	var sample *os.File
	if *samplePath != "" {
		sample, e = os.OpenFile(*samplePath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e != nil {
			fmt.Fprintln(os.Stderr, "sample_file_open_failed")
			return 1
		}
		defer sample.Close()
		out = io.MultiWriter(os.Stdout, sample)
	}
	stats := map[string]uint64{}
	effectiveHandshake := *handshake
	if *nativeHandshake {
		effectiveHandshake = "native"
	}
	if effectiveHandshake == "fresh" && *preferAlive {
		effectiveHandshake = "fresh-alive"
	}
	e = run(ctx, c, out, *duration, *inactivity, *kcpEncoding, effectiveHandshake, stats)
	if ctx.Err() != nil {
		e = nil
	}
	result := struct {
		Stats              map[string]uint64 `json:"stats"`
		Error              string            `json:"error,omitempty"`
		Experimental       bool              `json:"experimental"`
		ResponseAliveAlias bool              `json:"response_alive_alias"`
	}{stats, "", true, stats["response_alive_alias"] == 1}
	if e != nil {
		result.Error = e.Error()
	}
	encoded, _ := json.Marshal(result)
	fmt.Fprintln(os.Stderr, string(encoded))
	if *statsPath != "" {
		f, err := os.OpenFile(*statsPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			fmt.Fprintln(os.Stderr, "stats_file_write_failed")
			return 1
		}
		_, err = f.Write(append(encoded, '\n'))
		closeErr := f.Close()
		if err != nil || closeErr != nil {
			fmt.Fprintln(os.Stderr, "stats_file_write_failed")
			return 1
		}
	}
	if e != nil {
		return 1
	}
	return 0
}
