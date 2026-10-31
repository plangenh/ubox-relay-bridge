package main

import (
	"context"
	"errors"
	"io"
	"net"
	"time"
)

// Drain only already queued replies, bounded even under continuous traffic.
// This reduces stale wake replies; it cannot establish request correlation
// because the inherited response layout has no validated session-tag echo.
func drainSocket(s *net.UDPConn) int {
	b := make([]byte, 65535)
	count := 0
	for count < 64 {
		s.SetReadDeadline(time.Now().Add(time.Millisecond))
		if _, _, e := s.ReadFromUDP(b); e != nil {
			break
		}
		count++
	}
	return count
}

type attemptFunc func(context.Context, []*net.UDPAddr, camera, io.Writer, time.Duration, time.Duration, string, string, map[string]uint64) error

func mergeStats(dst, src map[string]uint64) {
	for k, v := range src {
		switch k {
		case "start_unacknowledged", "pending_segments", "pending_bytes", "rdt_pending_bytes", "response_alive_alias", "relay_candidate_index":
			dst[k] = v
		default:
			dst[k] += v
		}
	}
}
func retrySessions(ctx context.Context, relays []*net.UDPAddr, c camera, out io.Writer, duration, inactivity time.Duration, kcpEncoding, handshake string, stats map[string]uint64, attempt attemptFunc, cooldown time.Duration) error {
	started := time.Now()
	if duration > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, duration)
		defer cancel()
	}
	var err error
	defer func() { stats["elapsed_ms"] = uint64(time.Since(started).Milliseconds()) }()
	for i := 0; i < 3; i++ {
		if ctx.Err() != nil {
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				stats["duration_limit"]++
			}
			return nil
		}
		one := map[string]uint64{}
		stats["session_attempts"]++
		err = attempt(ctx, relays, c, out, 0, inactivity, kcpEncoding, handshake, one)
		mergeStats(stats, one)
		if ctx.Err() != nil {
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				stats["duration_limit"]++
			}
			return nil
		}
		if err == nil {
			return nil
		}
		if err.Error() == "video_output_failed" {
			return err
		}
		stats["session_failures"]++
		if i == 2 {
			break
		}
		timer := time.NewTimer(cooldown)
		select {
		case <-ctx.Done():
			timer.Stop()
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				stats["duration_limit"]++
			}
			return nil
		case <-timer.C:
		}
	}
	return err
}
func run(ctx context.Context, c camera, out io.Writer, duration, inactivity time.Duration, kcpEncoding, handshake string, stats map[string]uint64) error {
	started := time.Now()
	if duration > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, duration)
		defer cancel()
	}
	// Resolve once; each attempt creates a fresh UDP socket and random tag.
	var relays []*net.UDPAddr
	if c.Relay != "" {
		var err error
		relays, err = resolveSingleRelay(ctx, c.Relay)
		if err != nil {
			return err
		}
		stats["relay_scope_single"] = 1
	} else {
		relays = resolveRelays(ctx)
	}
	err := retrySessions(ctx, relays, c, out, 0, inactivity, kcpEncoding, handshake, stats, runAttempt, 700*time.Millisecond)
	stats["elapsed_ms"] = uint64(time.Since(started).Milliseconds())
	return err
}
