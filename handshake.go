package main

import (
	"bytes"
	"context"
	"net"
	"time"
)

// Only full, valid alive responses from the exact selected explicit-response
// endpoint may replace its session fields. Never derive a conversation from
// media. Keep at most 32 candidate endpoints, without logging their addresses.
type aliveCandidates map[string]*response

func (a aliveCandidates) remember(r *response, addr *net.UDPAddr) {
	if r.aliveAlias && (a[addr.String()] != nil || len(a) < 32) {
		a[addr.String()] = r
	}
}
func (a aliveCandidates) selectFor(explicit *response, addr *net.UDPAddr, stats map[string]uint64) *response {
	r := a[addr.String()]
	if r == nil {
		return nil
	}
	stats["handshake_alive_selected"]++
	if r.conv == explicit.conv {
		stats["handshake_alive_conv_matches_explicit"]++
	} else {
		stats["handshake_alive_conv_differs_explicit"]++
	}
	return r
}
func waitFreshResponse(ctx context.Context, s *net.UDPConn, relays []*net.UDPAddr, packet []byte, preferAlive bool, stats map[string]uint64) (*response, *net.UDPAddr) {
	end := time.Now().Add(3 * time.Second)
	next := time.Time{}
	aliases := aliveCandidates{}
	var chosen *response
	var addr *net.UDPAddr
	buffer := make([]byte, 65535)
	for ctx.Err() == nil && time.Now().Before(end) {
		now := time.Now()
		if chosen == nil && now.After(next) {
			sendAll(ctx, s, relays, packet)
			next = now.Add(700 * time.Millisecond)
		}
		s.SetReadDeadline(now.Add(50 * time.Millisecond))
		n, source, e := s.ReadFromUDP(buffer)
		if e != nil {
			if ne, ok := e.(net.Error); ok && ne.Timeout() {
				continue
			}
			break
		}
		if !allowedRelay(source, relays) {
			stats["handshake_unlisted_source"]++
			continue
		}
		r := parseResponse(buffer[:n])
		if r == nil {
			continue
		}
		if r.aliveAlias {
			stats["handshake_alive_responses"]++
			aliases.remember(r, source)
			if chosen != nil && preferAlive {
				if alive := aliases.selectFor(chosen, addr, stats); alive != nil {
					return alive, addr
				}
			}
			continue
		}
		if chosen == nil {
			chosen, addr = r, source
			stats["handshake_explicit_responses"]++
			if !preferAlive {
				return chosen, addr
			}
			if alive := aliases.selectFor(chosen, addr, stats); alive != nil {
				return alive, addr
			}
			end = time.Now().Add(700 * time.Millisecond)
		}
	}
	if chosen != nil && preferAlive {
		stats["handshake_alive_wait_expired"]++
	}
	return chosen, addr
}

// Some explicit responses identify a control registration, while the bound
// alive response carries the media conversation. Confirm only via a full
// control response from the exact bound relay, before sending any start PUSH.
func confirmBoundAlive(ctx context.Context, s *net.UDPConn, addr *net.UDPAddr, explicit *response, stats map[string]uint64) *response {
	end := time.Now().Add(1500 * time.Millisecond)
	b := make([]byte, 65535)
	for ctx.Err() == nil && time.Now().Before(end) {
		s.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
		n, source, e := s.ReadFromUDP(b)
		if e != nil {
			if ne, ok := e.(net.Error); ok && ne.Timeout() {
				continue
			}
			break
		}
		if !sameAddr(source, addr) {
			stats["postbind_other_source"]++
			continue
		}
		r := parseResponse(b[:n])
		if r == nil || !r.aliveAlias {
			stats["postbind_other_message"]++
			continue
		}
		compareBoundResponse(explicit, r, stats)
		return r
	}
	stats["postbind_alive_wait_expired"]++
	return explicit
}
func compareBoundResponse(explicit, alive *response, stats map[string]uint64) {
	stats["postbind_alive_selected"]++
	if explicit.conv == alive.conv {
		stats["postbind_conv_equal"]++
	} else {
		stats["postbind_conv_different"]++
	}
	if bytes.Equal(explicit.routing, alive.routing) {
		stats["postbind_routing_equal"]++
	} else {
		stats["postbind_routing_different"]++
	}
	if bytes.Equal(explicit.payload, alive.payload) {
		stats["postbind_payload_equal"]++
	} else {
		stats["postbind_payload_different"]++
	}
}
