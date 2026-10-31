package main

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"time"
)

func allowedRelay(addr *net.UDPAddr, relays []*net.UDPAddr) bool {
	for _, r := range relays {
		if sameAddr(addr, r) {
			return true
		}
	}
	return false
}
func relayHostPort(value string) (string, int, error) {
	host := value
	port := 20001
	if strings.Contains(value, ":") {
		h, p, e := net.SplitHostPort(value)
		if e != nil {
			return "", 0, errors.New("relay_argument_invalid")
		}
		n, e := strconv.Atoi(p)
		if e != nil || n < 1 || n > 65535 {
			return "", 0, errors.New("relay_argument_invalid")
		}
		host, port = h, n
	}
	if host == "" || strings.ContainsAny(host, "/\\\r\n\t ") {
		return "", 0, errors.New("relay_argument_invalid")
	}
	return host, port, nil
}
func resolveSingleRelay(ctx context.Context, value string) ([]*net.UDPAddr, error) {
	host, port, e := relayHostPort(value)
	if e != nil {
		return nil, e
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip.To4() == nil {
			return nil, errors.New("relay_requires_ipv4")
		}
		return []*net.UDPAddr{{IP: ip.To4(), Port: port}}, nil
	}
	lookup, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	ips, e := net.DefaultResolver.LookupIP(lookup, "ip4", host)
	if e != nil || len(ips) == 0 {
		return nil, errors.New("relay_resolution_failed")
	}
	out := []*net.UDPAddr{}
	for _, ip := range ips {
		if ip.To4() != nil {
			out = append(out, &net.UDPAddr{IP: ip.To4(), Port: port})
		}
	}
	if len(out) == 0 {
		return nil, errors.New("relay_resolution_failed")
	}
	return out, nil
}
