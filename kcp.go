package main

import (
	"errors"
	"fmt"
	"hash/crc32"
	"io"
)

const push = 81
const ack = 82
const wask = 83
const wins = 84
const receiveWindow = 512
const maxPending = 4_000_000

type segment struct {
	conv        uint32
	cmd, frg    byte
	wnd         uint16
	ts, sn, una uint32
	data        []byte
}

func (s segment) pack() []byte {
	b := make([]byte, 24+len(s.data))
	le.PutUint32(b, s.conv)
	b[4] = s.cmd
	b[5] = s.frg
	le.PutUint16(b[6:], s.wnd)
	le.PutUint32(b[8:], s.ts)
	le.PutUint32(b[12:], s.sn)
	le.PutUint32(b[16:], s.una)
	le.PutUint32(b[20:], uint32(len(s.data)))
	copy(b[24:], s.data)
	return b
}
func parseSegments(b []byte) ([]segment, error) {
	out := []segment{}
	for len(b) > 0 {
		if len(b) < 24 {
			return nil, errors.New("kcp_header")
		}
		n := int(le.Uint32(b[20:]))
		cmd := b[4]
		if n > 65535 || n > len(b)-24 || cmd < push || cmd > wins || (cmd != push && n != 0) {
			return nil, errors.New("kcp_segment")
		}
		out = append(out, segment{le.Uint32(b), cmd, b[5], le.Uint16(b[6:]), le.Uint32(b[8:]), le.Uint32(b[12:]), le.Uint32(b[16:]), append([]byte(nil), b[24:24+n]...)})
		b = b[24+n:]
	}
	return out, nil
}
func startSegments(conv uint32) []segment {
	out := []segment{}
	for i, typ := range []uint32{0x2122, 0x2112, 0x2122} {
		b := make([]byte, 36)
		le.PutUint16(b, 3)
		le.PutUint32(b[8:], 20)
		le.PutUint32(b[12:], typ)
		out = append(out, segment{conv: conv, cmd: push, wnd: 512, sn: uint32(i), data: b})
	}
	return out
}

type window struct {
	conv, next uint32
	pending    map[uint32][]byte
	size       int
	start      map[uint32]bool
	stats      map[string]uint64
}

func newWindow(conv uint32) *window {
	return &window{conv: conv, pending: map[uint32][]byte{}, start: map[uint32]bool{0: true, 1: true, 2: true}, stats: map[string]uint64{}}
}
func (w *window) available() uint16 {
	n := receiveWindow - len(w.pending)
	if m := (maxPending - w.size) / 65535; m < n {
		n = m
	}
	if n < 0 {
		n = 0
	}
	return uint16(n)
}
func (w *window) accept(segments []segment) ([]byte, [][]byte) {
	var out []byte
	var replies [][]byte
	var acks []segment
	probe := false
	for _, s := range segments {
		if s.conv != w.conv {
			w.stats["wrong_conv"]++
			continue
		}
		for sn := range w.start {
			if int32(sn-s.una) < 0 {
				delete(w.start, sn)
			}
		}
		switch s.cmd {
		case ack:
			delete(w.start, s.sn)
			w.stats["acks_received"]++
		case wask:
			probe = true
		case push:
			delta := int32(s.sn - w.next)
			if delta >= receiveWindow {
				w.stats["outside_window"]++
				continue
			}
			_, duplicate := w.pending[s.sn]
			reserve := 0
			if delta > 0 {
				reserve = 65535
			}
			if delta < 0 || duplicate {
				w.stats["duplicates"]++
			} else if w.size+len(s.data) > maxPending-reserve {
				w.stats["buffer_drops"]++
				continue
			} else {
				w.pending[s.sn] = s.data
				w.size += len(s.data)
			}
			acks = append(acks, segment{conv: w.conv, cmd: ack, ts: s.ts, sn: s.sn})
			for {
				data, ok := w.pending[w.next]
				if !ok {
					break
				}
				delete(w.pending, w.next)
				w.size -= len(data)
				out = append(out, data...)
				w.next++
			}
		}
	}
	for _, a := range acks {
		a.wnd = w.available()
		a.una = w.next
		replies = append(replies, a.pack())
	}
	if probe {
		replies = append(replies, segment{conv: w.conv, cmd: wins, wnd: w.available(), una: w.next}.pack())
	}
	return out, replies
}

type rdtParser struct {
	buffer    []byte
	resync    uint64
	stats     map[string]uint64
	values    map[string]map[uint16]bool
	sample    io.Writer
	verifyCRC bool
}

// Native 0x100699200 uses the reflected IEEE polynomial with raw seed zero
// and no initial/final complement, unlike ChecksumIEEE's conventions.
func nativeCRC32(data []byte) uint32 {
	return ^crc32.Update(^uint32(0), crc32.IEEETable, data)
}

func (p *rdtParser) observe(frame []byte) bool {
	stored := le.Uint32(frame[12:])
	typ := le.Uint32(frame)
	media := typ == 0x11 || typ == 0x13
	valid := !media || stored == 0 || nativeCRC32(frame[16:]) == stored
	if p.stats == nil {
		return valid
	}
	if media && stored != 0 {
		p.stats["rdt_crc_present"]++
		if valid {
			p.stats["rdt_crc_match"]++
		} else {
			p.stats["rdt_crc_mismatch"]++
		}
	}
	if p.values == nil {
		p.values = map[string]map[uint16]bool{}
	}
	for name, value := range map[string]uint16{"stream_index": uint16(frame[3]), "cam_index": uint16(frame[19]), "flags": uint16(frame[18]), "codec": le.Uint16(frame[16:])} {
		if p.values[name] == nil {
			p.values[name] = map[uint16]bool{}
		}
		if p.values[name][value] || len(p.values[name]) < 16 {
			p.values[name][value] = true
			p.stats[fmt.Sprintf("rdt_%s_%d", name, value)]++
		} else {
			p.stats["rdt_"+name+"_overflow"]++
		}
	}
	if p.sample != nil && p.stats["rdt_sample_frames"] < 10 && p.stats["rdt_sample_bytes"]+uint64(len(frame)) <= 2_000_000 {
		if err := writeFull(p.sample, frame); err != nil {
			p.stats["rdt_sample_write_failed"]++
			p.sample = nil
			return valid
		}
		p.stats["rdt_sample_frames"]++
		p.stats["rdt_sample_bytes"] += uint64(len(frame))
	}
	return valid
}

func (p *rdtParser) feed(b []byte) ([][]byte, error) {
	if len(p.buffer)+len(b) > 2_000_000+32+65535 {
		return nil, errors.New("rdt_buffer_limit")
	}
	p.buffer = append(p.buffer, b...)
	var out [][]byte
	for len(p.buffer) >= 32 {
		size := int64(le.Uint32(p.buffer[8:])) - 16
		if size < 0 || size > 2_000_000 {
			p.buffer = p.buffer[1:]
			p.resync++
			continue
		}
		total := int(size) + 32
		if len(p.buffer) < total {
			break
		}
		valid := p.observe(p.buffer[:total])
		if p.verifyCRC && !valid {
			if p.stats != nil {
				p.stats["rdt_crc_dropped"]++
			}
			p.buffer = p.buffer[total:]
			continue
		}
		if le.Uint32(p.buffer) == 0x11 && size > 0 {
			out = append(out, append([]byte(nil), p.buffer[32:total]...))
		}
		p.buffer = p.buffer[total:]
	}
	return out, nil
}
