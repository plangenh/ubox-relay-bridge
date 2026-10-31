package main

import "fmt"

// Diagnostics contain message-type numbers and aggregate counts only. Never
// retain packet bytes, addresses, conversation IDs or routing tags in stats.
// A hard cap prevents untrusted message IDs from growing the summary/map.
type packetDiagnostics struct {
	messageTypes map[string]bool
	aliveConvs   map[uint32]bool
}

func (d *packetDiagnostics) observe(packet []byte, selected bool, conv uint32, stats map[string]uint64) []byte {
	plain := decode(packet)
	prefix := "other_source"
	if selected {
		prefix = "selected_source"
	}
	if len(plain) < 16 || le.Uint32(plain) != magic {
		stats[prefix+"_invalid_envelope"]++
		return plain
	}
	typ := le.Uint32(plain[8:])
	if d.messageTypes == nil {
		d.messageTypes = map[string]bool{}
	}
	key := fmt.Sprintf("%s_msg_%08x", prefix, typ)
	if d.messageTypes[key] || len(d.messageTypes) < 16 {
		d.messageTypes[key] = true
		stats[key]++
	} else {
		stats["message_type_overflow"]++
	}
	if typ == 0x00421406 && selected {
		if r := parseResponse(plain); r != nil {
			if d.aliveConvs == nil {
				d.aliveConvs = map[uint32]bool{}
			}
			if len(d.aliveConvs) < 8 || d.aliveConvs[r.conv] {
				d.aliveConvs[r.conv] = true
			}
			if r.conv == conv {
				stats["selected_source_alive_conv_matches_chosen"]++
			} else {
				stats["selected_source_alive_conv_differs_chosen"]++
			}
		}
	}
	if typ != msgVideo {
		return plain
	}
	stats[prefix+"_video_msg"]++
	segments, e := parseSegments(plain[16:])
	if e != nil {
		stats[prefix+"_video_malformed_kcp"]++
		body := plain[16:]
		if len(body) < 24 {
			stats[prefix+"_malformed_short_header"]++
		} else {
			if le.Uint32(body) == conv {
				stats[prefix+"_malformed_first_conv_matches_chosen"]++
			} else {
				stats[prefix+"_malformed_first_conv_differs_chosen"]++
			}
			if body[4] < push || body[4] > wins {
				stats[prefix+"_malformed_first_command"]++
			}
			if uint64(le.Uint32(body[20:])) > uint64(len(body)-24) {
				stats[prefix+"_malformed_first_length"]++
			}
		}
		if nested, err := parseSegments(transform(body, true)); err == nil && len(nested) > 0 {
			stats[prefix+"_malformed_inner_decode_valid_kcp"]++
			for _, s := range nested {
				if s.conv == conv {
					stats[prefix+"_malformed_inner_decode_matches_chosen"]++
					break
				}
			}
		}

		return plain
	}
	matches, pushes := false, false
	matchesAlive := false
	for _, s := range segments {
		if selected && d.aliveConvs[s.conv] {
			matchesAlive = true
		}
		if s.conv == conv {
			matches = true
			if s.cmd == push {
				pushes = true
			}
		}
	}
	if matchesAlive {
		stats["selected_source_video_matches_alive_control"]++
	}
	if matches {
		stats[prefix+"_video_matching_conv"]++
	}
	if pushes {
		stats[prefix+"_video_matching_push"]++
	}
	return plain
}
