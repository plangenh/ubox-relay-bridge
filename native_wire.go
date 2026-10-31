package main

import "bytes"

// Native 1202 handler reads only this first UID/status, even when count>1.
// No record stride is inferred from a count without pointer advancement.
func parseNativeWake(packet []byte, uid string) (byte, bool) {
	b := decode(packet)
	if len(b) < 57 || le.Uint32(b) != magic || le.Uint32(b[8:]) != 0x00421202 || b[16] == 0 || b[16] > 16 {
		return 0, false
	}
	want := make([]byte, 20)
	fixed(want, uid)
	if !bytes.Equal(want, b[36:56]) {
		return 0, false
	}
	return b[56], true
}

// Native 1.1.30 wire layout: rlystreamrsp at 0x1006c5378. These
// records are 428 bytes; the old 20-byte interpretation parsed unrelated
// response metadata as a KCP conversation and accepted 1406 keepalives.
type nativeSession struct {
	clientSID, serverSID byte
	routeA, routeB       uint16
	randomID             uint32
}

func parseNativeResponse(packet []byte, sid byte, randomID uint32, seqnum byte) *nativeSession {
	b := decode(packet)
	if len(b) < 40 || le.Uint32(b) != magic || le.Uint32(b[8:]) != 0x00421206 {
		return nil
	}
	count := int(b[16])
	if count == 0 || count > 16 || len(b) < 40+count*428 {
		return nil
	}
	// Native response sequence zero means unspecified; otherwise it must
	// match the sequence used in the outstanding request.
	if b[19] != 0 && b[19] != seqnum {
		return nil
	}
	for i := 0; i < count; i++ {
		r := b[40+i*428 : 40+(i+1)*428]
		if le.Uint16(r) != 0 || r[30] != sid || le.Uint32(r[36:]) != randomID {
			continue
		}
		return &nativeSession{sid, r[31], le.Uint16(r[32:]), le.Uint16(r[34:]), randomID}
	}
	return nil
}

// Native relay-mode 1405 at 0x1006c3d34. Its header uses the client SID,
// whereas the 1409 relay header below uses the server SID.
func nativeBind(s *nativeSession) []byte {
	b := make([]byte, 36)
	le.PutUint32(b, magic)
	le.PutUint16(b[4:], 20)
	le.PutUint16(b[6:], uint16(s.clientSID))
	le.PutUint32(b[8:], 0x00241405)
	le.PutUint16(b[12:], s.routeB)
	b[17], b[18] = s.clientSID, s.serverSID
	le.PutUint16(b[20:], s.routeA)
	le.PutUint16(b[22:], s.routeB)
	le.PutUint32(b[24:], s.randomID)
	return transform(b, false)
}

// Native relay-mode 1409 at 0x1006cab90. The native packet limit is 1400
// payload bytes; channel is a separate byte and is not part of routeB.
func nativeWrapKCP(payload []byte, s *nativeSession, channel byte) []byte {
	if len(payload) > 0x578 {
		return nil
	}
	b := make([]byte, 16+len(payload))
	le.PutUint32(b, magic)
	le.PutUint16(b[4:], uint16(len(payload)))
	le.PutUint16(b[6:], uint16(s.serverSID))
	le.PutUint32(b[8:], 0x00241409)
	le.PutUint16(b[12:], s.routeB)
	b[14] = channel
	copy(b[16:], payload)
	return transform(b, false)
}

func nativeLogout(s *nativeSession, seqnum byte) []byte {
	b := make([]byte, 100)
	le.PutUint32(b, magic)
	le.PutUint16(b[4:], 84)
	le.PutUint16(b[6:], uint16(s.serverSID))
	le.PutUint32(b[8:], 0x00241207)
	le.PutUint16(b[12:], s.routeB)
	b[16], b[17] = 1, seqnum
	b[74], b[75] = s.clientSID, s.serverSID
	le.PutUint16(b[76:], s.routeA)
	le.PutUint16(b[78:], s.routeB)
	le.PutUint32(b[80:], s.randomID)
	return transform(b, false)
}
