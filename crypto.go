// Adapted from mahumadad/ubox-p4p (MIT); see THIRD_PARTY_NOTICES.md.
package main

import (
	"encoding/binary"
	"math/bits"
	"net"
)

var le = binary.LittleEndian
var be = binary.BigEndian

const magic uint32 = 0x00101807
const msgVideo uint32 = 0x0042140a

var key = []byte("I believe 1 ^ill win the battle!")
var permutation = []int{11, 9, 8, 15, 13, 10, 12, 14, 2, 1, 5, 0, 6, 4, 7, 3}

// Legacy fixed wire transform, not modern authenticated encryption.
func transform(in []byte, decrypt bool) []byte {
	out := make([]byte, len(in))
	full := len(in) / 16 * 16
	for o := 0; o < full; o += 16 {
		block := append([]byte(nil), in[o:o+16]...)
		if decrypt {
			for w := 0; w < 4; w++ {
				le.PutUint32(block[w*4:], bits.RotateLeft32(le.Uint32(block[w*4:]), w*4+3))
			}
			tmp := make([]byte, 16)
			for i, j := range permutation {
				tmp[j] = block[i]
			}
			block = tmp
			for i := range block {
				block[i] ^= key[i]
			}
			for w := 0; w < 4; w++ {
				le.PutUint32(block[w*4:], bits.RotateLeft32(le.Uint32(block[w*4:]), w*4+1))
			}
		} else {
			for w := 0; w < 4; w++ {
				le.PutUint32(block[w*4:], bits.RotateLeft32(le.Uint32(block[w*4:]), -(w*4+1)))
			}
			for i := range block {
				block[i] ^= key[i]
			}
			tmp := make([]byte, 16)
			for i, j := range permutation {
				tmp[i] = block[j]
			}
			block = tmp
			for w := 0; w < 4; w++ {
				le.PutUint32(block[w*4:], bits.RotateLeft32(le.Uint32(block[w*4:]), -(w*4+3)))
			}
		}
		copy(out[o:], block)
	}
	// Native short-block helper 0x1006ab380 permutes tails of 2, 4 and
	// 8 bytes. XOR is before the permutation on encode and after it on
	// decode. The three mappings are involutions; all other tails are
	// the identity mapping. Key indexing restarts at zero for the tail.
	tail := in[full:]
	var order []int
	switch len(tail) {
	case 2:
		order = []int{1, 0}
	case 4:
		order = []int{2, 3, 0, 1}
	case 8:
		order = []int{7, 4, 3, 2, 1, 6, 5, 0}
	}
	for i := range tail {
		j := i
		if order != nil {
			j = order[i]
		}
		if decrypt {
			out[full+i] = tail[j] ^ key[i]
		} else {
			out[full+i] = tail[j] ^ key[j]
		}
	}
	return out
}
func decode(in []byte) []byte {
	if len(in) >= 4 && le.Uint32(in) == magic {
		return in
	}
	return transform(in, true)
}
func fixed(dst []byte, s string) { copy(dst, []byte(s)) }
func knock(uid string) []byte {
	b := make([]byte, 60)
	le.PutUint32(b, magic)
	le.PutUint32(b[4:], 0x2c)
	le.PutUint32(b[8:], 0x00241201)
	le.PutUint32(b[16:], 0x101)
	fixed(b[20:40], uid)
	return transform(b, false)
}
func login(uid, password string, tag []byte, ip net.IP, port int, stream bool) []byte {
	b := make([]byte, 124)
	le.PutUint32(b, magic)
	le.PutUint32(b[4:], 0x6c)
	le.PutUint32(b[8:], 0x00241205)
	b[16] = 1
	copy(b[28:32], ip.To4())
	be.PutUint16(b[32:], uint16(port))
	fixed(b[40:60], uid)
	fixed(b[60:76], password)
	copy(b[88:92], tag)
	copy(b[92:97], []byte("admin"))
	if stream {
		b[82] = 1
		b[108] = 9
		b[111] = 1
		b[116] = 0x2d
		b[117] = 0x9c
	} else {
		be.PutUint32(b[80:], 0x200)
		be.PutUint32(b[104:], 9)
		be.PutUint32(b[108:], 0x100)
		be.PutUint32(b[112:], 0xe6)
		be.PutUint32(b[116:], 0x2a000000)
	}
	return transform(b, false)
}

type response struct {
	native                *nativeSession
	routing, low, payload []byte
	conv                  uint32
	aliveAlias            bool
}

func parseResponse(in []byte) *response {
	b := decode(in)
	if len(b) < 36 || le.Uint32(b) != magic {
		return nil
	}
	typ := le.Uint32(b[8:])
	if typ != 0x00421206 && typ != 0x00421406 {
		return nil
	}
	return &response{routing: append([]byte(nil), b[6:8]...), low: append([]byte(nil), b[12:14]...), payload: append([]byte(nil), b[16:36]...), conv: le.Uint32(b[24:]), aliveAlias: typ == 0x00421406}
}
func bind(r *response) []byte {
	if r.native != nil {
		return nativeBind(r.native)
	}
	b := make([]byte, 36)
	le.PutUint32(b, magic)
	le.PutUint16(b[4:], 0x14)
	copy(b[6:8], r.low)
	le.PutUint32(b[8:], 0x00241405)
	copy(b[12:14], r.routing)
	copy(b[16:], r.payload)
	return transform(b, false)
}
func logout(r *response) []byte {
	if r.native != nil {
		return nativeLogout(r.native, 1)
	}
	b := make([]byte, 100)
	le.PutUint32(b, magic)
	le.PutUint16(b[4:], 0x54)
	copy(b[6:8], r.low)
	le.PutUint32(b[8:], 0x00241207)
	copy(b[12:14], r.routing)
	b[16] = 1
	le.PutUint32(b[24:], r.conv)
	le.PutUint16(b[76:], 1)
	le.PutUint16(b[78:], 1)
	return transform(b, false)
}
func wrap(payload []byte, r *response) []byte {
	b := make([]byte, 16+len(payload))
	le.PutUint32(b, magic)
	le.PutUint16(b[4:], uint16(len(payload)))
	le.PutUint32(b[8:], 0x00241409)
	copy(b[12:14], r.routing)
	copy(b[16:], payload)
	return b
}

// All outgoing KCP packets use the same relay envelope transform, including
// initial start PUSH, retries, ACK and window replies.
func wrapKCP(payload []byte, r *response, encoding string) []byte {
	if r.native != nil {
		return nativeWrapKCP(payload, r.native, 0)
	}
	b := wrap(payload, r)
	if encoding == "legacy" {
		return transform(b, false)
	}
	return b
}
