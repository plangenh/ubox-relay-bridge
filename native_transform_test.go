package main

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// Expected bytes independently encode the native 0x1006ab380 short-block
// permutations recovered in wake-packet-crypto-assembly.txt. Full-block
// prefix is the established 0..31 fixture; tail key indexing restarts at 0.
func TestNativeTailVectors(t *testing.T) {
	prefix := "b4348c80685c1822242b791cacc8ba88b5358d90795c1923253b781dadd9ba89"
	cases := []struct {
		full, n int
		tail    string
	}{
		{0, 2, "2149"}, {0, 4, "60664921"}, {0, 8, "7168666021636c49"},
		{32, 2, "0169"}, {32, 4, "40466901"}, {32, 8, "5148464001434c69"},
	}
	for _, c := range cases {
		input := make([]byte, c.full+c.n)
		for i := range input {
			input[i] = byte(i)
		}
		expectedHex := c.tail
		if c.full != 0 {
			expectedHex = prefix + c.tail
		}
		expected, err := hex.DecodeString(expectedHex)
		if err != nil {
			t.Fatal(err)
		}
		if got := transform(input, false); !bytes.Equal(got, expected) {
			t.Fatalf("native encode full=%d tail=%d: %x want %x", c.full, c.n, got, expected)
		}
		if got := transform(expected, true); !bytes.Equal(got, input) {
			t.Fatalf("native decode full=%d tail=%d: %x", c.full, c.n, got)
		}
	}
}

func TestNativeTransformAllTailRoundTrips(t *testing.T) {
	for full := 0; full <= 48; full += 16 {
		for n := 0; n < 16; n++ {
			input := make([]byte, full+n)
			for i := range input {
				input[i] = byte(i*7 + 19)
			}
			if !bytes.Equal(transform(transform(input, false), true), input) {
				t.Fatalf("roundtrip full=%d tail=%d", full, n)
			}
		}
	}
}
