package pki_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"ritueel.id/ritueel/internal/pki"
)

func TestTBSDigests(t *testing.T) {
	// The standard answers for SHA-256 and SHA-384 (FIPS 180-4, the examples of the empty message and "abc").
	cases := []struct{ name, in, sha256, sha384 string }{
		{"empty", "",
			"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			"38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"},
		{"abc", "abc",
			"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
			"cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := pki.TBSSHA256([]byte(c.in)); got != c.sha256 {
				t.Errorf("TBSSHA256 = %s, want %s", got, c.sha256)
			}
			d := pki.TBSDigest([]byte(c.in))
			if hex.EncodeToString(d) != c.sha384 || len(d) != 48 {
				t.Errorf("TBSDigest = %x, want %s", d, c.sha384)
			}
		})
	}
	if pki.TBSSHA256(nil) != cases[0].sha256 || hex.EncodeToString(pki.TBSDigest(nil)) != cases[0].sha384 {
		t.Error("a nil slice is not the empty message")
	}
	// The digest is the caller's to keep.
	a := pki.TBSDigest([]byte("abc"))
	a[0] ^= 0xff
	if b := pki.TBSDigest([]byte("abc")); bytes.Equal(a, b) {
		t.Error("TBSDigest shares its result between calls")
	}
}
