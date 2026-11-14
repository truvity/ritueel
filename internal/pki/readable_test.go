package pki

import (
	"math/big"
	"testing"
	"time"
)

// readable is the check at the end of both builders. A body that the builders make never fails the
// parts of it that compare what was read back with what was made (the standard library gives the
// same bytes, serial and dates), so these are asked of it directly, with a body and the values it
// should have.
func TestReadable(t *testing.T) {
	serial := big.NewInt(0).SetBytes([]byte{0x4b, 1, 2, 3, 4, 5, 6, 7, 8})
	nb := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	na := time.Date(2029, 11, 15, 12, 0, 0, 0, time.UTC)
	good := func(version int64, alg []byte) []byte {
		name := commonName("Example Test Root K")
		spkiDER := mustSPKI(t)
		return shortSeq(
			short(tagVersion, integer(big.NewInt(version))),
			integer(serial),
			alg,
			name,
			shortSeq(timeValue(nb), timeValue(na)),
			name,
			spkiDER,
		)
	}
	other := big.NewInt(0).Add(serial, big.NewInt(1))
	cases := []struct {
		name   string
		body   []byte
		serial *big.Int
		nb, na time.Time
		ok     bool
	}{
		{"a body that reads back as made", good(2, algECDSAWithSHA384), serial, nb, na, true},
		{"another serial", good(2, algECDSAWithSHA384), other, nb, na, false},
		{"another start", good(2, algECDSAWithSHA384), serial, nb.Add(time.Second), na, false},
		{"another end", good(2, algECDSAWithSHA384), serial, nb, na.Add(time.Second), false},
		{"another start and end", good(2, algECDSAWithSHA384), serial, nb.Add(-time.Hour), na.Add(time.Hour), false},
		{"version 2", good(1, algECDSAWithSHA384), serial, nb, na, false},
		{"version 1", good(0, algECDSAWithSHA384), serial, nb, na, false},
		{"another algorithm, inner and outer differing", good(2, []byte{0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02}), serial, nb, na, false},
		{"not a certificate", shortSeq(short(tagVersion, integer(big.NewInt(2)))), serial, nb, na, false},
		{"nothing", nil, serial, nb, na, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := readable(c.body, c.serial, c.nb, c.na)
			if c.ok != (err == nil) {
				t.Errorf("readable = %v, want ok = %v", err, c.ok)
			}
		})
	}
}

func mustSPKI(t *testing.T) []byte {
	t.Helper()
	// The key of a fixed test point is not needed: any P-384 key in memory will do.
	k := newTestKey(t)
	der, _, err := spki(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return der
}
