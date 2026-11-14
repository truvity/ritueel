package rootlist_test

import (
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/rootlist"
)

// signedBytes is a candidate whose bytes are data, signed by the signers over exactly those bytes.
func signedBytes(t testing.TB, data []byte, signers ...*key) rootlist.Signed {
	t.Helper()
	return rootlist.Signed{JSON: data, JWS: sign(t, data, signers...)}
}

func TestCheck4TheVersionMustBeKnown(t *testing.T) {
	b := newBase(t)
	w := b.w
	j := b.cand.json()
	trust := b.trust(t)
	run := func(data []byte) rootlist.Verdict { return rootlist.Verify(signedBytes(t, data, w.a), trust, now) }
	for _, v := range []string{"2", "3", "0", "-1", "100", "9007199254740991", "-9007199254740991", "-0"} {
		t.Run("version "+v, func(t *testing.T) {
			refuses(t, run(replace(t, j, `"version":1`, `"version":`+v)), rootlist.VersionUnsupported, 4)
		})
	}
	t.Run("version 2 with what no reader of version 1 could read is refused for its version", func(t *testing.T) {
		for name, extra := range map[string]string{
			"a float":                     `,"x":1.5`,
			"a null":                      `,"x":null`,
			"an unknown member":           `,"x":"y"`,
			"a number out of range":       `,"x":99999999999999999999`,
			"a nested list":               `,"x":[[1.5,null],{"y":[]}]`,
			"a member named like another": `,"Sequence":1`,
		} {
			t.Run(name, func(t *testing.T) {
				refuses(t, run(replace(t, j, `"version":1`, `"version":2`+extra)), rootlist.VersionUnsupported, 4)
			})
		}
		t.Run("with no roots, no sequence and no times", func(t *testing.T) {
			refuses(t, run([]byte(`{"version":2}`)), rootlist.VersionUnsupported, 4)
			refuses(t, run([]byte(`{"roots":[],"version":2}`)), rootlist.VersionUnsupported, 4)
			refuses(t, run([]byte(`{"sequence":"x","version":2,"roots":null}`)), rootlist.VersionUnsupported, 4)
		})
		t.Run("with the version first, last and in the middle", func(t *testing.T) {
			refuses(t, run([]byte(`{"version":2,"sequence":8}`)), rootlist.VersionUnsupported, 4)
			refuses(t, run([]byte(`{"sequence":8,"version":2}`)), rootlist.VersionUnsupported, 4)
			refuses(t, run([]byte(`{"sequence":8,"version":2,"expires_at":1.5}`)), rootlist.VersionUnsupported, 4)
		})
	})
	t.Run("the same list with another version is refused by the signature when it is not signed", func(t *testing.T) {
		v2 := replace(t, j, `"version":1`, `"version":2`)
		cand := rootlist.Signed{JSON: v2, JWS: b.cand2jws(t)}
		refuses(t, rootlist.Verify(cand, trust, now), rootlist.SignatureInvalid, 3)
		// With an unknown signer as well: the signer is checked before the signature, and both
		// before the version.
		refuses(t, rootlist.Verify(rootlist.Signed{JSON: v2, JWS: sign(t, j, w.z)}, trust, now), rootlist.UnknownSigner, 2)
	})
	// The faults of the version that are not a known other version are faults of the members: the
	// reader of version 1 refuses them at check 5 (check 4 refuses an integer version only).
	for _, v := range []string{"1.0", "2.0", "1.5", "1e0", `"1"`, `"2"`, "true", "null", "[1]", "{}", "9007199254740993", "-9007199254740993", "99999999999999999999999", `""`} {
		t.Run("a version that is no integer: "+v, func(t *testing.T) {
			refuses(t, run(replace(t, j, `"version":1`, `"version":`+v)), rootlist.Malformed, 5)
		})
	}
	t.Run("no version", func(t *testing.T) {
		refuses(t, run(replace(t, j, `,"version":1`, ``)), rootlist.Malformed, 5)
	})
	t.Run("the version twice", func(t *testing.T) {
		refuses(t, run(replace(t, j, `"version":1`, `"version":1,"version":1`)), rootlist.Malformed, 5)
		refuses(t, run(replace(t, j, `"version":1`, `"version":2,"version":1`)), rootlist.Malformed, 5)
		refuses(t, run(replace(t, j, `"version":1`, `"version":1,"version":2`)), rootlist.Malformed, 5)
	})
	t.Run("a document that is not an object", func(t *testing.T) {
		for _, d := range []string{``, ` `, `[]`, `[{"version":2}]`, `"version"`, `null`, `1`, `{`, `{"version":2`, `{"version":2}x`, `{"version":2}{"version":2}`, "\xef\xbb\xbf" + `{"version":2}`, `{"version":2,}`} {
			refuses(t, run([]byte(d)), rootlist.Malformed, 5)
		}
	})
	t.Run("a nested member named version is not the version", func(t *testing.T) {
		refuses(t, run(replace(t, j, `"sequence":8`, `"sequence":8,"x":{"version":2}`)), rootlist.Malformed, 5)
	})
	t.Run("version 1 passes the check", func(t *testing.T) {
		accepts(t, run(j))
	})
}

// cand2jws is the signature file of the base candidate.
func (b *base) cand2jws(t testing.TB) []byte {
	t.Helper()
	return sign(t, b.cand.json(), b.w.a)
}

func TestCheck4TheHostReadsTheVersionOfASignedListOnly(t *testing.T) {
	b := newBase(t)
	w := b.w
	v2 := replace(t, b.cand.json(), `"version":1`, `"version":2,"x":1.5,"y":null`)
	t.Run("signed, it is version-unsupported", func(t *testing.T) {
		refuses(t, rootlist.Verify(signedBytes(t, v2, w.a), b.trust(t), now), rootlist.VersionUnsupported, 4)
	})
	t.Run("signed by a root key the host does not know, it is unknown-signer", func(t *testing.T) {
		refuses(t, rootlist.Verify(signedBytes(t, v2, w.z), b.trust(t), now), rootlist.UnknownSigner, 2)
	})
	t.Run("unsigned, it is signature-invalid", func(t *testing.T) {
		flipped := []byte(strings.Replace(string(v2), `"y":null`, `"y":nul1`, 1))
		cand := rootlist.Signed{JSON: flipped, JWS: sign(t, v2, w.a)}
		refuses(t, rootlist.Verify(cand, b.trust(t), now), rootlist.SignatureInvalid, 3)
	})
}
