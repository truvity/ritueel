package rootlist_test

import (
	"crypto/elliptic"
	"math/big"
	"testing"

	"ritueel.id/ritueel/internal/rootlist"
)

func TestCheck2ASignerMustBeKnown(t *testing.T) {
	b := newBase(t)
	w := b.w
	t.Run("the only signer is on no list", func(t *testing.T) {
		refuses(t, b.verify(t, b.cand, w.z), rootlist.UnknownSigner, 2)
	})
	t.Run("the only signer is on the new list and not on the held one", func(t *testing.T) {
		refuses(t, b.verify(t, listOf(8, w.a, w.b, w.c), w.c), rootlist.UnknownSigner, 2)
	})
	t.Run("the signers are on the new list only", func(t *testing.T) {
		refuses(t, b.verify(t, listOf(8, w.a, w.b, w.c), w.c, w.z), rootlist.UnknownSigner, 2)
	})
	t.Run("a revoked root key signs a list that left it out", func(t *testing.T) {
		held := heldOf(t, listOf(8, w.b))
		v := rootlist.Verify(signed(t, listOf(9, w.b), w.a), held, now)
		refuses(t, v, rootlist.UnknownSigner, 2)
	})
	t.Run("the host trusts nothing", func(t *testing.T) {
		cand := signed(t, b.cand, w.a)
		refuses(t, rootlist.Verify(cand, rootlist.Trust{}, now), rootlist.UnknownSigner, 2)
		refuses(t, rootlist.Verify(cand, rootlist.HeldTrust(nil), now), rootlist.UnknownSigner, 2)
	})
	t.Run("initial pins that do not hold the signer", func(t *testing.T) {
		refuses(t, rootlist.Verify(signed(t, b.cand, w.a), pinsOf(t, w.b.pin), now), rootlist.UnknownSigner, 2)
		refuses(t, rootlist.Verify(signed(t, b.cand, w.a), pinsOf(t, w.z.pin, w.c.pin), now), rootlist.UnknownSigner, 2)
	})
	t.Run("one known signer is enough for this check, whatever its place", func(t *testing.T) {
		add := listOf(8, w.a, w.b, w.c)
		for _, order := range [][]*key{{w.a, w.b, w.c}, {w.c, w.b, w.a}, {w.c, w.a, w.b}, {w.b, w.c, w.a}} {
			accepts(t, b.verify(t, add, order...))
		}
	})
	t.Run("a pin of the held list is not the same as the pin of the key that signs", func(t *testing.T) {
		// A list that holds a made-up pin where A is, signed by A: A is not on the held list.
		fake := listOf(7, w.b)
		fake.roots = append(fake.roots, rootSpec{label: "A", pin: w.z.pin, fp: w.a.fp()})
		v := rootlist.Verify(signed(t, listOf(8, w.a), w.a), heldOf(t, fake), now)
		refuses(t, v, rootlist.UnknownSigner, 2)
	})
}

func TestCheck2TheOtherSideOfThePins(t *testing.T) {
	b := newBase(t)
	w := b.w
	t.Run("a held list of one root key accepts only that key", func(t *testing.T) {
		held := heldOf(t, listOf(7, w.a))
		accepts(t, rootlist.Verify(signed(t, listOf(8, w.a), w.a), held, now))
		refuses(t, rootlist.Verify(signed(t, listOf(8, w.a), w.b), held, now), rootlist.UnknownSigner, 2)
	})
	t.Run("an initial pin repeated counts once", func(t *testing.T) {
		accepts(t, rootlist.Verify(signed(t, listOf(1, w.a), w.a), pinsOf(t, w.a.pin, w.a.pin, w.a.pin), now))
	})
}

func TestCheck3EverySignatureMustVerify(t *testing.T) {
	b := newBase(t)
	w := b.w
	payload := b.cand.json()
	trust := b.trust(t)
	protectedA := goodHeader(w.a, typList).text()
	protectedB := goodHeader(w.b, typList).text()
	verify := func(jws []byte) rootlist.Verdict {
		return rootlist.Verify(rootlist.Signed{JSON: payload, JWS: jws}, trust, now)
	}
	flipped := func(k *key, protected string) string {
		sig := k.rawSign(t, []byte(protected+"."+b64u(payload)))
		sig[95] ^= 0x01
		return b64u(sig)
	}
	t.Run("the witness", func(t *testing.T) {
		accepts(t, verify(sign(t, payload, w.a, w.b)))
	})
	t.Run("one good signature and one that is not", func(t *testing.T) {
		good := goodEntry(t, w.a, typList, payload)
		bad := entry(protectedB, flipped(w.b, protectedB))
		refuses(t, verify(jwsFile(good, bad)), rootlist.SignatureInvalid, 3)
		refuses(t, verify(jwsFile(bad, good)), rootlist.SignatureInvalid, 3)
	})
	t.Run("the bad signature is by a key that is on no list, and the good one by a known key", func(t *testing.T) {
		good := goodEntry(t, w.a, typList, payload)
		pz := goodHeader(w.z, typList).text()
		bad := entry(pz, flipped(w.z, pz))
		refuses(t, verify(jwsFile(good, bad)), rootlist.SignatureInvalid, 3)
	})
	t.Run("a signature by one key under the header of another", func(t *testing.T) {
		refuses(t, verify(jwsFile(entry(protectedA, sigOver(t, w.b, protectedA, payload)))), rootlist.SignatureInvalid, 3)
		refuses(t, verify(jwsFile(entry(protectedA, sigOver(t, w.z, protectedA, payload)))), rootlist.SignatureInvalid, 3)
	})
	t.Run("a signature over another protected text", func(t *testing.T) {
		other := goodHeader(w.a, typList)
		other.extra = ""
		other.alg = ` "ES384"` // the same header with a space: another text
		refuses(t, verify(jwsFile(entry(protectedA, sigOver(t, w.a, other.text(), payload)))), rootlist.SignatureInvalid, 3)
	})
	t.Run("a signature over another payload", func(t *testing.T) {
		for _, p := range [][]byte{b.held.json(), append([]byte{}, payload[:len(payload)-1]...), append(append([]byte{}, payload...), '\n'), nil} {
			refuses(t, verify(jwsFile(entry(protectedA, sigOver(t, w.a, protectedA, p)))), rootlist.SignatureInvalid, 3)
		}
	})
	t.Run("the signing input is the Base64url of the payload without padding", func(t *testing.T) {
		in := func(pl string) string {
			return b64u(w.a.rawSign(t, []byte(protectedA+"."+pl)))
		}
		for name, pl := range map[string]string{
			"the payload itself":     string(payload),
			"Base64url with padding": padded(b64u(payload)),
			"hexadecimal":            hexOf(payload),
			"nothing":                "",
		} {
			t.Run(name, func(t *testing.T) {
				refuses(t, verify(jwsFile(entry(protectedA, in(pl)))), rootlist.SignatureInvalid, 3)
			})
		}
		t.Run("a payload whose standard Base64 differs from its Base64url", func(t *testing.T) {
			// Bytes 0xfb 0xff 0xbf are "+/+/" in standard Base64 and "-_-_" in Base64url; two bytes
			// more need padding. The text is no list: it is read at check 5, after check 3 passed.
			odd := []byte("\xfb\xff\xbf\xfb\xff")
			if stdB64(odd) == b64u(odd) {
				t.Fatal("the two alphabets agree on the payload")
			}
			v := func(pl string) rootlist.Verdict {
				sig := b64u(w.a.rawSign(t, []byte(protectedA+"."+pl)))
				return rootlist.Verify(rootlist.Signed{JSON: odd, JWS: jwsFile(entry(protectedA, sig))}, trust, now)
			}
			refuses(t, v(stdB64(odd)), rootlist.SignatureInvalid, 3)
			refuses(t, v(padded(b64u(odd))), rootlist.SignatureInvalid, 3)
			refuses(t, v(b64u(odd)), rootlist.Malformed, 5)
		})
		t.Run("a dot is the separator and the only one", func(t *testing.T) {
			sig := b64u(w.a.rawSign(t, []byte(protectedA+payloadSep+b64u(payload))))
			refuses(t, verify(jwsFile(entry(protectedA, sig))), rootlist.SignatureInvalid, 3)
		})
	})
	t.Run("the payload as read: white space and order are signed", func(t *testing.T) {
		spaced := append([]byte(" "), payload...)
		refuses(t, rootlist.Verify(rootlist.Signed{JSON: spaced, JWS: sign(t, payload, w.a)}, trust, now), rootlist.SignatureInvalid, 3)
		refuses(t, rootlist.Verify(rootlist.Signed{JSON: append(append([]byte{}, payload...), '\n'), JWS: sign(t, payload, w.a)}, trust, now), rootlist.SignatureInvalid, 3)
		// The list as signed, with white space the canonical form has not: the host verifies the
		// bytes it received and does not write them again, so this is accepted.
		pretty := append([]byte("\n  "), append(append([]byte{}, payload...), " \n"...)...)
		accepts(t, rootlist.Verify(rootlist.Signed{JSON: pretty, JWS: sign(t, pretty, w.a)}, trust, now))
		// The same list in another order of members, with the signature of the first order.
		reordered := []byte(`{"version":1,` + string(payload[1:len(payload)-len(`,"version":1}`)]) + `}`)
		if string(reordered) == string(payload) {
			t.Fatal("the list was not reordered")
		}
		refuses(t, rootlist.Verify(rootlist.Signed{JSON: reordered, JWS: sign(t, payload, w.a)}, trust, now), rootlist.SignatureInvalid, 3)
		accepts(t, rootlist.Verify(rootlist.Signed{JSON: reordered, JWS: sign(t, reordered, w.a)}, trust, now))
	})
	t.Run("the signature of another list", func(t *testing.T) {
		other := signed(t, listOf(9, w.a, w.b), w.a)
		refuses(t, rootlist.Verify(rootlist.Signed{JSON: payload, JWS: other.JWS}, trust, now), rootlist.SignatureInvalid, 3)
	})
	t.Run("malformed JSON that was signed is not reached before the signature", func(t *testing.T) {
		garbage := []byte("not json at all")
		refuses(t, rootlist.Verify(rootlist.Signed{JSON: garbage, JWS: sign(t, payload, w.a)}, trust, now), rootlist.SignatureInvalid, 3)
		refuses(t, rootlist.Verify(rootlist.Signed{JSON: nil, JWS: sign(t, payload, w.a)}, trust, now), rootlist.SignatureInvalid, 3)
		refuses(t, rootlist.Verify(rootlist.Signed{JSON: garbage, JWS: sign(t, garbage, w.a)}, trust, now), rootlist.Malformed, 5)
	})
}

func TestCheck3SignatureValues(t *testing.T) {
	b := newBase(t)
	w := b.w
	payload := b.cand.json()
	trust := b.trust(t)
	p := goodHeader(w.a, typList).text()
	sig := w.a.rawSign(t, []byte(p+"."+b64u(payload)))
	r := new(big.Int).SetBytes(sig[:48])
	s := new(big.Int).SetBytes(sig[48:])
	n := elliptic.P384().Params().N
	verify := func(raw []byte) rootlist.Verdict {
		return rootlist.Verify(rootlist.Signed{JSON: payload, JWS: jwsFile(entry(p, b64u(raw)))}, trust, now)
	}
	join := func(r, s *big.Int) []byte {
		out := make([]byte, 96)
		r.FillBytes(out[:48])
		s.FillBytes(out[48:])
		return out
	}
	for name, raw := range map[string][]byte{
		"r is zero":                               join(new(big.Int), s),
		"s is zero":                               join(r, new(big.Int)),
		"r and s are zero":                        make([]byte, 96),
		"r is the order of the group":             join(n, s),
		"s is the order of the group":             join(r, n),
		"r and s are the order":                   join(n, n),
		"r is the order plus one":                 join(new(big.Int).Add(n, big.NewInt(1)), s),
		"every byte is 0xff":                      bytesOf(0xff, 96),
		"r and s are swapped":                     join(s, r),
		"r is one":                                join(big.NewInt(1), s),
		"s is the order minus one":                join(r, new(big.Int).Sub(n, big.NewInt(1))),
		"the signature with s negated, r changed": join(new(big.Int).Xor(r, big.NewInt(1)), new(big.Int).Sub(n, s)),
	} {
		t.Run(name, func(t *testing.T) { refuses(t, verify(raw), rootlist.SignatureInvalid, 3) })
	}
	t.Run("the witness", func(t *testing.T) { accepts(t, verify(sig)) })
	t.Run("s replaced by the order less s is another valid signature of the same list", func(t *testing.T) {
		// ECDSA has two valid forms of every signature. No part of the format keys on a signature,
		// so the host takes both.
		accepts(t, verify(join(r, new(big.Int).Sub(n, s))))
	})
}

func TestCheck3KeysThatCannotVerify(t *testing.T) {
	w := newWorld(t)
	for _, curve := range []elliptic.Curve{elliptic.P256(), elliptic.P521()} {
		t.Run(curve.Params().Name, func(t *testing.T) {
			odd := newKeyOn(t, "P", curve)
			// The host trusts the pin of that key: the signature must still not verify.
			for name, trust := range map[string]rootlist.Trust{
				"a held list":    heldOf(t, listOf(7, odd)),
				"an initial pin": pinsOf(t, odd.pin),
			} {
				t.Run(name, func(t *testing.T) {
					refuses(t, rootlist.Verify(signed(t, listOf(8, odd), odd), trust, now), rootlist.SignatureInvalid, 3)
					// A good signature by another key next to it does not help.
					refuses(t, rootlist.Verify(signed(t, listOf(8, odd, w.a), odd, w.a), trust, now), rootlist.SignatureInvalid, 3)
				})
			}
		})
	}
}
