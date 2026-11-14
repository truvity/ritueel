package rootlist_test

import (
	"errors"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/rootlist"
)

// removalVerdict verifies a list that drops A and carries the authorisation text auth for the
// entry of A, signed by B (so that checks 1 to 8 pass), against the held list of A and B.
func removalVerdict(t testing.TB, b *base, auth string) rootlist.Verdict {
	t.Helper()
	w := b.w
	cand := listOf(8, w.b).withRemovals(removalSpec{label: "A", pin: w.a.pin, auth: auth})
	return rootlist.Verify(signed(t, cand, w.b), b.trust(t), now)
}

func TestCheck9TheRemovalAuthorisationMustBeValid(t *testing.T) {
	b := newBase(t)
	w := b.w
	pinA := w.a.pin
	t.Run("the witness", func(t *testing.T) {
		accepts(t, removalVerdict(t, b, authorisation(t, w.a)))
	})
	hdr := func(k *key, edit func(*header)) header {
		h := goodHeader(k, typRemoval)
		edit(&h)
		return h
	}
	payload := string(removalPayload(pinA))
	for _, c := range []struct{ name, auth string }{
		{"the authorisation of another root key under A's entry", authorisation(t, w.b)},
		{"the authorisation of a key that is on no list", authorisation(t, w.z)},
		{"a header that names A and a key of B", authWith(t, w.b, hdr(w.a, func(h *header) { h.x5c = `["` + w.b.x5c() + `"]` }), removalPayload(pinA))},
		{"the kid of B with the key and the payload of A", authWith(t, w.a, hdr(w.a, func(h *header) { h.kid = `"` + w.b.pin + `"` }), removalPayload(pinA))},
		{"the certificate of B, the kid of B and the payload of A", authWith(t, w.b, goodHeader(w.b, typRemoval), removalPayload(pinA))},
		{"the pin of B in the payload, signed by A", authWith(t, w.a, goodHeader(w.a, typRemoval), removalPayload(w.b.pin))},
		{"the payload of B signed by B, A's pin in the header", authWith(t, w.b, hdr(w.b, func(h *header) { h.kid = `"` + pinA + `"` }), removalPayload(w.b.pin))},
		{"A's header and payload, B's signature", authWith(t, w.b, goodHeader(w.a, typRemoval), removalPayload(pinA))},
		{"A's header and payload, a signature by a key on no list", authWith(t, w.z, goodHeader(w.a, typRemoval), removalPayload(pinA))},
		{"the type of the list", authWith(t, w.a, hdr(w.a, func(h *header) { h.typ = `"` + typList + `"` }), removalPayload(pinA))},
		{"no type", authWith(t, w.a, hdr(w.a, func(h *header) { h.drop = "typ" }), removalPayload(pinA))},
		{"the type in upper case", authWith(t, w.a, hdr(w.a, func(h *header) { h.typ = `"ROOT-REMOVAL+JSON"` }), removalPayload(pinA))},
		{"alg none", authWith(t, w.a, hdr(w.a, func(h *header) { h.alg = `"none"` }), removalPayload(pinA))},
		{"alg ES256", authWith(t, w.a, hdr(w.a, func(h *header) { h.alg = `"ES256"` }), removalPayload(pinA))},
		{"an extra header", authWith(t, w.a, hdr(w.a, func(h *header) { h.extra = `,"crit":["b64"]` }), removalPayload(pinA))},
		{"b64 false", authWith(t, w.a, hdr(w.a, func(h *header) { h.extra = `,"b64":false` }), removalPayload(pinA))},
		{"two certificates", authWith(t, w.a, hdr(w.a, func(h *header) { h.x5c = `["` + w.a.x5c() + `","` + w.a.x5c() + `"]` }), removalPayload(pinA))},
		{"no certificate", authWith(t, w.a, hdr(w.a, func(h *header) { h.x5c = `[]` }), removalPayload(pinA))},
		{"a payload with a space", authWith(t, w.a, goodHeader(w.a, typRemoval), []byte(`{"version": 1,"x509_spki_sha256":"`+pinA+`"}`))},
		{"a payload with the members in the other order", authWith(t, w.a, goodHeader(w.a, typRemoval), []byte(`{"x509_spki_sha256":"`+pinA+`","version":1}`))},
		{"a payload with version 2", authWith(t, w.a, goodHeader(w.a, typRemoval), []byte(`{"version":2,"x509_spki_sha256":"`+pinA+`"}`))},
		{"a payload with version as a string", authWith(t, w.a, goodHeader(w.a, typRemoval), []byte(`{"version":"1","x509_spki_sha256":"`+pinA+`"}`))},
		{"a payload with no version", authWith(t, w.a, goodHeader(w.a, typRemoval), []byte(`{"x509_spki_sha256":"`+pinA+`"}`))},
		{"a payload with no pin", authWith(t, w.a, goodHeader(w.a, typRemoval), []byte(`{"version":1}`))},
		{"a payload with another member", authWith(t, w.a, goodHeader(w.a, typRemoval), []byte(`{"sequence":8,"version":1,"x509_spki_sha256":"`+pinA+`"}`))},
		{"a payload with a line feed after it", authWith(t, w.a, goodHeader(w.a, typRemoval), []byte(payload+"\n"))},
		{"a payload with the pin in upper case", authWith(t, w.a, goodHeader(w.a, typRemoval), []byte(`{"version":1,"x509_spki_sha256":"`+strings.ToUpper(pinA)+`"}`))},
		{"an empty payload", authWith(t, w.a, goodHeader(w.a, typRemoval), nil)},
		{"a payload that is a list", authWith(t, w.a, goodHeader(w.a, typRemoval), []byte(`[`+payload+`]`))},
		{"a payload that is the pin", authWith(t, w.a, goodHeader(w.a, typRemoval), []byte(pinA))},
		{"a root list as the payload", authWith(t, w.a, goodHeader(w.a, typRemoval), b.cand.json())},
		{"a good authorisation with a line feed after it", authorisation(t, w.a) + `\n`},
		{"a good authorisation with a space before it", ` ` + authorisation(t, w.a)},
		{"a good authorisation with a dot after it", authorisation(t, w.a) + `.`},
		{"a good authorisation with a part missing", authorisation(t, w.a)[:strings.LastIndex(authorisation(t, w.a), ".")]},
		{"a good authorisation cut short", authorisation(t, w.a)[:len(authorisation(t, w.a))-1]},
		{"a good authorisation with its signature in the ASN.1 form", strings.TrimSuffix(authorisation(t, w.a), authorisation(t, w.a)[strings.LastIndex(authorisation(t, w.a), ".")+1:]) + b64u(der103())},
		{"the general form of a JWS", `{\"signatures\":[]}`},
		{"the list's own signature as the authorisation", authWith(t, w.a, goodHeader(w.a, typList), removalPayload(pinA))},
		{"a text that is not a JWS", `not a jws`},
		{"three dots", `...`},
		{"a good authorisation in standard Base64 for the payload", func() string {
			p := goodHeader(w.a, typRemoval).text()
			odd := []byte(payload)
			return p + "." + stdB64(odd) + "=" + "." + sigOver(t, w.a, p, odd)
		}()},
	} {
		t.Run(c.name, func(t *testing.T) {
			refuses(t, removalVerdict(t, b, c.auth), rootlist.RemovalInvalid, 9)
		})
	}
}

func TestCheck9TheKeyMustLeaveTheSet(t *testing.T) {
	b := newBase(t)
	w := b.w
	t.Run("a root key that is not on the held list", func(t *testing.T) {
		cand := listOf(8, w.a, w.b).withRemovals(removalOf(t, w.z))
		refuses(t, rootlist.Verify(signed(t, cand, w.a), b.trust(t), now), rootlist.RemovalInvalid, 9)
	})
	t.Run("a root key that is still on the new list", func(t *testing.T) {
		cand := listOf(8, w.a, w.b).withRemovals(removalOf(t, w.a))
		refuses(t, rootlist.Verify(signed(t, cand, w.a, w.b), b.trust(t), now), rootlist.RemovalInvalid, 9)
	})
	t.Run("a root key that is still on the new list and signs it", func(t *testing.T) {
		cand := listOf(8, w.b).withRemovals(removalOf(t, w.b))
		refuses(t, rootlist.Verify(signed(t, cand, w.b), b.trust(t), now), rootlist.RemovalInvalid, 9)
	})
	t.Run("a root key that the new list adds", func(t *testing.T) {
		cand := listOf(8, w.a, w.b, w.c).withRemovals(removalOf(t, w.c))
		refuses(t, rootlist.Verify(signed(t, cand, w.a, w.b, w.c), b.trust(t), now), rootlist.RemovalInvalid, 9)
	})
	t.Run("a root key of the held list under the entry of another key", func(t *testing.T) {
		entry := removalSpec{label: "A", pin: w.b.pin, auth: authorisation(t, w.a)}
		cand := listOf(8, w.a).withRemovals(entry)
		refuses(t, rootlist.Verify(signed(t, cand, w.a), b.trust(t), now), rootlist.RemovalInvalid, 9)
	})
	t.Run("a good entry and a bad one", func(t *testing.T) {
		held := heldOf(t, listOf(7, w.a, w.b, w.c))
		bad := removalSpec{label: "B", pin: w.b.pin, auth: authorisation(t, w.a)}
		for _, entries := range [][]removalSpec{{removalOf(t, w.a), bad}, {bad, removalOf(t, w.a)}} {
			cand := listOf(8, w.c).withRemovals(entries...)
			refuses(t, rootlist.Verify(signed(t, cand, w.c), held, now), rootlist.RemovalInvalid, 9)
		}
	})
	t.Run("two good entries", func(t *testing.T) {
		held := heldOf(t, listOf(7, w.a, w.b, w.c))
		cand := listOf(8, w.c).withRemovals(removalOf(t, w.a), removalOf(t, w.b))
		accepts(t, rootlist.Verify(signed(t, cand, w.c), held, now))
	})
	t.Run("the order of the entries is not enforced", func(t *testing.T) {
		// The page puts the entries in label order; the host does not read the order. The test
		// pins the behaviour so that a change is seen.
		held := heldOf(t, listOf(7, w.a, w.b, w.c))
		for _, entries := range [][]removalSpec{{removalOf(t, w.a), removalOf(t, w.b)}, {removalOf(t, w.b), removalOf(t, w.a)}} {
			accepts(t, rootlist.Verify(signed(t, listOf(8, w.c).withRemovals(entries...), w.c), held, now))
		}
	})
	t.Run("a removal and a signature of the same key", func(t *testing.T) {
		cand := listOf(8, w.b).withRemovals(removalOf(t, w.a))
		accepts(t, rootlist.Verify(signed(t, cand, w.a, w.b), b.trust(t), now))
	})
	t.Run("against initial pins", func(t *testing.T) {
		pins := pinsOf(t, w.a.pin, w.b.pin)
		accepts(t, rootlist.Verify(signed(t, listOf(8, w.b).withRemovals(removalOf(t, w.a)), w.b), pins, now))
		refuses(t, rootlist.Verify(signed(t, listOf(8, w.b).withRemovals(removalOf(t, w.z)), w.b), pins, now), rootlist.RemovalInvalid, 9)
	})
	t.Run("the label of an entry is not compared with anything", func(t *testing.T) {
		// The page gives the label to the entry and compares nothing with it; the pin names the key
		// The test pins the behaviour so that a change is seen.
		entry := removalOf(t, w.a)
		entry.label = "Q"
		accepts(t, rootlist.Verify(signed(t, listOf(8, w.b).withRemovals(entry), w.b), b.trust(t), now))
	})
	t.Run("a removal for a key when nothing else changes", func(t *testing.T) {
		// A list with the same root keys and a removals entry for a key that is on it.
		cand := listOf(8, w.a, w.b).withRemovals(removalOf(t, w.b))
		refuses(t, rootlist.Verify(signed(t, cand, w.a), b.trust(t), now), rootlist.RemovalInvalid, 9)
	})
}

func TestCheckRemovalDirectly(t *testing.T) {
	w := newWorld(t)
	held := []string{w.a.pin, w.b.pin}
	cand := &rootlist.List{Roots: []rootlist.Root{{Label: "B", X509SPKISHA256: w.b.pin}}}
	good := rootlist.Removal{Label: "A", X509SPKISHA256: w.a.pin, Authorisation: authorisation(t, w.a)}
	if err := rootlist.CheckRemoval(good, cand, held); err != nil {
		t.Fatalf("the witness: %v", err)
	}
	t.Run("a nil candidate list asks nothing of the new list", func(t *testing.T) {
		if err := rootlist.CheckRemoval(good, nil, held); err != nil {
			t.Error(err)
		}
	})
	for name, c := range map[string]struct {
		r    rootlist.Removal
		cand *rootlist.List
		held []string
	}{
		"no held pins":                   {good, cand, nil},
		"held pins without the key":      {good, cand, []string{w.b.pin, w.c.pin}},
		"the key on the new list":        {good, &rootlist.List{Roots: []rootlist.Root{{Label: "A", X509SPKISHA256: w.a.pin}}}, held},
		"an empty authorisation":         {rootlist.Removal{Label: "A", X509SPKISHA256: w.a.pin}, cand, held},
		"another key's authorisation":    {rootlist.Removal{Label: "A", X509SPKISHA256: w.a.pin, Authorisation: authorisation(t, w.b)}, cand, held},
		"an entry pin in upper case":     {rootlist.Removal{Label: "A", X509SPKISHA256: strings.ToUpper(w.a.pin) + "A", Authorisation: good.Authorisation}, cand, append(held, strings.ToUpper(w.a.pin)+"A")},
		"an entry pin that is short":     {rootlist.Removal{Label: "A", X509SPKISHA256: w.a.pin[:63], Authorisation: good.Authorisation}, cand, append(held, w.a.pin[:63])},
		"an empty entry pin":             {rootlist.Removal{Label: "A", Authorisation: good.Authorisation}, cand, append(held, "")},
		"a pin that is held in capitals": {rootlist.Removal{Label: "A", X509SPKISHA256: upperFirstLetter(w.a.pin), Authorisation: good.Authorisation}, cand, held},
	} {
		t.Run(name, func(t *testing.T) {
			err := rootlist.CheckRemoval(c.r, c.cand, c.held)
			if err == nil {
				t.Fatal("accepted")
			}
			if !errors.Is(err, rootlist.ErrRemovalInvalid) {
				t.Errorf("the error does not wrap ErrRemovalInvalid: %v", err)
			}
			mustBeASCII(t, "the error text", err.Error())
		})
	}
	t.Run("the authorisation of C is good for C and for no other entry", func(t *testing.T) {
		heldC := []string{w.a.pin, w.b.pin, w.c.pin}
		okC := rootlist.Removal{Label: "C", X509SPKISHA256: w.c.pin, Authorisation: authorisation(t, w.c)}
		if err := rootlist.CheckRemoval(okC, cand, heldC); err != nil {
			t.Fatal(err)
		}
		for _, other := range []*key{w.a, w.b} {
			wrong := rootlist.Removal{Label: other.label, X509SPKISHA256: other.pin, Authorisation: okC.Authorisation}
			if err := rootlist.CheckRemoval(wrong, nil, heldC); err == nil {
				t.Errorf("C's authorisation was taken for %s", other.label)
			}
		}
	})
}
