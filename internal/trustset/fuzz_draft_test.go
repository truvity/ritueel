package trustset_test

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/canonjson"
	"ritueel.id/ritueel/internal/history"
	"ritueel.id/ritueel/internal/jws"
	"ritueel.id/ritueel/internal/rootlist"
	"ritueel.id/ritueel/internal/trustset"
)

// The fuzz targets of the draft and of Sign. None starts a program or touches a file; the keys are
// software keys made in memory. CI runs the seeds only. The laws:
//
//   - no panic;
//   - an error comes with no draft and wraps ErrParams or ErrReturns (never ErrSelf, which is a fault of
//     the builder, never ErrSign or ErrSigners, which belong to Sign);
//   - a draft that comes has a list that the reader of the page accepts, in canonical form, with
//     expires_at 13 months after signed_at, and a CA bundle that the reader accepts; and it can be
//     signed by the signers that it names, and the reader accepts the set against the previous list.

// fuzzAuth holds the stored authorisation of each label, made once.
var (
	fuzzAuthOnce sync.Once
	fuzzAuth     = map[string]string{}
)

func authOf(t testing.TB, label string) string {
	fuzzAuthOnce.Do(func() {
		for _, l := range []string{"A", "B", "C", "D"} {
			fuzzAuth[l] = newRoot(t, l, true).removal(t)
		}
	})
	return fuzzAuth[label]
}

// lawsOfDraft checks the laws for the result of NewDraft.
func lawsOfDraft(t *testing.T, in trustset.Input, d *trustset.Draft, err error) {
	t.Helper()
	if err != nil {
		if d != nil {
			t.Fatal("a draft comes with an error")
		}
		if errors.Is(err, trustset.ErrSelf) || errors.Is(err, trustset.ErrSign) || errors.Is(err, trustset.ErrSigners) {
			t.Fatalf("a fault of the builder or of another call: %v", err)
		}
		if !errors.Is(err, trustset.ErrParams) && !errors.Is(err, trustset.ErrReturns) {
			t.Fatalf("an error of no kind of the package: %v", err)
		}
		if errors.Is(err, trustset.ErrParams) && errors.Is(err, trustset.ErrReturns) {
			t.Fatalf("an error of two kinds: %v", err)
		}
		if !printable(err.Error()) || len(err.Error()) > 700 {
			t.Fatalf("the text of the error: %.100q (%d bytes)", err.Error(), len(err.Error()))
		}
		return
	}
	if d == nil {
		t.Fatal("no draft and no error")
	}
	data := d.ListJSON()
	list, perr := rootlist.ParseList(data)
	if perr != nil {
		t.Fatalf("the reader refuses the list: %v", perr)
	}
	if ok, cerr := canonjson.IsCanonical(data); !ok || cerr != nil {
		t.Fatalf("not canonical: %v", cerr)
	}
	if !list.ExpiresAt.Equal(rootlist.ExpiresFor(list.SignedAt)) {
		t.Fatalf("expires_at %v for signed_at %v", list.ExpiresAt, list.SignedAt)
	}
	if v := rootlist.VerifyCABundle(d.CABundle(), list); !v.Accepted {
		t.Fatalf("the reader refuses the CA bundle: %+v", v)
	}
	if d.Sequence() != in.Sequence || list.Sequence != in.Sequence {
		t.Fatalf("sequence %d, %d, input %d", d.Sequence(), list.Sequence, in.Sequence)
	}
	if d.ListSHA256() != hexOf(string(data)) || d.CABundleSHA256() != hexOf(string(d.CABundle())) {
		t.Fatal("a digest is not the digest of its file")
	}
	if k := d.Kind(); k < trustset.KindFirst || k > trustset.KindRevoke {
		t.Fatalf("kind %d", int(k))
	}
	if (d.Kind() == trustset.KindFirst) != (in.Sequence == 1) {
		t.Fatalf("kind %v at sequence %d", d.Kind(), in.Sequence)
	}
	// The name is the name of the list, and a set of the same input has it too.
	if want, nerr := trustset.SetName(d.Sequence(), hexOf(string(data))); nerr != nil || d.SetName() != want {
		t.Fatalf("SetName %q, want %q (%v)", d.SetName(), want, nerr)
	}
	// A draft that is made again from a copy of the input, whose bytes the caller then wipes, is the
	// same draft; it is the one that is signed below, against the previous list as it was.
	again := in
	again.Previous = bytes.Clone(in.Previous)
	d2, err2 := trustset.NewDraft(again)
	if err2 != nil || d2 == nil || !bytes.Equal(d2.ListJSON(), data) || d2.SetName() != d.SetName() {
		t.Fatalf("a second draft of the same input: %v", err2)
	}
	for i := range again.Previous {
		again.Previous[i] = 0xff
	}
	d = d2
	// It can be signed by the signers it names, and the reader accepts the set.
	labels := slices.Clone(d.Required())
	if len(d.OneOf()) > 0 {
		labels = append(labels, d.OneOf()[0])
	}
	var signers []trustset.Signer
	for _, l := range labels {
		root := newRootIfPool(l)
		if root == nil {
			return // a label outside the pool of the fuzz target has no key here
		}
		signers = append(signers, root.signer(t))
	}
	set, serr := d.Sign(signers, func(trustset.Signed) error { return nil })
	if serr != nil {
		t.Fatalf("a draft that cannot be signed by the signers it names: %v", serr)
	}
	if set.Name() != d.SetName() {
		t.Fatalf("the set is named %q, the draft %q", set.Name(), d.SetName())
	}
	pins := list.Pins()
	var trust rootlist.Trust
	var terr error
	if in.Previous == nil {
		trust, terr = rootlist.PinTrust(pins)
	} else {
		held, herr := rootlist.ParseHeld(in.Previous)
		if herr != nil {
			t.Fatalf("the previous list was taken and cannot be read: %v", herr)
		}
		trust = rootlist.HeldTrust(held)
	}
	if terr != nil {
		t.Fatal(terr)
	}
	v := rootlist.Verify(rootlist.Signed{JSON: set.ListJSON(), JWS: set.ListJWS()}, trust, list.SignedAt)
	if !v.Accepted || v.Again || v.Wayback {
		t.Fatalf("the reader refuses the set: %+v", v)
	}
}

// newRootIfPool returns the key of a label of the pool A to D, nil for another label.
func newRootIfPool(label string) *testRoot {
	if !slices.Contains([]string{"A", "B", "C", "D"}, label) {
		return nil
	}
	rootsMu.Lock()
	r := roots[label+"-test"]
	rootsMu.Unlock()
	return r
}

func poolRoots(t testing.TB) {
	for _, l := range []string{"A", "B", "C", "D"} {
		newRoot(t, l, true)
	}
}

// FuzzDraftPrevious: the bytes are the previous list, whatever they hold.
func FuzzDraftPrevious(f *testing.F) {
	m := loadVectors(f)
	for _, l := range m.Lists {
		f.Add(vectorFile(f, l.Files[0]))
	}
	prev, err := trustset.MarshalList(trustset.ListSpec{
		Sequence: 1, SignedAt: firstCeremony,
		Roots: []trustset.Root{newRoot(f, "A", true).entry(true), newRoot(f, "B", true).entry(true)},
	})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(prev)
	f.Add([]byte(`{}`))
	f.Add([]byte(strings.Repeat("[", 5000)))
	poolRoots(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		entries := rootsOf(t, false, "A", "B")
		in := trustset.Input{
			Sequence: 2, SignedAt: firstCeremony.Add(time.Hour), Roots: entries,
			Certificates: certsOf(t, "A", "B"), LastRecordSHA256: hexOf("end"),
			Previous: data,
			Earlier:  []history.RootList{historyList("1", entries)},
		}
		d, err := trustset.NewDraft(in)
		lawsOfDraft(t, in, d, err)
		// The sequence that the bytes ask for, when they are a list, with an Earlier of that length.
		if l, perr := rootlist.ParseList(data); perr == nil && l.Sequence >= 1 && l.Sequence < 40 {
			in.Sequence = l.Sequence + 1
			in.Earlier = nil
			for i := int64(0); i < l.Sequence; i++ {
				in.Earlier = append(in.Earlier, historyList("x", entries))
			}
			if l.Sequence == 1 {
				// Sequence 2 is the one tried above.
				return
			}
			in.SignedAt = l.SignedAt.Add(time.Hour)
			d, err = trustset.NewDraft(in)
			lawsOfDraft(t, in, d, err)
		}
	})
}

// FuzzDraftInput: the bytes pick the previous list, the new entries, the departures and the history.
// Byte 0 and 1 are the masks of the labels A to D of the previous and the new list, byte 2 holds a code
// of two bits for each label's departure (none, retired, revoked with its authorisation, revoked
// with none), byte 3 holds flags, and each byte after them is the mask of one earlier list.
func FuzzDraftInput(f *testing.F) {
	for _, seed := range [][]byte{
		{0x00, 0x03, 0x00, 0x00},             // first list of A and B
		{0x03, 0x03, 0x00, 0x00, 0x03},       // renewal
		{0x03, 0x07, 0x00, 0x00, 0x03},       // add C
		{0x07, 0x03, 0x30, 0x00, 0x07},       // retire C (code 1 in bits 4-5)
		{0x07, 0x06, 0x02, 0x00, 0x07},       // revoke A with its authorisation (code 2 for A)
		{0x07, 0x06, 0x03, 0x00, 0x07},       // revoke A with no authorisation
		{0x03, 0x06, 0x01, 0x00, 0x03},       // add and remove
		{0x07, 0x07, 0x00, 0x00, 0x03, 0x07}, // an earlier list that does not match
		{0x03, 0x07, 0x00, 0x00, 0x03, 0x01}, // a key that came back
		{0x03, 0x03, 0x00, 0x01, 0x03},       // no fingerprints
		{0x03, 0x03, 0x00, 0x02, 0x03},       // the time goes back
		{0x0f, 0x0f, 0x00, 0x00, 0x0f, 0x0f, 0x0f},
	} {
		f.Add(seed)
	}
	poolRoots(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) < 4 || len(data) > 40 {
			return
		}
		labelsOf := func(mask byte) []string {
			var out []string
			for i, l := range []string{"A", "B", "C", "D"} {
				if mask&(1<<i) != 0 {
					out = append(out, l)
				}
			}
			return out
		}
		prevMask, newMask, depCodes, flags := data[0]&0x0f, data[1]&0x0f, data[2], data[3]
		noPrint := flags&1 != 0
		prevLabels, newLabels := labelsOf(prevMask), labelsOf(newMask)
		in := trustset.Input{
			SignedAt:     firstCeremony.Add(time.Hour),
			Roots:        rootsOf(t, noPrint, newLabels...),
			Certificates: certsOf(t, newLabels...),
		}
		if len(newLabels) == 0 {
			in.Certificates = map[string][]byte{}
		}
		if flags&2 != 0 {
			in.SignedAt = firstCeremony.Add(-time.Second)
		}
		var masks []byte
		if len(prevLabels) == 0 {
			in.Sequence = 1
		} else {
			masks = slices.Clone(data[4:])
			in.Sequence = int64(len(masks)) + 1
			if in.Sequence < 2 {
				masks = []byte{prevMask}
				in.Sequence = 2
			}
			masks[len(masks)-1] = prevMask // the last earlier list is the previous list
			in.LastRecordSHA256 = hexOf("end")
			for _, m := range masks {
				if ls := labelsOf(m & 0x0f); len(ls) > 0 {
					in.Earlier = append(in.Earlier, historyList("x", rootsOf(t, noPrint, ls...)))
				} else {
					in.Earlier = append(in.Earlier, history.RootList{Name: "empty"})
				}
			}
			prev, err := trustset.MarshalList(trustset.ListSpec{
				Sequence: in.Sequence - 1, SignedAt: firstCeremony, Roots: rootsOf(t, noPrint, prevLabels...),
				LastRecordSHA256: func() string {
					if in.Sequence-1 == 1 {
						return ""
					}
					return hexOf("old end")
				}(),
			})
			if err != nil {
				return
			}
			in.Previous = prev
		}
		for i, l := range []string{"A", "B", "C", "D"} {
			switch (depCodes >> (2 * i)) & 3 {
			case 1:
				in.Departures = append(in.Departures, trustset.Departure{X509SPKISHA256: newRoot(t, l, true).Pin, Leave: trustset.LeaveRetired})
			case 2:
				in.Departures = append(in.Departures, trustset.Departure{X509SPKISHA256: newRoot(t, l, true).Pin, Leave: trustset.LeaveRevoked, Authorisation: authOf(t, l)})
			case 3:
				in.Departures = append(in.Departures, trustset.Departure{X509SPKISHA256: newRoot(t, l, true).Pin, Leave: trustset.LeaveRevoked})
			}
		}
		d, err := trustset.NewDraft(in)
		lawsOfDraft(t, in, d, err)
	})
}

// FuzzDraftAuthorisation: the bytes are the stored authorisation of a revoked key.
func FuzzDraftAuthorisation(f *testing.F) {
	m := loadVectors(f)
	f.Add([]byte(vectorRemoval(f, m, "A")))
	f.Add([]byte(vectorRemoval(f, m, "B")))
	f.Add([]byte(authOf(f, "A")))
	f.Add([]byte(""))
	f.Add([]byte("a.b.c"))
	f.Add([]byte(strings.Repeat("a", 5000)))
	poolRoots(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		c := newChain(t)
		c.add(next{labels: []string{"A", "B"}})
		dep := trustset.Departure{X509SPKISHA256: newRoot(t, "A", true).Pin, Leave: trustset.LeaveRevoked, Authorisation: string(data)}
		in := c.input(next{labels: []string{"B"}, deps: []trustset.Departure{dep}})
		d, err := trustset.NewDraft(in)
		lawsOfDraft(t, in, d, err)
		if err == nil && len(data) > 0 && string(data) != authOf(t, "A") {
			// Another text was taken: the reader of the page took it as A's authorisation.
			entry := rootlist.Removal{Label: "A", X509SPKISHA256: dep.X509SPKISHA256, Authorisation: dep.Authorisation}
			if cerr := rootlist.CheckRemoval(entry, nil, []string{dep.X509SPKISHA256}); cerr != nil {
				t.Fatalf("an authorisation was taken that the reader refuses: %v", cerr)
			}
		}
	})
}

// FuzzDraftCertificate: the bytes are the certificate of root A of a first list.
func FuzzDraftCertificate(f *testing.F) {
	m := loadVectors(f)
	for _, l := range []string{"A", "B", "C", "Z"} {
		f.Add(m.certificate(f, l))
	}
	f.Add(newRoot(f, "A", true).DER)
	f.Add(newRoot(f, "A", false).DER)
	f.Add(reissue(f, newRoot(f, "A", true), 10).Raw)
	f.Add([]byte{})
	f.Add([]byte{0x30, 0x00})
	for _, p := range [][]byte{vectorFile(f, "pki/test-root-a.pem")} {
		if b, _ := pem.Decode(p); b != nil {
			f.Add(b.Bytes[:len(b.Bytes)/2])
		}
	}
	poolRoots(f)
	f.Fuzz(func(t *testing.T, der []byte) {
		a := newRoot(t, "A", true)
		in := trustset.Input{
			Sequence: 1, SignedAt: firstCeremony,
			Roots:        []trustset.Root{a.entry(true)},
			Certificates: map[string][]byte{"A": der},
		}
		if c, err := x509.ParseCertificate(der); err == nil {
			// The pin of whatever certificate came, so that the pin check is not the only refusal.
			in.Roots[0].X509SPKISHA256 = jws.Pin(c)
		}
		d, err := trustset.NewDraft(in)
		if err != nil {
			lawsOfDraft(t, in, d, err)
			return
		}
		// A certificate was taken: the bundle holds exactly it, and the reader accepts the bundle.
		list, _ := rootlist.ParseList(d.ListJSON())
		if v := rootlist.VerifyCABundle(d.CABundle(), list); !v.Accepted {
			t.Fatalf("the reader refuses the CA bundle: %+v", v)
		}
		certs := bundleCerts(t, d.CABundle())
		if len(certs) != 1 || string(certs[0]) != string(der) {
			t.Fatal("the bundle does not hold the certificate that was given")
		}
	})
}

// FuzzSignerOutput: the bytes are what the signer returns as its signature.
func FuzzSignerOutput(f *testing.F) {
	c := newChain(f)
	d, err := c.draft(next{labels: []string{"A", "B"}})
	if err != nil {
		f.Fatal(err)
	}
	a := newRoot(f, "A", true)
	good, err := a.signer(f).SignES384(mustInput(f, d, a))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(good)
	f.Add(good[:95])
	f.Add(append(slices.Clone(good), 0))
	f.Add(make([]byte, 96))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, sig []byte) {
		s := counting(a.signer(t))
		s.sign = func([]byte) ([]byte, error) { return sig, nil }
		set, err := d.Sign([]trustset.Signer{s}, nil)
		if err != nil {
			if set != nil {
				t.Fatal("a set comes with an error")
			}
			wantOnly(t, err, trustset.ErrSign)
			return
		}
		// Taken: the signature verifies, and the reader accepts the set.
		mustAccept(t, set, nil, firstCeremony)
		if s.count() != 1 {
			t.Fatalf("asked %d times", s.count())
		}
	})
}

// mustInput returns the signing input that the draft has for the key's certificate, from a signer
// that records it.
func mustInput(t testing.TB, d *trustset.Draft, r *testRoot) []byte {
	t.Helper()
	rec := counting(r.signer(t))
	if _, err := d.Sign([]trustset.Signer{rec}, nil); err != nil {
		t.Fatal(err)
	}
	return rec.inputs[0]
}

// FuzzEarlier: the bytes are a history: lines are lists, words are entries, a word is
// label,pin,fingerprint. The last list is made the previous list when it can be written.
func FuzzEarlier(f *testing.F) {
	a, b := newRoot(f, "A", true), newRoot(f, "B", true)
	f.Add([]byte("A," + a.Pin + "," + a.Print + " B," + b.Pin + "," + b.Print))
	f.Add([]byte("A," + a.Pin + " B," + b.Pin + "\nB," + b.Pin))
	f.Add([]byte("A," + a.Pin + " B," + b.Pin + "\nB," + b.Pin + "\nA," + a.Pin + " B," + b.Pin))
	f.Add([]byte("a,x,y\n\n,,"))
	f.Add([]byte(strings.Repeat("A,"+a.Pin+" ", 40)))
	poolRoots(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		var earlier []history.RootList
		lines := strings.Split(string(data), "\n")
		if len(lines) > 60 {
			lines = lines[:60]
		}
		for i, line := range lines {
			l := history.RootList{Name: "list " + string(rune('a'+i%26))}
			for _, word := range strings.Fields(line) {
				parts := strings.SplitN(word, ",", 3)
				k := history.RootKey{Label: parts[0]}
				if len(parts) > 1 {
					k.Pin = parts[1]
				}
				if len(parts) > 2 {
					k.Fingerprint = parts[2]
				}
				l.Keys = append(l.Keys, k)
			}
			earlier = append(earlier, l)
		}
		if len(earlier) == 0 {
			return
		}
		entries := rootsOf(t, false, "A", "B")
		in := trustset.Input{
			Sequence: int64(len(earlier)) + 1, SignedAt: firstCeremony.Add(time.Hour), Roots: entries,
			Certificates: certsOf(t, "A", "B"), LastRecordSHA256: hexOf("end"), Earlier: earlier,
		}
		if in.Sequence == 1 {
			return
		}
		// The previous list is the last earlier list when it can be written, otherwise A and B.
		var spec trustset.ListSpec
		spec.Sequence, spec.SignedAt = in.Sequence-1, firstCeremony
		if in.Sequence-1 > 1 {
			spec.LastRecordSHA256 = hexOf("old")
		}
		for _, k := range earlier[len(earlier)-1].Keys {
			spec.Roots = append(spec.Roots, trustset.Root{Label: k.Label, X509SPKISHA256: k.Pin, OpenPGPFingerprint: k.Fingerprint})
		}
		prev, err := trustset.MarshalList(spec)
		if err != nil {
			spec.Roots = entries
			prev, err = trustset.MarshalList(spec)
			if err != nil {
				return
			}
		}
		in.Previous = prev
		d, err := trustset.NewDraft(in)
		lawsOfDraft(t, in, d, err)
	})
}
