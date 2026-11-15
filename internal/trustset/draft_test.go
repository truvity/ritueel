package trustset_test

import (
	"bytes"
	"encoding/json"
	"slices"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/canonjson"
	"ritueel.id/ritueel/internal/rootlist"
	"ritueel.id/ritueel/internal/trustset"
)

func TestKindString(t *testing.T) {
	for k, want := range map[trustset.Kind]string{
		trustset.KindFirst: "first", trustset.KindRenewal: "renewal", trustset.KindAdd: "add",
		trustset.KindRetire: "retire", trustset.KindRevoke: "revoke",
		0: "invalid", -1: "invalid", 6: "invalid", 100: "invalid",
	} {
		if got := k.String(); got != want {
			t.Errorf("Kind(%d).String() = %q, want %q", int(k), got, want)
		}
	}
	// The five kinds are numbered from 1 and the zero value is not one of them.
	if trustset.KindFirst != 1 || trustset.KindRenewal != 2 || trustset.KindAdd != 3 || trustset.KindRetire != 4 || trustset.KindRevoke != 5 {
		t.Error("the kinds are not numbered from 1 in the order of the page")
	}
	if trustset.LeaveRetired != 1 || trustset.LeaveRevoked != 2 {
		t.Error("the two ways of leaving are not numbered from 1")
	}
}

// expect is what a kind of list must show.
type expect struct {
	kind     trustset.Kind
	required []string
	oneOf    []string
	unnamed  []string
	signers  []string // the labels the automatic signers give
	removals []string // the labels in removals
	kids     []string // the labels whose pins are the kids of the file, in order
}

func checkDraft(t *testing.T, c *chain, n next, want expect) *trustset.Set {
	t.Helper()
	d, err := c.draft(n)
	if err != nil {
		t.Fatalf("NewDraft: %v", err)
	}
	if d.Kind() != want.kind {
		t.Errorf("Kind = %v, want %v", d.Kind(), want.kind)
	}
	if d.Sequence() != int64(len(c.links)+1) {
		t.Errorf("Sequence = %d", d.Sequence())
	}
	eq := func(name string, got, want []string) {
		t.Helper()
		if len(got) == 0 && len(want) == 0 {
			return
		}
		if !slices.Equal(got, want) {
			t.Errorf("%s = %v, want %v", name, got, want)
		}
	}
	eq("Required", d.Required(), want.required)
	eq("OneOf", d.OneOf(), want.oneOf)
	eq("Unnamed", d.Unnamed(), want.unnamed)
	set, err := d.Sign(asSigners(signersFor(t, d, nil, nil)), nil)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	eq("Signers", set.Signers(), want.signers)
	var previous []byte
	if len(c.links) > 0 {
		previous = c.last().ListJSON()
	}
	list := mustAccept(t, set, previous, c.input(n).SignedAt)
	var gotRemovals []string
	for _, r := range list.Removals {
		gotRemovals = append(gotRemovals, r.Label)
	}
	eq("removals", gotRemovals, want.removals)
	var wantKids []string
	for _, l := range want.kids {
		wantKids = append(wantKids, newRoot(t, l, true).Pin)
	}
	if got := kidsOf(t, set.ListJWS()); !slices.Equal(got, wantKids) {
		t.Errorf("the kids of root-list.jws are %v, want the pins of %v", got, want.kids)
	}
	// The digests are those of the bytes.
	if d.ListSHA256() != hexOf(string(d.ListJSON())) || d.CABundleSHA256() != hexOf(string(d.CABundle())) {
		t.Error("the digests are not the SHA-256 of the files")
	}
	if !bytes.Equal(d.ListJSON(), set.ListJSON()) || !bytes.Equal(d.CABundle(), set.CABundle()) {
		t.Error("the set does not hold the bytes of the draft")
	}
	if set.Sequence() != d.Sequence() {
		t.Errorf("the set has sequence %d", set.Sequence())
	}
	return set
}

// Every kind, with keys made in memory, built the way a bundle grows.
func TestEveryKind(t *testing.T) {
	t.Run("first", func(t *testing.T) {
		c := newChain(t)
		checkDraft(t, c, next{labels: []string{"A", "B"}}, expect{
			kind: trustset.KindFirst, oneOf: []string{"A", "B"}, signers: []string{"A"}, kids: []string{"A"},
		})
	})
	t.Run("first of one key", func(t *testing.T) {
		c := newChain(t)
		checkDraft(t, c, next{labels: []string{"A"}}, expect{
			kind: trustset.KindFirst, oneOf: []string{"A"}, signers: []string{"A"}, kids: []string{"A"},
		})
	})
	t.Run("renewal", func(t *testing.T) {
		c := newChain(t)
		c.add(next{labels: []string{"A", "B"}})
		checkDraft(t, c, next{labels: []string{"B", "A"}}, expect{
			kind: trustset.KindRenewal, oneOf: []string{"A", "B"}, signers: []string{"A"}, kids: []string{"A"},
		})
	})
	t.Run("add", func(t *testing.T) {
		c := newChain(t)
		c.add(next{labels: []string{"A", "B"}})
		checkDraft(t, c, next{labels: []string{"A", "B", "C"}}, expect{
			kind: trustset.KindAdd, required: []string{"A", "B", "C"}, signers: []string{"A", "B", "C"}, kids: []string{"A", "B", "C"},
		})
	})
	t.Run("retire-carries-no-authorisation", func(t *testing.T) {
		c := newChain(t)
		c.add(next{labels: []string{"A", "B"}})
		c.add(next{labels: []string{"A", "B", "C"}})
		set := checkDraft(t, c, next{labels: []string{"A", "B"}, deps: []trustset.Departure{retire(t, "C")}}, expect{
			kind: trustset.KindRetire, required: []string{"A", "B", "C"}, signers: []string{"A", "B", "C"}, kids: []string{"A", "B", "C"},
		})
		if bytes.Contains(set.ListJSON(), []byte(`"removals"`)) {
			t.Error("a retire has removals")
		}
		// The CA bundle is written without the retired key.
		certs := bundleCerts(t, set.CABundle())
		if len(certs) != 2 || slices.ContainsFunc(certs, func(c []byte) bool { return bytes.Equal(c, newRoot(t, "C", true).DER) }) {
			t.Error("the CA bundle holds the retired key")
		}
	})
	t.Run("revoke-carries-the-authorisation-when-the-key-signs", func(t *testing.T) {
		c := newChain(t)
		c.add(next{labels: []string{"A", "B"}})
		c.add(next{labels: []string{"A", "B", "C"}})
		set := checkDraft(t, c, next{labels: []string{"B", "C"}, deps: []trustset.Departure{revoke(t, "A")}}, expect{
			kind: trustset.KindRevoke, required: []string{"B", "C"}, signers: []string{"B", "C"},
			removals: []string{"A"}, kids: []string{"B", "C"},
		})
		// The entry holds the pin of A and A's stored authorisation, as it was given.
		list, err := rootlist.ParseList(set.ListJSON())
		if err != nil {
			t.Fatal(err)
		}
		if list.Removals[0].X509SPKISHA256 != newRoot(t, "A", true).Pin || list.Removals[0].Label != "A" {
			t.Errorf("the entry of removals is %+v", list.Removals[0])
		}
	})
	t.Run("revoke-without-the-authorisation-when-the-key-signs", func(t *testing.T) {
		c := newChain(t)
		c.add(next{labels: []string{"A", "B"}})
		set := checkDraft(t, c, next{labels: []string{"B"}, deps: []trustset.Departure{revokeLost(t, "A")}}, expect{
			kind: trustset.KindRevoke, required: []string{"A", "B"}, unnamed: []string{"A"}, signers: []string{"A", "B"}, kids: []string{"A", "B"},
		})
		if bytes.Contains(set.ListJSON(), []byte(`"removals"`)) {
			t.Error("a revoke without its authorisation names a key")
		}
	})
	t.Run("revoke of two keys with their authorisations", func(t *testing.T) {
		c := newChain(t)
		c.add(next{labels: []string{"A", "B", "C"}})
		checkDraft(t, c, next{labels: []string{"C"}, deps: []trustset.Departure{revoke(t, "B"), revoke(t, "A")}}, expect{
			kind: trustset.KindRevoke, required: []string{"C"}, signers: []string{"C"}, removals: []string{"A", "B"}, kids: []string{"C"},
		})
	})
	t.Run("revoke of two keys, one authorisation lost", func(t *testing.T) {
		c := newChain(t)
		c.add(next{labels: []string{"A", "B", "C"}})
		checkDraft(t, c, next{labels: []string{"C"}, deps: []trustset.Departure{revokeLost(t, "A"), revoke(t, "B")}}, expect{
			kind: trustset.KindRevoke, required: []string{"A", "C"}, unnamed: []string{"A"}, signers: []string{"A", "C"},
			removals: []string{"B"}, kids: []string{"A", "C"},
		})
	})
	t.Run("revoke of two keys, both lost", func(t *testing.T) {
		c := newChain(t)
		c.add(next{labels: []string{"A", "B", "C"}})
		checkDraft(t, c, next{labels: []string{"C"}, deps: []trustset.Departure{revokeLost(t, "B"), revokeLost(t, "A")}}, expect{
			kind: trustset.KindRevoke, required: []string{"A", "B", "C"}, unnamed: []string{"A", "B"}, signers: []string{"A", "B", "C"}, kids: []string{"A", "B", "C"},
		})
	})
	t.Run("retire of two keys", func(t *testing.T) {
		c := newChain(t)
		c.add(next{labels: []string{"A", "B", "C"}})
		checkDraft(t, c, next{labels: []string{"B"}, deps: []trustset.Departure{retire(t, "C"), retire(t, "A")}}, expect{
			kind: trustset.KindRetire, required: []string{"A", "B", "C"}, signers: []string{"A", "B", "C"}, kids: []string{"A", "B", "C"},
		})
	})
	t.Run("a key without a fingerprint", func(t *testing.T) {
		c := newChain(t)
		c.add(next{labels: []string{"A", "B"}, noPrint: true})
		checkDraft(t, c, next{labels: []string{"A", "B"}, noPrint: true}, expect{
			kind: trustset.KindRenewal, oneOf: []string{"A", "B"}, signers: []string{"A"}, kids: []string{"A"},
		})
	})
	t.Run("26 keys", func(t *testing.T) {
		labels := make([]string, 26)
		for i := range labels {
			labels[i] = string(rune('A' + i))
		}
		c := newChain(t)
		c.add(next{labels: labels})
		checkDraft(t, c, next{labels: labels[:25], deps: []trustset.Departure{retire(t, "Z")}}, expect{
			kind: trustset.KindRetire, required: labels, signers: labels, kids: labels,
		})
	})
}

// A long history: ten lists of every kind, each read by the reader of the page against the one
// before it, and the sequence of each is the one before it plus one.
func TestAChainOfEveryKind(t *testing.T) {
	c := newChain(t)
	steps := []next{
		{labels: []string{"A", "B"}},
		{labels: []string{"A", "B"}},
		{labels: []string{"A", "B", "C"}},
		{labels: []string{"A", "B", "C"}},
		{labels: []string{"B", "C"}, deps: []trustset.Departure{revoke(t, "A")}},
		{labels: []string{"B", "C"}},
		{labels: []string{"B", "C", "D"}},
		{labels: []string{"B", "D"}, deps: []trustset.Departure{retire(t, "C")}},
		{labels: []string{"D"}, deps: []trustset.Departure{revokeLost(t, "B")}},
		{labels: []string{"D", "E"}},
	}
	wantKinds := []trustset.Kind{
		trustset.KindFirst, trustset.KindRenewal, trustset.KindAdd, trustset.KindRenewal, trustset.KindRevoke,
		trustset.KindRenewal, trustset.KindAdd, trustset.KindRetire, trustset.KindRevoke, trustset.KindAdd,
	}
	for i, n := range steps {
		var previous []byte
		if i > 0 {
			previous = c.last().ListJSON()
		}
		set := c.add(n)
		if set.Sequence() != int64(i+1) {
			t.Fatalf("list %d has sequence %d", i+1, set.Sequence())
		}
		if got := c.links[i].draft.Kind(); got != wantKinds[i] {
			t.Errorf("list %d is %v, want %v", i+1, got, wantKinds[i])
		}
		mustAccept(t, set, previous, c.links[i].signed)
	}
}

// root-list.json is what the page says: canonical, the two times 13 months apart as the reader
// computes them, the members the page defines and no other, and the roots in label order.
func TestTheListIsWhatThePageSays(t *testing.T) {
	c := newChain(t)
	c.add(next{labels: []string{"A", "B"}})
	d, err := c.draft(next{labels: []string{"C", "B", "A"}})
	if err != nil {
		t.Fatal(err)
	}
	data := d.ListJSON()
	if ok, err := canonjson.IsCanonical(data); !ok || err != nil {
		t.Errorf("root-list.json is not canonical: %v", err)
	}
	if bytes.HasSuffix(data, []byte("\n")) {
		t.Error("root-list.json has a trailing newline")
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(data, &members); err != nil {
		t.Fatal(err)
	}
	var names []string
	for k := range members {
		names = append(names, k)
	}
	slices.Sort(names)
	if want := []string{"expires_at", "last_record_sha256", "roots", "sequence", "signed_at", "version"}; !slices.Equal(names, want) {
		t.Errorf("members %v, want %v", names, want)
	}
	l, err := rootlist.ParseList(data)
	if err != nil {
		t.Fatal(err)
	}
	if l.Sequence != 2 || l.Version != 1 {
		t.Errorf("sequence %d, version %d", l.Sequence, l.Version)
	}
	if !l.SignedAt.Equal(firstCeremony.Add(time.Hour)) || !l.ExpiresAt.Equal(rootlist.ExpiresFor(l.SignedAt)) {
		t.Errorf("signed_at %v expires_at %v", l.SignedAt, l.ExpiresAt)
	}
	if l.LastRecordSHA256 != lastRecord(2) {
		t.Errorf("last_record_sha256 %q", l.LastRecordSHA256)
	}
	var labels []string
	for _, r := range l.Roots {
		labels = append(labels, r.Label)
	}
	if !slices.Equal(labels, []string{"A", "B", "C"}) {
		t.Errorf("roots are in the order %v", labels)
	}
	// The first list leaves last_record_sha256 out.
	first := c.links[0].set.ListJSON()
	if bytes.Contains(first, []byte("last_record_sha256")) {
		t.Error("the first list has last_record_sha256")
	}
	// The CA bundle is the one of the same list: its first line carries the sequence, in the order of roots.
	if !bytes.HasPrefix(d.CABundle(), []byte("# trust-sequence: 2\n")) {
		t.Errorf("the CA bundle starts %q", d.CABundle()[:30])
	}
	if bytes.Count(d.CABundle(), []byte("-----BEGIN CERTIFICATE-----")) != 3 {
		t.Error("the CA bundle does not hold three certificates")
	}
	// The input did not give the order; the draft sorted a copy and left the input alone.
	in := c.input(next{labels: []string{"C", "B", "A"}})
	if in.Roots[0].Label != "C" {
		t.Fatal("the helper changed the order")
	}
	before := slices.Clone(in.Roots)
	if _, err := trustset.NewDraft(in); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(before, in.Roots) {
		t.Error("NewDraft reordered the roots of the caller")
	}
}

// The signing time may be given in another zone, and is the same instant.
func TestSignedAtInAnotherZone(t *testing.T) {
	c := newChain(t)
	in := c.input(next{labels: []string{"A", "B"}})
	utc, err := trustset.NewDraft(in)
	if err != nil {
		t.Fatal(err)
	}
	in.SignedAt = in.SignedAt.In(time.FixedZone("east", 5*3600+1800))
	east, err := trustset.NewDraft(in)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(utc.ListJSON(), east.ListJSON()) {
		t.Error("the same instant in another zone gives another list")
	}
}

// The end of the month: the 13 months are the page's, written in the list.
func TestTheThirteenMonthsInTheDraft(t *testing.T) {
	for _, tc := range []struct{ signed, expires string }{
		{"2026-01-31T12:00:00Z", "2027-02-28T12:00:00Z"},
		{"2027-01-30T12:00:00Z", "2028-02-29T12:00:00Z"},
		{"2028-02-29T23:59:59Z", "2029-03-29T23:59:59Z"},
	} {
		signed, err := time.Parse(rootlist.TimeLayout, tc.signed)
		if err != nil {
			t.Fatal(err)
		}
		c := newChain(t)
		d, err := c.draft(next{labels: []string{"A"}, at: signed})
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(d.ListJSON(), []byte(`"expires_at":"`+tc.expires+`"`)) {
			t.Errorf("signed %s: %s", tc.signed, d.ListJSON())
		}
	}
}

// A zero and a nil draft refuse everything and give nothing.
func TestZeroAndNilDraft(t *testing.T) {
	for name, d := range map[string]*trustset.Draft{"nil": nil, "zero": {}} {
		if d.Kind() != 0 || d.Sequence() != 0 || d.ListJSON() != nil || d.CABundle() != nil ||
			d.ListSHA256() != "" || d.CABundleSHA256() != "" || d.Required() != nil || d.OneOf() != nil || d.Unnamed() != nil {
			t.Errorf("%s draft gives something", name)
		}
		s := counting(newRoot(t, "A", true).signer(t))
		set, err := d.Sign([]trustset.Signer{s}, nil)
		if set != nil {
			t.Errorf("%s draft gave a set", name)
		}
		wantOnly(t, err, trustset.ErrParams)
		if s.count() != 0 {
			t.Errorf("%s draft asked a key", name)
		}
		got, err := d.SigningInputSHA256(newRoot(t, "A", true).Cert)
		if got != "" {
			t.Errorf("%s draft gave a digest", name)
		}
		wantOnly(t, err, trustset.ErrParams)
	}
}

// The accessors return copies: changing a result changes nothing in the draft.
func TestDraftAccessorsReturnCopies(t *testing.T) {
	c := newChain(t)
	c.add(next{labels: []string{"A", "B"}})
	d, err := c.draft(next{labels: []string{"A", "B", "C"}})
	if err != nil {
		t.Fatal(err)
	}
	listJSON, bundle := d.ListJSON(), d.CABundle()
	req := d.Required()
	listJSON[0], bundle[0], req[0] = 'X', 'X', "Z"
	if bytes.Equal(d.ListJSON(), listJSON) || bytes.Equal(d.CABundle(), bundle) || d.Required()[0] != "A" {
		t.Error("an accessor gave the draft's own bytes")
	}
	r, err := c.draft(next{labels: []string{"A", "B"}})
	if err != nil {
		t.Fatal(err)
	}
	oo := r.OneOf()
	oo[0] = "Q"
	if r.OneOf()[0] != "A" {
		t.Error("OneOf gave the draft's own bytes")
	}
	lost, err := func() (*trustset.Draft, error) {
		cc := newChain(t)
		cc.add(next{labels: []string{"A", "B"}})
		return cc.draft(next{labels: []string{"B"}, deps: []trustset.Departure{revokeLost(t, "A")}})
	}()
	if err != nil {
		t.Fatal(err)
	}
	u := lost.Unnamed()
	u[0] = "Q"
	if lost.Unnamed()[0] != "A" {
		t.Error("Unnamed gave the draft's own bytes")
	}
}

// Changing the input after NewDraft changes nothing in the draft.
func TestDraftKeepsCopiesOfTheInput(t *testing.T) {
	c := newChain(t)
	c.add(next{labels: []string{"A", "B"}})
	c.add(next{labels: []string{"A", "B", "C"}})
	in := c.input(next{labels: []string{"A", "B"}, deps: []trustset.Departure{revoke(t, "C")}})
	d, err := trustset.NewDraft(in)
	if err != nil {
		t.Fatal(err)
	}
	wantList, wantBundle := d.ListJSON(), d.CABundle()
	in.Roots[0].Label = "Z"
	in.Roots[1].X509SPKISHA256 = hexOf("other")
	for k := range in.Certificates {
		in.Certificates[k][0] ^= 0xff
		delete(in.Certificates, k)
	}
	in.Previous[0] = '['
	in.Earlier[0].Keys[0].Pin = "x"
	in.Earlier = in.Earlier[:1]
	in.Departures[0].Authorisation = "x"
	in.Departures[0].Leave = trustset.LeaveRetired
	if !bytes.Equal(d.ListJSON(), wantList) || !bytes.Equal(d.CABundle(), wantBundle) {
		t.Error("the files of the draft changed")
	}
	// Signing still works and the reader accepts the result, against the previous list as it was.
	prev := c.last().ListJSON()
	set, err := d.Sign(asSigners(signersFor(t, d, nil, nil)), nil)
	if err != nil {
		t.Fatalf("Sign after the input was changed: %v", err)
	}
	mustAccept(t, set, prev, firstCeremony.Add(3*time.Hour))
}

// What the draft holds before any key is touched: the digests of both files, and nothing from a
// signer.
func TestTheDigestsNeedNoKey(t *testing.T) {
	c := newChain(t)
	d, err := c.draft(next{labels: []string{"A", "B"}})
	if err != nil {
		t.Fatal(err)
	}
	a, err := c.draft(next{labels: []string{"B", "A"}})
	if err != nil {
		t.Fatal(err)
	}
	if d.ListSHA256() != a.ListSHA256() || d.CABundleSHA256() != a.CABundleSHA256() {
		t.Error("the same input in another order gives another digest")
	}
	if len(d.ListSHA256()) != 64 || len(d.CABundleSHA256()) != 64 || d.ListSHA256() == d.CABundleSHA256() {
		t.Error("the digests are not two SHA-256 values")
	}
	// A list of another sequence or another time has another digest.
	b, err := c.draft(next{labels: []string{"A", "B"}, at: firstCeremony.Add(5 * time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	if b.ListSHA256() == d.ListSHA256() {
		t.Error("another time, the same digest")
	}
	if b.CABundleSHA256() != d.CABundleSHA256() {
		t.Error("the CA bundle depends on the time")
	}
}
