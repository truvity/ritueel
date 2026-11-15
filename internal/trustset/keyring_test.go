package trustset_test

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/bundle"
	"ritueel.id/ritueel/internal/fsx"
	"ritueel.id/ritueel/internal/openpgp"
	"ritueel.id/ritueel/internal/rootlist"
	"ritueel.id/ritueel/internal/trustset"
)

// The keyring file of a trust set, in its first form (docs/reference/keyring-package.md, "The first
// form of the keyring file"; docs/reference/bundle.md, "The layout"): one flat file beside the three
// others, the certificates of the primaries that the root list pins, binary, in the order of the list.

// The name is the name of the page, the file is one flat name that the writer takes, and FileNames
// still lists the three files that every set has.
func TestKeyringFileName(t *testing.T) {
	if trustset.KeyringFile != "keyring.gpg" {
		t.Errorf("KeyringFile = %q", trustset.KeyringFile)
	}
	if err := fsx.CheckName(trustset.KeyringFile); err != nil {
		t.Errorf("the writer does not take the name: %v", err)
	}
	if got := trustset.FileNames(); !slices.Equal(got, []string{"root-list.json", "root-list.jws", "ca-bundle.pem"}) {
		t.Errorf("FileNames = %v", got)
	}
	if slices.Contains(trustset.FileNames(), trustset.KeyringFile) {
		t.Error("FileNames lists the keyring file")
	}
	if strings.ContainsAny(trustset.KeyringFile, "/\\") {
		t.Error("the keyring file is not one flat name")
	}
}

// Two roots: the keyring file is the two certificates joined in the order of the list, its digest is
// the digest of those bytes, Sign gives four files in the order of the names, and the set holds the
// same bytes. A reader that did not make the file reads the same primaries in the same order.
func TestKeyringFirstForm(t *testing.T) {
	d, err := trustset.NewDraft(keyringInput(t, "A", "B"))
	if err != nil {
		t.Fatal(err)
	}
	want := joined(t, "A", "B")
	if !bytes.Equal(d.Keyring(), want) {
		t.Fatalf("the keyring file is not the two certificates in the order of the list")
	}
	sum := sha256.Sum256(want)
	if d.KeyringSHA256() != hex.EncodeToString(sum[:]) {
		t.Errorf("KeyringSHA256 = %q", d.KeyringSHA256())
	}
	if len(d.KeyringSHA256()) != 64 || d.KeyringSHA256() != strings.ToLower(d.KeyringSHA256()) {
		t.Errorf("KeyringSHA256 is not 64 lower-case digits: %q", d.KeyringSHA256())
	}
	// The file is binary: no armour, every packet header has bit 7 set, and the file splits into
	// packets with nothing between and nothing after.
	if bytes.HasPrefix(d.Keyring(), []byte("-----BEGIN")) {
		t.Error("the file is armoured")
	}
	packets := packetsOf(t, d.Keyring())
	if len(packets) != 6 {
		t.Fatalf("%d packets, want key, user ID and one certification for each of two roots", len(packets))
	}
	for i, p := range packets {
		if p[0]&0x80 == 0 {
			t.Errorf("packet %d has no bit 7", i)
		}
		if want := []byte{6, 13, 2}[i%3]; tagOf(p) != want {
			t.Errorf("packet %d has tag %d, want %d", i, tagOf(p), want)
		}
	}
	// Another reader reads the same primaries in the same order.
	if got := readByGoCrypto(t, d.Keyring()); !slices.Equal(got, fingerprintsOf(t, "A", "B")) {
		t.Errorf("go-crypto reads %v", got)
	}
	// The reader of the program takes the file with the entries of the list.
	keys, err := openpgp.ReadKeyring(d.Keyring(), entriesOf(t, "A", "B"))
	if err != nil || len(keys) != 2 {
		t.Fatalf("ReadKeyring: %d keys, %v", len(keys), err)
	}

	set, err := d.Sign(asSigners(signersFor(t, d, nil, nil)), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(set.Keyring(), want) {
		t.Error("the set holds other bytes than the draft")
	}
	files := set.Files()
	var names []string
	for _, f := range files {
		names = append(names, f.Name)
		if f.Perm != trustset.FileMode {
			t.Errorf("%s has mode %v", f.Name, f.Perm)
		}
	}
	if !slices.Equal(names, []string{"root-list.json", "root-list.jws", "ca-bundle.pem", "keyring.gpg"}) {
		t.Errorf("the files are %v", names)
	}
	if !bytes.Equal(files[3].Data, want) {
		t.Error("the fourth file holds other bytes")
	}
}

// The file follows the order of the list, which is the label order, whatever the order of the roots
// that the caller gives and whatever the order that a map is walked in.
func TestKeyringIsInLabelOrder(t *testing.T) {
	for _, order := range [][]string{{"A", "B", "C"}, {"C", "B", "A"}, {"B", "C", "A"}, {"C", "A", "B"}} {
		in := keyringInput(t, order...)
		d, err := trustset.NewDraft(in)
		if err != nil {
			t.Fatalf("%v: %v", order, err)
		}
		if !bytes.Equal(d.Keyring(), joined(t, "A", "B", "C")) {
			t.Errorf("roots given as %v: the file is not A, B, C", order)
		}
		if got := readByGoCrypto(t, d.Keyring()); !slices.Equal(got, fingerprintsOf(t, "A", "B", "C")) {
			t.Errorf("roots given as %v: go-crypto reads %v", order, got)
		}
	}
}

// A certificate that holds more than one certification (the packets that NewPrimary returned, with a
// later certification of ExtendPrimary added) is the certificate of the file as it is.
func TestKeyringKeepsEveryCertification(t *testing.T) {
	a, b := newRoot(t, "A", true), newRoot(t, "B", true)
	more := append(slices.Clone(a.PGP), extension(t, a, 1)...)
	more = append(more, extension(t, a, 2)...)
	in := keyringInput(t, "A", "B")
	in.OpenPGPCertificates["A"] = more
	d, err := trustset.NewDraft(in)
	if err != nil {
		t.Fatal(err)
	}
	if want := slices.Concat(more, b.PGP); !bytes.Equal(d.Keyring(), want) {
		t.Error("the file is not the certificate with its three certifications, and then the other")
	}
	if n := len(packetsOf(t, d.Keyring())); n != 8 {
		t.Errorf("%d packets, want 8", n)
	}
	if _, err := d.Sign(asSigners(signersFor(t, d, nil, nil)), nil); err != nil {
		t.Errorf("Sign: %v", err)
	}
}

// The reader of the keyring file does not read the clock: a primary that has expired at the time of
// the list is taken (the page: "The reader reads no clock").
func TestKeyringDoesNotJudgeExpiry(t *testing.T) {
	a := newRoot(t, "A", true)
	old := &testRoot{Label: "A", Test: true}
	old.PGPKey = a.PGPKey
	p := old.primaryParams(t, primaryCreated.AddDate(0, 1, 0))
	p.ExpiresAt = primaryCreated.AddDate(0, 2, 0)
	cert, err := openpgp.NewPrimary(rand.Reader, p)
	if err != nil {
		t.Fatal(err)
	}
	in := keyringInput(t, "A")
	in.OpenPGPCertificates["A"] = cert
	if _, err := trustset.NewDraft(in); err != nil {
		t.Errorf("a primary that expired before the list was signed is refused: %v", err)
	}
}

// The names agree: a set that Write made is read by Bundle.Primaries, which holds its own copy of the
// name of the file. This test pins the two names (the constant of internal/bundle is not exported).
// The primaries come back with the fingerprints of the list, in the order of the list, for each set
// of a chain; the newest set of the chain pins B only, so its keyring file holds one certificate.
func TestKeyringNameAgreesWithTheBundle(t *testing.T) {
	c := threeSets(t)
	dir := filepath.Join(t.TempDir(), "acme")
	if _, err := bundle.Create(dir, bundle.StarterOptions{TestRoot: true}); err != nil {
		t.Fatal(err)
	}
	w, err := fsx.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = w.Close() }()
	if err := w.Mkdir(bundle.TrustDir, 0o700); err != nil {
		t.Fatal(err)
	}
	wantLabels := [][]string{{"A", "B"}, {"A", "B"}, {"B"}}
	for i, l := range c.links {
		name := l.set.Name()
		if err := l.set.Write(w, bundle.TrustDir+"/"+name); err != nil {
			t.Fatalf("Write %d: %v", i+1, err)
		}
		onDisk, err := os.ReadFile(filepath.Join(dir, bundle.TrustDir, name, trustset.KeyringFile))
		if err != nil {
			t.Fatalf("set %d: the keyring file is not there: %v", i+1, err)
		}
		if !bytes.Equal(onDisk, l.set.Keyring()) || !bytes.Equal(onDisk, joined(t, wantLabels[i]...)) {
			t.Errorf("set %d: the file on disk is not the certificates of %v", i+1, wantLabels[i])
		}
		b, err := bundle.Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		refs, set, err := b.Primaries()
		_ = b.Close()
		if err != nil {
			t.Fatalf("Primaries after set %d: %v", i+1, err)
		}
		if set.Name != name {
			t.Errorf("set %d: the primaries come from %q", i+1, set.Name)
		}
		var got []string
		for _, r := range refs {
			got = append(got, r.Fingerprint)
		}
		if !slices.Equal(got, fingerprintsOf(t, wantLabels[i]...)) {
			t.Errorf("set %d: the primaries are %v", i+1, got)
		}
	}
}

// A list whose roots have no fingerprint writes no keyring file: nothing of today changes. The draft
// and the set have no file and no digest, the files are the three, a set is byte for byte what the
// writers of the list and of the CA bundle make, and an empty map of certificates is the same as none.
func TestNoFingerprintNoKeyringFile(t *testing.T) {
	for _, certs := range []map[string][]byte{nil, {}} {
		in := newChain(t).input(next{labels: []string{"A", "B"}, noPrint: true})
		if in.OpenPGPCertificates != nil {
			t.Fatal("the helper gives certificates to a list with no fingerprint")
		}
		in.OpenPGPCertificates = certs
		d, err := trustset.NewDraft(in)
		if err != nil {
			t.Fatal(err)
		}
		if d.Keyring() != nil || d.KeyringSHA256() != "" {
			t.Errorf("a list with no fingerprint has a keyring file: %d bytes, %q", len(d.Keyring()), d.KeyringSHA256())
		}
		// The bytes are those of the two writers.
		spec := trustset.ListSpec{Sequence: 1, SignedAt: firstCeremony, Roots: rootsOf(t, true, "A", "B")}
		wantList, err := trustset.MarshalList(spec)
		if err != nil {
			t.Fatal(err)
		}
		wantBundle, err := trustset.MarshalCABundle(1, spec.Roots, [][]byte{newRoot(t, "A", true).DER, newRoot(t, "B", true).DER})
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(d.ListJSON(), wantList) || !bytes.Equal(d.CABundle(), wantBundle) {
			t.Error("the bytes of the list or of the CA bundle differ from what the writers make")
		}
		set, err := d.Sign(asSigners(signersFor(t, d, nil, nil)), nil)
		if err != nil {
			t.Fatal(err)
		}
		if set.Keyring() != nil {
			t.Error("the set has a keyring file")
		}
		files := set.Files()
		if len(files) != 3 {
			t.Fatalf("%d files, want 3", len(files))
		}
		for i, f := range files {
			if f.Name != trustset.FileNames()[i] {
				t.Errorf("file %d is %q", i, f.Name)
			}
		}
	}
}

// A set with no keyring file is written as three files, and Bundle.Primaries gives no primary and no
// error for it.
func TestNoFingerprintSetIsThreeFilesOnDisk(t *testing.T) {
	c := newChain(t)
	set := c.add(next{labels: []string{"A", "B"}, noPrint: true})
	dir := filepath.Join(t.TempDir(), "acme")
	if _, err := bundle.Create(dir, bundle.StarterOptions{TestRoot: true}); err != nil {
		t.Fatal(err)
	}
	w, err := fsx.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = w.Close() }()
	if err := w.Mkdir(bundle.TrustDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := set.Write(w, bundle.TrustDir+"/"+set.Name()); err != nil {
		t.Fatal(err)
	}
	ents, err := os.ReadDir(filepath.Join(dir, bundle.TrustDir, set.Name()))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range ents {
		names = append(names, e.Name())
	}
	if !slices.Equal(names, []string{"ca-bundle.pem", "root-list.json", "root-list.jws"}) {
		t.Errorf("the folder holds %v", names)
	}
	b, err := bundle.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = b.Close() }()
	refs, _, err := b.Primaries()
	if err != nil || len(refs) != 0 {
		t.Errorf("Primaries: %d primaries, %v", len(refs), err)
	}
}

// The keyring file is written beside the other files, whole: the keyring file is one of the files of
// the single call to the writer, so the cut test of TestSetWriteCutAtEachStep covers it. A second
// write to the same name fails and changes nothing.
func TestKeyringFileIsWrittenWithTheSet(t *testing.T) {
	_, s := aSet(t)
	w, dir := setDir(t)
	final := "trust/" + s.Name()
	if err := s.Write(w, final); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(final), "keyring.gpg"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, joined(t, "A", "B", "C")) {
		t.Error("the file on disk is not the certificates of A, B and C")
	}
	info, err := os.Stat(filepath.Join(dir, filepath.FromSlash(final), "keyring.gpg"))
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&^0o644 != 0 || info.Mode().Perm()&0o400 == 0 {
		t.Errorf("the file has mode %v", info.Mode())
	}
}

// The keyring file of the vectors: for each list that the vector set holds and that the draft makes,
// the file is the certificates of testdata/root-list/v1/pki/test-primary-*.pgp in the order of the
// list. root-list.json and ca-bundle.pem are tested against the vector bytes in TestVectorDrafts.
func TestVectorKeyringFiles(t *testing.T) {
	m := loadVectors(t)
	primary := func(label string) []byte {
		for _, r := range m.Roots {
			if r.Label == label {
				return vectorFile(t, r.OpenPGP)
			}
		}
		t.Fatalf("no vector root %s", label)
		return nil
	}
	cases := []struct {
		id, previous string
		deps         func() []trustset.Departure
		labels       []string
	}{
		{id: "init-a", labels: []string{"A", "B"}},
		{id: "seq7-a", previous: "seq6-b", labels: []string{"A", "B"}},
		{id: "seq8-abc", previous: "seq7-a", labels: []string{"A", "B", "C"}},
		{
			id: "seq8-b-without-a", previous: "seq7-a", labels: []string{"B"},
			deps: func() []trustset.Departure {
				return []trustset.Departure{{X509SPKISHA256: pinOfVector(t, m, "A"), Leave: trustset.LeaveRevoked, Authorisation: vectorRemoval(t, m, "A")}}
			},
		},
		{
			id: "seq8-ab-without-a", previous: "seq7-a", labels: []string{"B"},
			deps: func() []trustset.Departure {
				return []trustset.Departure{{X509SPKISHA256: pinOfVector(t, m, "A"), Leave: trustset.LeaveRetired}}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			var deps []trustset.Departure
			if tc.deps != nil {
				deps = tc.deps()
			}
			d, err := trustset.NewDraft(vectorInput(t, m, tc.id, tc.previous, deps))
			if err != nil {
				t.Fatal(err)
			}
			var want []byte
			var prints []string
			for _, l := range tc.labels {
				want = append(want, primary(l)...)
			}
			list, err := rootlist.ParseList(d.ListJSON())
			if err != nil {
				t.Fatal(err)
			}
			for _, r := range list.Roots {
				prints = append(prints, r.OpenPGPFingerprint)
			}
			if !bytes.Equal(d.Keyring(), want) {
				t.Errorf("the keyring file is not the vector certificates of %v in the order of the list", tc.labels)
			}
			if got := readByGoCrypto(t, d.Keyring()); !slices.Equal(got, prints) {
				t.Errorf("go-crypto reads %v, the list pins %v", got, prints)
			}
		})
	}
	// seq7-a, from the page's own example: the file is the first primary joined with the second.
	d, err := trustset.NewDraft(vectorInput(t, m, "seq7-a", "seq6-b", nil))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(d.Keyring(), slices.Concat(primary("A"), primary("B"))) {
		t.Error("seq7-a: the file is not the first certificate joined with the second")
	}
}

// The accessors give copies and nothing of a zero or nil draft or set.
func TestKeyringAccessorsGiveCopies(t *testing.T) {
	d, err := trustset.NewDraft(keyringInput(t, "A", "B"))
	if err != nil {
		t.Fatal(err)
	}
	want := joined(t, "A", "B")
	got := d.Keyring()
	for i := range got {
		got[i] = 'x'
	}
	if !bytes.Equal(d.Keyring(), want) {
		t.Error("changing the result of Draft.Keyring changed the draft")
	}
	set, err := d.Sign(asSigners(signersFor(t, d, nil, nil)), nil)
	if err != nil {
		t.Fatal(err)
	}
	got = set.Keyring()
	for i := range got {
		got[i] = 'x'
	}
	if !bytes.Equal(set.Keyring(), want) {
		t.Error("changing the result of Set.Keyring changed the set")
	}
	for _, f := range set.Files() {
		for i := range f.Data {
			f.Data[i] = 'x'
		}
	}
	if !bytes.Equal(set.Keyring(), want) || !bytes.Equal(set.Files()[3].Data, want) {
		t.Error("changing the data of a file changed the set")
	}
	// The input is copied too: a caller that changes its map afterwards changes nothing.
	in := keyringInput(t, "A", "B")
	d2, err := trustset.NewDraft(in)
	if err != nil {
		t.Fatal(err)
	}
	for _, cert := range in.OpenPGPCertificates {
		for i := range cert {
			cert[i] = 0
		}
	}
	if !bytes.Equal(d2.Keyring(), want) {
		t.Error("changing the certificates after NewDraft changed the draft")
	}

	var nilDraft *trustset.Draft
	var zeroDraft trustset.Draft
	var nilSet *trustset.Set
	var zeroSet trustset.Set
	if nilDraft.Keyring() != nil || zeroDraft.Keyring() != nil || nilDraft.KeyringSHA256() != "" || zeroDraft.KeyringSHA256() != "" {
		t.Error("a nil or zero draft gives a keyring file")
	}
	if nilSet.Keyring() != nil || zeroSet.Keyring() != nil {
		t.Error("a nil or zero set gives a keyring file")
	}
}

// A draft that was signed twice gives two sets with the same keyring file, and the same draft signed
// by sixteen goroutines gives equal sets (the draft is read and never written after NewDraft).
func TestKeyringSetsOfOneDraftAreEqual(t *testing.T) {
	d, err := trustset.NewDraft(keyringInput(t, "A", "B"))
	if err != nil {
		t.Fatal(err)
	}
	const n = 16
	sets := make([]*trustset.Set, n)
	errs := make([]error, n)
	signers := make([][]*scriptedSigner, n)
	for i := range signers {
		signers[i] = signersFor(t, d, nil, nil)
	}
	start := make(chan struct{})
	done := make(chan int)
	for i := 0; i < n; i++ {
		go func() {
			<-start
			sets[i], errs[i] = d.Sign(asSigners(signers[i]), nil)
			_ = d.Keyring()
			_ = d.KeyringSHA256()
			done <- i
		}()
	}
	close(start)
	for i := 0; i < n; i++ {
		<-done
	}
	for i := 0; i < n; i++ {
		if errs[i] != nil {
			t.Fatalf("goroutine %d: %v", i, errs[i])
		}
		if !bytes.Equal(sets[i].Keyring(), d.Keyring()) {
			t.Errorf("goroutine %d: another keyring file", i)
		}
		if !bytes.Equal(sets[i].Files()[3].Data, d.Keyring()) {
			t.Errorf("goroutine %d: another fourth file", i)
		}
	}
}

// The call that a list with no fingerprint and no certificates makes (a test root of X.509 only, with
// no OpenPGP primary) gives the bytes that it gave before the keyring file existed. The input is the
// vector pins and certificates of A and B with no fingerprint; the two digests are those that the
// builder gave for it on main before the keyring file, and the set is the three files of today.
func TestNoFingerprintBytesAreThoseOfBefore(t *testing.T) {
	m := loadVectors(t)
	in := trustset.Input{
		Sequence: 1, SignedAt: firstCeremony,
		Roots: []trustset.Root{
			{Label: "A", X509SPKISHA256: pinOfVector(t, m, "A")},
			{Label: "B", X509SPKISHA256: pinOfVector(t, m, "B")},
		},
		Certificates: map[string][]byte{"A": m.certificate(t, "A"), "B": m.certificate(t, "B")},
	}
	d, err := trustset.NewDraft(in)
	if err != nil {
		t.Fatal(err)
	}
	const (
		wantList   = "e5f9e512caeb517921e6c4fd3d079222c5df6ef92ebdc7ad77177bbb178afe6e"
		wantBundle = "9a05367038003efb42296846f79ee73d245e560262bc189772f5ea259832446c"
	)
	if d.ListSHA256() != wantList || d.CABundleSHA256() != wantBundle || d.SetName() != "1-e5f9e512" {
		t.Errorf("the digests are %s, %s and the name %s", d.ListSHA256(), d.CABundleSHA256(), d.SetName())
	}
	if d.Keyring() != nil || d.KeyringSHA256() != "" {
		t.Error("a keyring file for a list that pins none")
	}
}
