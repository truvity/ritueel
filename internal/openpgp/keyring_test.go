package openpgp_test

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/openpgp"
)

// The keyring file of a trust set, first form: the certificates of the primaries, in the order of the
// root list, each held to the fingerprint of its entry. These tests read what the page and record 0009
// say, and use go-crypto as a second reader for every file that is accepted.

func TestTheLimitsAreTheOnesThatArePublished(t *testing.T) {
	if openpgp.MaxKeyringBytes != 1<<20 || openpgp.MaxKeyringCertificates != 26 || openpgp.MaxCertifications != 256 {
		t.Errorf("limits %d, %d, %d; want 1 MiB, 26 and 256", openpgp.MaxKeyringBytes, openpgp.MaxKeyringCertificates, openpgp.MaxCertifications)
	}
	if openpgp.MaxKeyringPackets != 26*(2+256) {
		t.Errorf("the packet limit is %d, want 26 * (2 + 256)", openpgp.MaxKeyringPackets)
	}
	if openpgp.MaxCertificationBody != 512 || openpgp.MaxBindingSubpackets != 32 || openpgp.MaxUserIDBytes != 1024 {
		t.Errorf("certification body %d, subpackets %d, user ID %d; want 512, 32 and 1024",
			openpgp.MaxCertificationBody, openpgp.MaxBindingSubpackets, openpgp.MaxUserIDBytes)
	}
}

func TestTheKindsOfARefusedKeyringAreOneKindWithTwoChildren(t *testing.T) {
	if errors.Unwrap(openpgp.ErrKeyring) != nil {
		t.Error("ErrKeyring wraps another error, want none")
	}
	for _, kind := range []error{openpgp.ErrKeyringForm, openpgp.ErrKeyringPrimaries} {
		if !errors.Is(kind, openpgp.ErrKeyring) {
			t.Errorf("%v is not an ErrKeyring", kind)
		}
		if errors.Is(kind, openpgp.ErrParams) {
			t.Errorf("%v is an ErrParams", kind)
		}
	}
	if errors.Is(openpgp.ErrKeyringForm, openpgp.ErrKeyringPrimaries) || errors.Is(openpgp.ErrKeyringPrimaries, openpgp.ErrKeyringForm) {
		t.Error("the two kinds of a refused keyring are each other's kind")
	}
	if errors.Is(openpgp.ErrKeyring, openpgp.ErrParams) {
		t.Error("ErrKeyring is an ErrParams")
	}
}

func TestTheReaderOpensNoFileAndKnowsNoFileName(t *testing.T) {
	for _, name := range []string{"keyring.go", "primary.go"} {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, name, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range f.Imports {
			path, _ := strconv.Unquote(imp.Path.Value)
			switch path {
			case "os", "io/fs", "io/ioutil", "path", "path/filepath", "net", "net/http", "os/exec", "syscall":
				t.Errorf("%s imports %q: the reader takes bytes and opens nothing", name, path)
			}
		}
	}
	src, err := os.ReadFile("keyring.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"keyring.gpg", "keyring.asc", "root-list"} {
		if bytes.Contains(src, []byte(name)) {
			t.Errorf("keyring.go names %q: the reader knows no file name", name)
		}
	}
}

func TestTheTwoVectorPrimariesJoinedAreTheKeyringOfTheirRootList(t *testing.T) {
	v := loadVectorKeyring(t)
	if len(v.want) != 2 || v.want[0].Label != "A" || v.want[1].Label != "B" {
		t.Fatalf("the vector list gives %v, want the labels A and B", v.want)
	}
	keys := assertRead(t, "a || b", cat(v.a, v.b), v.want)
	for i, k := range keys {
		if !k.Created().Equal(created) {
			t.Errorf("primary %d was created at %v, want %v (the creation time of the key packet)", i, k.Created(), created)
		}
		if k.PublicKey() == nil {
			t.Errorf("primary %d has no public key", i)
		}
	}
	// The key that the reader returns is the key of the key packet, which a second reader holds too.
	for i, file := range [][]byte{v.a, v.b} {
		x := loadRingKey(t, file)
		if !keys[i].PublicKey().Equal(x) {
			t.Errorf("primary %d is not the key that go-crypto reads from the packet", i)
		}
	}
}

func TestOneVectorPrimaryIsTheKeyringOfOneEntry(t *testing.T) {
	v := loadVectorKeyring(t)
	assertRead(t, "a", v.a, v.want[:1])
	assertRead(t, "b", v.b, v.want[1:])
}

func TestTheVectorPrimariesAreReadWhateverTheHeaderFormOfTheirPackets(t *testing.T) {
	v := loadVectorKeyring(t)
	both := cat(v.a, v.b)
	// The vector files use the five-octet length. The shortest new form and the old format hold the
	// same packets and the same key (RFC 9580, section 4.2).
	for _, form := range []string{"new1", "new5", "old1", "old2", "old4"} {
		file := repack(t, both, form)
		if form != "new5" && bytes.Equal(file, both) {
			t.Fatalf("form %s changed no packet", form)
		}
		assertRead(t, "a || b in "+form, file, v.want)
	}
}

func TestACertificateIsReadWhateverTheHeaderFormOfEachOfItsPackets(t *testing.T) {
	m := newKeyringPrimary(t, "A", true)
	for _, form := range []string{"new1", "new5", "old1", "old2", "old4"} {
		for _, tag := range []byte{tagPublicKey, tagUserID, tagSignature} {
			var out []byte
			for _, p := range splitPackets(t, m.good(t)) {
				pkt := p.Raw
				if p.Tag == tag {
					var ok bool
					if pkt, ok = packetIn(form, p.Tag, p.Body); !ok {
						t.Fatalf("form %s does not hold a packet of tag %d", form, tag)
					}
				}
				out = append(out, pkt...)
			}
			assertRead(t, fmt.Sprintf("tag %d in %s", tag, form), out, wantOf(m), m)
		}
	}
}

func TestAUserIDOfTwoHundredBytesIsHeldByTheTwoOctetLength(t *testing.T) {
	// The user ID is the only packet of a certificate that can pass 191 bytes and stay below 8384.
	m := keyringPrimaryOf(t, genKey(t), "A", true, created, strings.Repeat("a", 170)+"@example.org")
	if n := len(m.uid); n < 192 || n > 8383 {
		t.Fatalf("the user ID is %d bytes, want one the two-octet length holds", n)
	}
	file := m.good(t)
	if ps := splitPackets(t, file); ps[1].HeaderLen != 3 {
		t.Fatalf("the user ID packet has a header of %d octets, want 3", ps[1].HeaderLen)
	}
	assertRead(t, "two-octet length", file, wantOf(m), m)
	assertRead(t, "five-octet length", repack(t, file, "new5"), wantOf(m), m)
	assertRead(t, "old two-octet length", repack(t, file, "old2"), wantOf(m), m)
}

func TestCertificatesThatNewPrimaryWritesAreReadInTheOrderOfTheList(t *testing.T) {
	for _, test := range []bool{true, false} {
		ms := []keyringPrimary{newKeyringPrimary(t, "A", test), newKeyringPrimary(t, "B", test), newKeyringPrimary(t, "C", test)}
		file := cat(ms[0].cert(t), ms[1].cert(t), ms[2].cert(t))
		keys := assertRead(t, fmt.Sprintf("three primaries, test=%v", test), file, wantOf(ms...), ms...)
		if len(keys) != 3 {
			t.Fatalf("%d primaries, want 3", len(keys))
		}
	}
}

func TestTheLabelsOfTheListNeedNotBeInOrderOrNextToEachOther(t *testing.T) {
	// The reader holds the file to the order of the list, whatever the labels are.
	ms := []keyringPrimary{newKeyringPrimary(t, "Z", true), newKeyringPrimary(t, "C", true), newKeyringPrimary(t, "M", true)}
	assertRead(t, "Z, C, M", cat(ms[0].cert(t), ms[1].cert(t), ms[2].cert(t)), wantOf(ms...), ms...)
}

func TestTwentySixPrimariesAreTheMostThatAreRead(t *testing.T) {
	var ms []keyringPrimary
	var file []byte
	for c := 'A'; c <= 'Z'; c++ {
		m := newKeyringPrimary(t, string(c), true)
		ms = append(ms, m)
		file = append(file, m.good(t)...)
	}
	keys := assertRead(t, "A to Z", file, wantOf(ms...), ms...)
	if len(keys) != openpgp.MaxKeyringCertificates {
		t.Errorf("%d primaries, want %d", len(keys), openpgp.MaxKeyringCertificates)
	}
}

func TestACertificateWithTheCertificationsOfExtendPrimaryIsRead(t *testing.T) {
	m := newKeyringPrimary(t, "A", true)
	cert := m.cert(t)
	for i := 1; i <= 3; i++ {
		cert = append(cert, m.extension(t, ceremony.Add(time.Duration(i)*24*time.Hour))...)
	}
	if got := tags(splitPackets(t, cert)); !bytes.Equal(got, []byte{6, 13, 2, 2, 2, 2}) {
		t.Fatalf("tags % d, want 6 13 2 2 2 2", got)
	}
	assertRead(t, "four certifications", cert, wantOf(m), m)
}

func TestACertificateWithTwoHundredAndFiftySixCertificationsIsRead(t *testing.T) {
	m := newKeyringPrimary(t, "A", true)
	cert := m.cert(t)
	for i := 1; i < openpgp.MaxCertifications; i++ {
		cert = append(cert, m.extension(t, ceremony.Add(time.Duration(i)*time.Second))...)
	}
	if got := len(splitPackets(t, cert)); got != 2+openpgp.MaxCertifications {
		t.Fatalf("%d packets, want %d", got, 2+openpgp.MaxCertifications)
	}
	assertRead(t, "256 certifications", cert, wantOf(m), m)
}

func TestTwoCertificationsOfTheSameMomentAreInCreationOrder(t *testing.T) {
	m := newKeyringPrimary(t, "A", true)
	cert := cat(m.cert(t), m.extension(t, ceremony))
	assertRead(t, "two certifications at one moment", cert, wantOf(m), m)
}

func TestACertificationMadeAtTheMomentTheKeyWasCreatedIsNotBeforeIt(t *testing.T) {
	m := newKeyringPrimary(t, "A", true)
	cert := m.assemble(m.sig(t, m.at, nil))
	assertRead(t, "a certification at the creation time of the key", cert, wantOf(m), m)
}

func TestACreationTimeWithTheHighBitSetIsTheYear2038AndIsRead(t *testing.T) {
	// The page gives the years 1970 to 2106 and refuses only the time 0 (what NewPrimaryKey accepts).
	at := time.Unix(1<<31+5, 0).UTC()
	m := keyringPrimaryOf(t, genKey(t), "A", true, at, "release@example.org")
	p := m.params(at.Add(time.Hour))
	cert, err := openpgp.NewPrimary(rand.Reader, p)
	if err != nil {
		t.Fatalf("NewPrimary: %v", err)
	}
	keys := assertRead(t, "created in 2038", cert, wantOf(m), m)
	if !keys[0].Created().Equal(at) {
		t.Errorf("created at %v, want %v", keys[0].Created(), at)
	}
	last := time.Unix(1<<32-1, 0).UTC()
	m = keyringPrimaryOf(t, genKey(t), "A", true, last, "release@example.org")
	file := m.assemble(m.sig(t, last, func(sp *sigSpec) { sp.Hashed[2].Data = u32(1) }))
	assertRead(t, "created in the last second of 2106", file, wantOf(m), m)
}

func TestARealPrimaryAndATestPrimaryAreEachReadAlone(t *testing.T) {
	for _, test := range []bool{true, false} {
		m := newKeyringPrimary(t, "A", test)
		assertRead(t, fmt.Sprintf("test=%v", test), m.good(t), wantOf(m), m)
	}
}

func TestTwoPrimariesOfOneKindAreReadAndTheyAreTheNegativeControlOfAMix(t *testing.T) {
	for _, test := range []bool{true, false} {
		a, b := newKeyringPrimary(t, "A", test), newKeyringPrimary(t, "B", test)
		assertRead(t, fmt.Sprintf("two of one kind, test=%v", test), cat(a.good(t), b.good(t)), wantOf(a, b), a, b)
	}
}

// The builder and the reader are one check.

func TestWhatTheBuilderWritesTheReaderReadsAndNoOtherCertificationIsRead(t *testing.T) {
	m := newKeyringPrimary(t, "A", true)
	for i, cert := range [][]byte{m.cert(t), m.good(t)} {
		pkts := splitPackets(t, cert)
		created, life, err := openpgp.CheckCertificationBytes(pkts[2].Raw, pkts[0].Raw, m.uid, m.at)
		if err != nil {
			t.Fatalf("certificate %d: the shared check refuses it: %v", i, err)
		}
		if !created.Equal(ceremony) || life != m.life(ceremony) {
			t.Errorf("certificate %d: created %v, life %d; want %v and %d", i, created, life, ceremony, m.life(ceremony))
		}
	}
}

func TestTheSelfSignatureOfExtendPrimaryIsReadByTheSharedCheck(t *testing.T) {
	m := newKeyringPrimary(t, "A", false)
	key := m.keyPacket()
	at := ceremony.AddDate(0, 6, 0)
	if _, _, err := openpgp.CheckCertificationBytes(m.extension(t, at), key, m.uid, ceremony); err != nil {
		t.Errorf("the shared check refuses the signature of ExtendPrimary: %v", err)
	}
	if _, _, err := openpgp.CheckCertificationBytes(m.extension(t, ceremony), key, m.uid, at); err == nil {
		t.Error("a signature made before the one that precedes it was accepted")
	}
}

func TestASignerThatReturnsASignatureThatDoesNotVerifyGivesNoCertificateAndNoCertification(t *testing.T) {
	for name, f := range map[string]func(p openpgp.PrimaryParams) ([]byte, error){
		"NewPrimary":    func(p openpgp.PrimaryParams) ([]byte, error) { return openpgp.NewPrimary(rand.Reader, p) },
		"ExtendPrimary": func(p openpgp.PrimaryParams) ([]byte, error) { return openpgp.ExtendPrimary(rand.Reader, p) },
	} {
		s := newSigner(t)
		other := genKey(t)
		s.sign = func(digest []byte) ([]byte, error) { return ecdsaSign(other, digest), nil }
		assertRefused(t, name, func() ([]byte, error) { return f(s.params()) }, openpgp.ErrSignature)
	}
}

// What the vector files are, held against the reader: no change of one bit leaves a file accepted.

func TestNoChangeOfOneBitOfAVectorPrimaryLeavesItAcceptedAndNoCutDoes(t *testing.T) {
	v := loadVectorKeyring(t)
	want := v.want[:1]
	assertRead(t, "the file as it is", v.a, want)
	accepted := 0
	for i := range v.a {
		for bit := 0; bit < 8; bit++ {
			file := bytes.Clone(v.a)
			file[i] ^= 1 << bit
			keys, err := readSafely(t, fmt.Sprintf("byte %d bit %d", i, bit), file, want)
			if err == nil {
				accepted++
				t.Errorf("byte %d bit %d changed and the file is still accepted (%d primaries)", i, bit, len(keys))
			}
		}
	}
	for n := 0; n < len(v.a); n++ {
		if _, err := readSafely(t, fmt.Sprintf("cut at %d", n), v.a[:n], want); err == nil {
			t.Errorf("the first %d bytes of %d are accepted", n, len(v.a))
		}
	}
	if accepted != 0 {
		t.Errorf("%d single-bit changes were accepted", accepted)
	}
}

func TestEveryByteOfACertificateThatNewPrimaryWroteIsHeldByTheReader(t *testing.T) {
	m := newKeyringPrimary(t, "A", true)
	cert := m.cert(t)
	for i := range cert {
		file := bytes.Clone(cert)
		file[i] ^= 0x01
		if _, err := readSafely(t, fmt.Sprintf("byte %d", i), file, wantOf(m)); err == nil {
			t.Errorf("a change of the lowest bit of byte %d of %d is accepted", i, len(cert))
		}
	}
}

// What the caller hands over and what comes back.

func TestTheReaderChangesNeitherItsFileNorItsListAndReturnsKeysThatAreCopies(t *testing.T) {
	v := loadVectorKeyring(t)
	file, want := cat(v.a, v.b), slices.Clone(v.want)
	fileBefore := bytes.Clone(file)
	keys := assertRead(t, "first read", file, want)
	// A caller that changes the file or the list afterwards changes nothing that was returned.
	fp0, at0 := keys[0].Fingerprint(), keys[0].Created()
	pub := keys[0].PublicKey()
	x, err := pub.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	clear(file)
	want[0].Fingerprint = strings.Repeat("0", 40)
	if got, _ := keys[0].PublicKey().Bytes(); keys[0].Fingerprint() != fp0 || !keys[0].Created().Equal(at0) || !bytes.Equal(got, x) {
		t.Error("a change of the file or of the list changed a returned primary")
	}
	// The key that comes back is a copy: changing it changes nothing in the next read.
	//nolint:staticcheck // the coordinates are the only way to show that a returned key is a copy
	pub.X.SetInt64(7)
	again := assertRead(t, "second read", fileBefore, v.want)
	if got, _ := again[0].PublicKey().Bytes(); !bytes.Equal(got, x) {
		t.Error("a change of a returned key changed the next read")
	}
	if keys[0] == again[0] {
		t.Error("two reads returned the same primary object")
	}
}

func TestTheReaderIsReadByManyGoroutinesAtOnceAndAllGetTheSame(t *testing.T) {
	v := loadVectorKeyring(t)
	file := cat(v.a, v.b)
	const n = 8
	start := make(chan struct{})
	var wg sync.WaitGroup
	results := make([][]string, n)
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			keys, err := openpgp.ReadKeyring(file, v.want)
			errs[i] = err
			for _, k := range keys {
				results[i] = append(results[i], k.Fingerprint())
			}
		}()
	}
	close(start)
	wg.Wait()
	for i := 0; i < n; i++ {
		if errs[i] != nil {
			t.Errorf("goroutine %d: %v", i, errs[i])
		}
		if !slices.Equal(results[i], []string{v.want[0].Fingerprint, v.want[1].Fingerprint}) {
			t.Errorf("goroutine %d got %v", i, results[i])
		}
	}
}

// The worst file that the limits allow. The limits do not hold all at once: 26 certificates of 256
// certifications are about 1.1 MB, more than the file may be. The largest file has 26 certificates and
// as many certifications as fit in the size limit.

func TestTheLargestFileThatTheLimitsAllowIsReadOnceAndItsTimeIsLogged(t *testing.T) {
	if testing.Short() || openpgp.RaceEnabled {
		t.Skip("six thousand signature checks: not under -short and not under the race detector")
	}
	const labels = openpgp.MaxKeyringCertificates
	probe := newKeyringPrimary(t, "A", true)
	sigSize := len(probe.sig(t, ceremony, nil))
	base := len(probe.assemble())
	n := (openpgp.MaxKeyringBytes - labels*base) / (labels * sigSize)
	if n >= openpgp.MaxCertifications {
		t.Fatalf("%d certifications fit in each of 26 certificates: the limits hold at once, and this test no longer shows the largest file", n)
	}
	var ms []keyringPrimary
	var certs [][]byte
	total := 0
	for c := 0; c < labels; c++ {
		m := newKeyringPrimary(t, string(rune('A'+c)), true)
		cert := m.keyPacket()
		cert = append(cert, m.uidPacket()...)
		for i := 0; i < n; i++ {
			cert = append(cert, m.sig(t, ceremony.Add(time.Duration(i)*time.Second), nil)...)
		}
		ms, certs, total = append(ms, m), append(certs, cert), total+len(cert)
	}
	// Fill what is left of the size limit with more certifications, from the last certificate back.
	have := make([]int, labels)
	for c := range have {
		have[c] = n
	}
	count := n * labels
	for c := labels - 1; c >= 0; c-- {
		for have[c] < openpgp.MaxCertifications {
			sig := ms[c].sig(t, ceremony.Add(time.Duration(have[c])*time.Second), nil)
			if total+len(sig) > openpgp.MaxKeyringBytes {
				break
			}
			certs[c], total, count, have[c] = append(certs[c], sig...), total+len(sig), count+1, have[c]+1
		}
	}
	file := cat(certs...)
	if len(file) > openpgp.MaxKeyringBytes {
		t.Fatalf("the file has %d bytes, more than the limit %d", len(file), openpgp.MaxKeyringBytes)
	}
	load, _ := os.ReadFile("/proc/loadavg")
	start := time.Now()
	keys, err := openpgp.ReadKeyring(file, wantOf(ms...))
	took := time.Since(start)
	if err != nil {
		t.Fatalf("the largest file that the limits allow is refused: %v", err)
	}
	t.Logf("the worst file: %d bytes, %d certificates, %d certifications in all (%d to %d for each), %d signature checks, read in %v by ReadKeyring alone; load average %s",
		len(file), len(keys), count, slices.Min(have), slices.Max(have), count, took, strings.TrimSpace(string(load)))
	assertRead(t, "26 certificates of the most certifications that fit", file, wantOf(ms...), ms...)
}

// callsIn returns the names that the function fn of a file calls, by the tests' own reading of the
// source: a plain call f(...) gives "f", a method call x.m(...) gives "m".
func callsIn(t *testing.T, file, fn string) map[string]bool {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), file, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	calls := map[string]bool{}
	found := false
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || fd.Name.Name != fn {
			continue
		}
		found = true
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			if c, ok := n.(*ast.CallExpr); ok {
				switch f := c.Fun.(type) {
				case *ast.Ident:
					calls[f.Name] = true
				case *ast.SelectorExpr:
					calls[f.Sel.Name] = true
				}
			}
			return true
		})
	}
	if !found {
		t.Fatalf("%s has no function %s", file, fn)
	}
	return calls
}

func TestTheBuilderAndTheReaderCallTheOneSharedCheckOfACertification(t *testing.T) {
	if !callsIn(t, "primary.go", "selfSign")["checkCertification"] {
		t.Error("selfSign does not call checkCertification: the builder does not read back its own certification by the shared check")
	}
	if !callsIn(t, "keyring.go", "readCertificates")["checkCertification"] {
		t.Error("readCertificates does not call checkCertification")
	}
	// There is no second way to verify a certification: the signature is verified in one function.
	for _, file := range []string{"primary.go", "keyring.go"} {
		f, err := parser.ParseFile(token.NewFileSet(), file, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Name.Name == "verifyCertification" {
				continue
			}
			if callsIn(t, file, fd.Name.Name)["VerifyUserIdSignature"] {
				t.Errorf("%s: %s verifies a certification by itself, beside the shared check", file, fd.Name.Name)
			}
		}
	}
}
