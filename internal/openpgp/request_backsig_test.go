package openpgp_test

import (
	"bytes"
	"crypto/rand"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/openpgp"
	"ritueel.id/ritueel/internal/testrepo"
)

// One reader of a back-signature. BindSubkey signs a binding that holds the back-signature, and the
// hand-off check accepts a request only if the ceremony could bind it, so the two must decide the
// same on every back-signature (record 0009, rule 8; the contract page, "The request").

// oneReaderCase is a back-signature of one shape, and what both functions must say of it.
type oneReaderCase struct {
	table  string
	name   string
	tweak  func(*sigSpec)
	accept bool
	// foreign makes the signature with another key than the subkey's, with the issuer fields of the
	// subkey.
	foreign bool
}

// oneReaderCases is every table of back-signatures that the tests of BindSubkey use, with each
// table's own verdict, plus the faults that no table of BindSubkey holds because they are not about
// the shape: a signature by another key that names the subkey as its issuer.
func oneReaderCases() []oneReaderCase {
	var out []oneReaderCase
	for _, sh := range backSigShapes(backTimes{subAt: subAt, ceremony: ceremony}) {
		out = append(out, oneReaderCase{table: "shapes", name: sh.name, tweak: sh.tweak, accept: sh.kind == accept})
	}
	for _, c := range strictRefusals() {
		out = append(out, oneReaderCase{table: "strict refusals", name: c.name, tweak: c.tweak})
	}
	for _, c := range faultsPutRight() {
		out = append(out, oneReaderCase{table: "faults put right", name: c.name, tweak: c.tweak, accept: true})
	}
	for _, c := range pageLengthFaults() {
		out = append(out, oneReaderCase{table: "page lengths", name: c.name, tweak: c.tweak})
	}
	for _, c := range subpacketTypeFaults() {
		out = append(out, oneReaderCase{table: "subpacket types", name: c.name, tweak: c.tweak})
	}
	out = append(out,
		oneReaderCase{table: "other", name: "a signature by another key that names the subkey as its issuer", foreign: true},
		oneReaderCase{table: "other", name: "the SHA-256 hash with its own digest", tweak: func(sp *sigSpec) { sp.Hash = 8 }},
		oneReaderCase{table: "other", name: "the SHA-512 hash with its own digest", tweak: func(sp *sigSpec) { sp.Hash = 10 }},
		oneReaderCase{table: "other", name: "a signature of type 0x18", tweak: func(sp *sigSpec) { sp.Type = 0x18 }},
		oneReaderCase{table: "other", name: "a signature of type 0x13", tweak: func(sp *sigSpec) { sp.Type = 0x13 }},
		oneReaderCase{table: "other", name: "a signature of type 0x00", tweak: func(sp *sigSpec) { sp.Type = 0x00 }},
		oneReaderCase{table: "other", name: "a signature of type 0x1F", tweak: func(sp *sigSpec) { sp.Type = 0x1F }},
		oneReaderCase{table: "other", name: "a signature of type 0x20", tweak: func(sp *sigSpec) { sp.Type = 0x20 }},
		oneReaderCase{table: "other", name: "a signature of type 0x19 as the plain control", accept: true},
	)
	return out
}

// Every case of every table: BindSubkey and VerifyBackSignature decide alike, the refusals are
// request errors of the right kinds, and a refusal never reaches the signer.
func TestBindSubkeyAndVerifyBackSignatureDecideAlikeOnEveryTableOfBackSignatures(t *testing.T) {
	cases := oneReaderCases()
	tables := map[string]int{}
	accepted, refused := 0, 0
	for _, c := range cases {
		tables[c.table]++
		s, b, m := bindFixture(t)
		sig := backSig(t, m.Key, m.Created, m.Primary, m.PrimaryAt, c.tweak)
		if c.foreign {
			// The signature is made by another key, with the issuer fields of the subkey: it is whole
			// and its hash tag is right, and it does not verify with the subkey.
			sig = backSig(t, genKey(t), m.Created, m.Primary, m.PrimaryAt, func(sp *sigSpec) {
				fp := fingerprint(&m.Key.PublicKey, m.Created)
				sp.Hashed[1].Data = append([]byte{4}, fp...)
				sp.Unhashed[0].Data = fp[12:]
				sp.Data = [][]byte{hashPrefix(m.Primary, m.PrimaryAt), hashPrefix(&m.Key.PublicKey, m.Created)}
			})
		}
		b.BackSig = sig
		_, bindErr := openpgp.BindSubkey(rand.Reader, b)

		primary, err := openpgp.NewPrimaryKey(&s.key.PublicKey, created)
		if err != nil {
			t.Fatal(err)
		}
		sub, err := openpgp.ReadSubkey(m.Packet)
		if err != nil {
			t.Fatal(err)
		}
		verErr := openpgp.VerifyBackSignature(sig, primary, sub, ceremony)

		if (bindErr == nil) != c.accept || (verErr == nil) != c.accept {
			t.Errorf("%s / %s: BindSubkey error %v, VerifyBackSignature error %v, the table says accepted=%v", c.table, c.name, bindErr, verErr, c.accept)
			continue
		}
		if c.accept {
			accepted++
			if s.calls != 1 {
				t.Errorf("%s / %s: the signer was asked %d times, want once", c.table, c.name, s.calls)
			}
			continue
		}
		refused++
		if !errors.Is(bindErr, openpgp.ErrRequest) || errors.Is(bindErr, openpgp.ErrParams) {
			t.Errorf("%s / %s: BindSubkey error = %v, want an ErrRequest", c.table, c.name, bindErr)
		}
		if !isRequestError(verErr, openpgp.ErrBackSignature) {
			t.Errorf("%s / %s: VerifyBackSignature error = %v, want an ErrBackSignature", c.table, c.name, verErr)
		}
		if s.calls != 0 {
			t.Errorf("%s / %s: the signer was asked %d times for a refused back-signature", c.table, c.name, s.calls)
		}
	}
	// A check that finds nothing to check fails: every table is there and none is thin.
	for _, want := range []struct {
		table string
		n     int
	}{{"shapes", 200}, {"strict refusals", 30}, {"faults put right", 8}, {"page lengths", 12}, {"subpacket types", 1000}, {"other", 8}} {
		if tables[want.table] < want.n {
			t.Errorf("the table %q has %d cases, want at least %d", want.table, tables[want.table], want.n)
		}
	}
	if accepted < 20 || refused < 1000 {
		t.Errorf("%d accepted and %d refused back-signatures", accepted, refused)
	}
}

// BindSubkey and VerifyBackSignature are one reader in the source as well, not only by agreement: both
// call checkBackSig, nothing else in the package reads the shape of a back-signature, and there is
// no second function with a name that says it does.
func TestBindSubkeyAndVerifyBackSignatureCallTheOneFunctionThatDecidesAndNoSecondReaderExists(t *testing.T) {
	dir := testrepo.Path(t, "internal", "openpgp")
	fset := token.NewFileSet()
	files := map[string]*ast.File{}
	for _, name := range []string{"bind.go", "request.go", "sign.go", "key.go", "frame.go", "primary.go", "revoke.go", "userid.go", "errors.go"} {
		f, err := parser.ParseFile(fset, dir+"/"+name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		files[name] = f
	}
	callsOf := func(fn *ast.FuncDecl) map[string]int {
		out := map[string]int{}
		ast.Inspect(fn, func(n ast.Node) bool {
			if c, ok := n.(*ast.CallExpr); ok {
				if id, ok := c.Fun.(*ast.Ident); ok {
					out[id.Name]++
				}
			}
			return true
		})
		return out
	}
	find := func(name string) *ast.FuncDecl {
		for _, f := range files {
			for _, d := range f.Decls {
				if fn, ok := d.(*ast.FuncDecl); ok && fn.Name.Name == name && fn.Recv == nil {
					return fn
				}
			}
		}
		t.Fatalf("the function %s is not in the package", name)
		return nil
	}
	if n := callsOf(find("BindSubkey"))["checkBackSig"]; n != 1 {
		t.Errorf("BindSubkey calls checkBackSig %d times, want once", n)
	}
	if n := callsOf(find("VerifyBackSignature"))["checkBackSig"]; n != 1 {
		t.Errorf("VerifyBackSignature calls checkBackSig %d times, want once", n)
	}
	// Who calls checkBackSig: those two and nobody else.
	var callers []string
	for _, f := range files {
		for _, d := range f.Decls {
			if fn, ok := d.(*ast.FuncDecl); ok && fn.Name.Name != "checkBackSig" && callsOf(fn)["checkBackSig"] > 0 {
				callers = append(callers, fn.Name.Name)
			}
		}
	}
	sort.Strings(callers)
	if got := strings.Join(callers, " "); got != "BindSubkey VerifyBackSignature" {
		t.Errorf("checkBackSig is called by %q, want exactly BindSubkey and VerifyBackSignature", got)
	}
	// And no function of the package whose name speaks of a back-signature, a signature check or a
	// subkey reader exists beside the ones that are known.
	known := map[string]bool{
		"checkBackSig": true, "checkBackSigTimes": true, "checkBackSigEnd": true, "VerifyBackSignature": true,
		"readSubkey": true, "checkSubkeyKind": true, "parseSubkey": true, "ReadSubkey": true, "SplitSubkeyFile": true,
		"checkIssuers": true, "NewPrimaryKey": true, "BindSubkey": true,
	}
	for name, f := range files {
		for _, d := range f.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Recv != nil {
				continue
			}
			lower := strings.ToLower(fn.Name.Name)
			if (strings.Contains(lower, "backsig") || strings.Contains(lower, "subkey")) && !known[fn.Name.Name] {
				t.Errorf("%s has an unexpected function %s: a second reader?", name, fn.Name.Name)
			}
		}
	}
}

// The unexported reader of a subkey is the one behind both ReadSubkey and BindSubkey: a packet
// that ReadSubkey refuses is refused by BindSubkey as an ErrRequest of the same kind, and one that
// ReadSubkey accepts is not refused as a fault of the subkey.
func TestBindSubkeyReadsTheSubkeyWithTheSameReaderAsReadSubkey(t *testing.T) {
	body := subkeyBody(t)
	packets := map[string][]byte{
		"the plain subkey":               wrap(tagSubkey, body),
		"the old format":                 oldHeader(tagSubkey, body),
		"a five-octet length":            wrapLong(tagSubkey, body),
		"a primary key packet":           wrap(tagPublicKey, body),
		"version 6":                      wrap(tagSubkey, bodyWith(body, setByte(0, 6))),
		"EdDSA":                          wrap(tagSubkey, bodyWith(body, setByte(5, 22))),
		"P-521":                          wrap(tagSubkey, bodyWith(body, withOID(oidP521))),
		"one byte after the point":       wrap(tagSubkey, append(bytes.Clone(body), 0)),
		"a creation time of zero":        wrap(tagSubkey, bodyWith(body, func(b []byte) []byte { copy(b[1:5], make([]byte, 4)); return b })),
		"a packet and a stray byte":      append(wrap(tagSubkey, body), 0),
		"an empty packet":                nil,
		"a cut packet":                   wrap(tagSubkey, body)[:50],
		"a creation time after ceremony": wrap(tagSubkey, keyBody(&genKey(t).PublicKey, ceremony.Add(time.Second))),
	}
	for name, pkt := range packets {
		t.Run(name, func(t *testing.T) {
			s, b, _ := bindFixture(t)
			b.Subkey = pkt
			_, readErr := openpgp.ReadSubkey(pkt)
			_, bindErr := openpgp.BindSubkey(rand.Reader, b)
			if readErr != nil {
				if !errors.Is(bindErr, openpgp.ErrRequest) {
					t.Errorf("ReadSubkey refuses (%v), BindSubkey says %v", readErr, bindErr)
				}
				for _, kind := range []error{openpgp.ErrForm, openpgp.ErrAlgorithm} {
					if errors.Is(readErr, kind) != errors.Is(bindErr, kind) {
						t.Errorf("ReadSubkey says %v and BindSubkey says %v: not the same kind", readErr, bindErr)
					}
				}
				if s.calls != 0 {
					t.Errorf("the signer was asked %d times", s.calls)
				}
			}
			if readErr == nil && bindErr != nil && (errors.Is(bindErr, openpgp.ErrForm) || errors.Is(bindErr, openpgp.ErrAlgorithm)) {
				t.Errorf("ReadSubkey accepts the packet and BindSubkey refuses it as %v", bindErr)
			}
		})
	}
}

// Every single bit of a valid back-signature: the signature packet is accepted exactly as it is, and
// no change of one bit is accepted that the independent reader of the page refuses. Every prefix of
// it and every addition to it is refused.
func TestNoChangeOfOneBitOfAValidBackSignatureIsAcceptedAndNoPrefixOrAdditionEither(t *testing.T) {
	primaryA := primaryOf(t, "a")
	pubA, _ := vectorPrimary(t, "a")
	subRaw, sigs, err := openpgp.SplitSubkeyFile(subkeyFile(t, "pgp-software-valid"), 16)
	if err != nil {
		t.Fatal(err)
	}
	sub, err := openpgp.ReadSubkey(subRaw)
	if err != nil {
		t.Fatal(err)
	}
	sig := sigs[0]
	if err := openpgp.VerifyBackSignature(sig, primaryA, sub, ceremony); err != nil {
		t.Fatalf("the control: %v", err)
	}
	accepted, tried := 0, 0
	for i := range sig {
		for bit := 0; bit < 8; bit++ {
			m := bytes.Clone(sig)
			m[i] ^= 1 << bit
			tried++
			err := openpgp.VerifyBackSignature(m, primaryA, sub, ceremony)
			if err == nil {
				accepted++
				if !pageAcceptsBackSig(t, pubA, created, subRaw, m) {
					t.Errorf("bit %d of byte %d: accepted, and the independent reader of the page refuses it", bit, i)
				}
				t.Logf("bit %d of byte %d changed: still accepted", bit, i)
				continue
			}
			if !isRequestError(err, openpgp.ErrBackSignature) {
				t.Errorf("bit %d of byte %d: error %v is not an ErrBackSignature", bit, i, err)
			}
		}
	}
	if tried != len(sig)*8 {
		t.Fatalf("%d changes tried, want %d", tried, len(sig)*8)
	}
	if accepted != 0 {
		t.Errorf("%d changes of one bit are accepted", accepted)
	}
	for n := 0; n < len(sig); n++ {
		if err := openpgp.VerifyBackSignature(sig[:n], primaryA, sub, ceremony); !isRequestError(err, openpgp.ErrBackSignature) {
			t.Errorf("the first %d bytes: error %v, want an ErrBackSignature", n, err)
		}
	}
	for _, extra := range [][]byte{{0}, {0xFF}, {0xC2, 0x00}, sig, bytes.Repeat([]byte{0}, 1000)} {
		if err := openpgp.VerifyBackSignature(append(bytes.Clone(sig), extra...), primaryA, sub, ceremony); !isRequestError(err, openpgp.ErrBackSignature) {
			t.Errorf("%d bytes added: error %v, want an ErrBackSignature", len(extra), err)
		}
	}
}

// Packets of the wrong kind, signatures of the wrong version or algorithm, and packets of absurd
// size and count in the place of a back-signature are refused with an ErrBackSignature and never
// panic.
func TestHostileBackSignaturesAreRefusedAndNeverPanic(t *testing.T) {
	s := newSigner(t)
	m := newSubkey(t, &s.key.PublicKey, created, subAt)
	primary, err := openpgp.NewPrimaryKey(&s.key.PublicKey, created)
	if err != nil {
		t.Fatal(err)
	}
	sub, err := openpgp.ReadSubkey(m.Packet)
	if err != nil {
		t.Fatal(err)
	}
	body := splitPackets(t, m.BackSig)[0].Body
	_, primaryPackets := vectorPrimary(t, "a")
	manyHashed := func(sp *sigSpec) {
		for range 20000 {
			sp.Hashed = append(sp.Hashed, sub0Pad())
		}
	}
	manyUnhashed := func(sp *sigSpec) {
		for range 20000 {
			sp.Unhashed = append(sp.Unhashed, sub0Pad())
		}
	}
	nested := func(sp *sigSpec) {
		// A signature whose unhashed area holds a signature, nested three levels deep.
		inner := body
		for range 3 {
			inner = parseWrapEmbedded(t, m, inner)
		}
		sp.Unhashed = append(sp.Unhashed, sub0{Type: 32, Data: inner})
	}
	cases := map[string][]byte{
		"no bytes":                                     nil,
		"one byte":                                     {0xC2},
		"a header with a length and no body":           {0xC2, 0x05},
		"a signature with the version 3":               wrap(tagSignature, bodyWith(body, setByte(0, 3))),
		"a signature with the version 5":               wrap(tagSignature, bodyWith(body, setByte(0, 5))),
		"a signature with the version 6":               wrap(tagSignature, bodyWith(body, setByte(0, 6))),
		"a signature with the version 0":               wrap(tagSignature, bodyWith(body, setByte(0, 0))),
		"a signature of type 0x18":                     wrap(tagSignature, bodyWith(body, setByte(1, 0x18))),
		"a signature of type 0x1F":                     wrap(tagSignature, bodyWith(body, setByte(1, 0x1F))),
		"RSA in the place of ECDSA":                    wrap(tagSignature, bodyWith(body, setByte(2, 1))),
		"EdDSA in the place of ECDSA":                  wrap(tagSignature, bodyWith(body, setByte(2, 22))),
		"SHA-256 in the place of SHA-384":              wrap(tagSignature, bodyWith(body, setByte(3, 8))),
		"SHA-512 in the place of SHA-384":              wrap(tagSignature, bodyWith(body, setByte(3, 10))),
		"hash identifier 0":                            wrap(tagSignature, bodyWith(body, setByte(3, 0))),
		"hash identifier 255":                          wrap(tagSignature, bodyWith(body, setByte(3, 255))),
		"a hashed area that is longer than the packet": wrap(tagSignature, bodyWith(body, func(b []byte) []byte { b[4], b[5] = 0xFF, 0xFF; return b })),
		"a hashed area of the length of the packet":    wrap(tagSignature, bodyWith(body, func(b []byte) []byte { b[4], b[5] = byte(len(b)>>8), byte(len(b)); return b })),
		"an unhashed area that is longer than the packet": wrap(tagSignature, func() []byte {
			b := bytes.Clone(body)
			hl := int(b[4])<<8 | int(b[5])
			b[6+hl], b[7+hl] = 0xFF, 0xFF
			return b
		}()),
		"a subkey packet in the place of a signature":     m.Packet,
		"a primary key packet":                            primaryPackets[0].Raw,
		"a user ID packet":                                primaryPackets[1].Raw,
		"the self-signature of a primary":                 primaryPackets[2].Raw,
		"a literal data packet (tag 11)":                  wrap(11, body),
		"a marker packet (tag 10)":                        wrap(10, []byte("PGP")),
		"a signature with tag 0":                          wrap(0, body),
		"a signature with tag 63":                         wrap(63, body),
		"a signature with an indeterminate length":        append([]byte{0x80 | tagSignature<<2 | 3}, body...),
		"a signature with a partial length":               append([]byte{0xC2, 0xE5}, body...),
		"a signature with a length of 4 GiB":              append([]byte{0xC2, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, body...),
		"a signature packet of one mebibyte of zeros":     wrap(tagSignature, make([]byte, 1<<20)),
		"one mebibyte of zeros that is no packet":         make([]byte, 1<<20),
		"one mebibyte of 0xC2":                            bytes.Repeat([]byte{0xC2}, 1<<20),
		"two signatures in the place of one":              append(bytes.Clone(m.BackSig), m.BackSig...),
		"a signature whose length is a lie by one":        append(wrap(tagSignature, body)[:1], append([]byte{byte(len(body) + 1)}, body...)...),
		"a signature and a stray byte":                    append(bytes.Clone(m.BackSig), 0x00),
		"twenty thousand hashed subpackets":               buildWith(t, m, manyHashed),
		"twenty thousand unhashed subpackets":             buildWith(t, m, manyUnhashed),
		"a signature nested three levels in itself":       buildWith(t, m, nested),
		"a hashed area of 60000 bytes of one subpacket":   buildWith(t, m, func(sp *sigSpec) { sp.Hashed = append(sp.Hashed, sub0{Type: 100, Data: make([]byte, 60000)}) }),
		"a subpacket of 65000 bytes in the unhashed area": buildWith(t, m, func(sp *sigSpec) { sp.Unhashed = append(sp.Unhashed, sub0{Type: 100, Data: make([]byte, 65000)}) }),
	}
	for name, sig := range cases {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panic: %v", r)
				}
			}()
			err := openpgp.VerifyBackSignature(sig, primary, sub, ceremony)
			if !isRequestError(err, openpgp.ErrBackSignature) {
				t.Errorf("error = %v, want an ErrBackSignature", err)
			}
			// BindSubkey says the same of the same bytes, and never asks the signer.
			b := openpgp.BindParams{Primary: s.params(), Subkey: m.Packet, BackSig: sig, Capability: "sign", ExpiresAt: ceremony.AddDate(1, 0, 0)}
			if _, err := openpgp.BindSubkey(rand.Reader, b); !errors.Is(err, openpgp.ErrRequest) {
				t.Errorf("BindSubkey error = %v, want an ErrRequest", err)
			}
			if s.calls != 0 {
				t.Errorf("the signer was asked %d times", s.calls)
			}
		})
	}
}

// sub0 is the subpacket of the test builder; sub0Pad is a small subpacket of an unknown type.
type sub0 = sub

func sub0Pad() sub0 { return sub0{Type: 100, Data: []byte{1}} }

// buildWith builds the back-signature of the subkey with one change.
func buildWith(t testing.TB, m subkeyMaterial, tweak func(*sigSpec)) []byte {
	t.Helper()
	return backSig(t, m.Key, m.Created, m.Primary, m.PrimaryAt, tweak)
}

// parseWrapEmbedded makes a signature body that holds the given body as an embedded signature in its
// unhashed area.
func parseWrapEmbedded(t testing.TB, m subkeyMaterial, inner []byte) []byte {
	t.Helper()
	pkt := backSig(t, m.Key, m.Created, m.Primary, m.PrimaryAt, func(sp *sigSpec) {
		sp.Unhashed = append(sp.Unhashed, sub0{Type: 32, Data: inner})
	})
	return splitPackets(t, pkt)[0].Body
}

// Many goroutines read and verify through the same keys. The goroutines are started behind a closed
// channel and joined with a wait group, and each writes only its own result. The race detector, when
// it is on, finds a shared write.
func TestTheReaderAndTheKeysAreSafeForManyGoroutinesAtOnce(t *testing.T) {
	a, b := primaryOf(t, "a"), primaryOf(t, "b")
	file := subkeyFile(t, "pgp-software-valid")
	subRaw, sigs, err := openpgp.SplitSubkeyFile(file, 16)
	if err != nil {
		t.Fatal(err)
	}
	sub, err := openpgp.ReadSubkey(subRaw)
	if err != nil {
		t.Fatal(err)
	}
	const workers, rounds = 16, 20
	results := make([][]string, workers)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for w := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for range rounds {
				if err := openpgp.VerifyBackSignature(sigs[0], a, sub, ceremony); err != nil {
					results[w] = append(results[w], "A/1: "+err.Error())
				}
				if err := openpgp.VerifyBackSignature(sigs[1], b, sub, ceremony); err != nil {
					results[w] = append(results[w], "B/2: "+err.Error())
				}
				if err := openpgp.VerifyBackSignature(sigs[0], b, sub, ceremony); !errors.Is(err, openpgp.ErrBackSignature) {
					results[w] = append(results[w], "B/1 accepted or wrong kind")
				}
				s2, g2, err := openpgp.SplitSubkeyFile(file, 16)
				if err != nil || len(g2) != 2 {
					results[w] = append(results[w], "split failed")
				}
				r, err := openpgp.ReadSubkey(s2)
				if err != nil || r.Fingerprint() != sub.Fingerprint() {
					results[w] = append(results[w], "read failed")
				}
				// A copy that a goroutine changes is its own.
				k := a.PublicKey()
				k.X.SetInt64(int64(w)) //nolint:staticcheck // the coordinates are the only way to change a key in place
				if a.Fingerprint() != "d3780197fa25eb09d7027128ab3de854e11fe959" {
					results[w] = append(results[w], "fingerprint changed")
				}
			}
		}()
	}
	close(start)
	wg.Wait()
	for w, r := range results {
		for _, msg := range r {
			t.Errorf("worker %d: %s", w, msg)
		}
	}
}
