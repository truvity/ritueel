package answer_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"path"
	"strings"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/handoff"
	"ritueel.id/ritueel/internal/handoff/answer"
	"ritueel.id/ritueel/internal/rootlist"
	"ritueel.id/ritueel/internal/testrepo"
)

func wantConfigRefused(t *testing.T, cfg answer.Config) {
	t.Helper()
	c, err := answer.New(cfg)
	if !errors.Is(err, answer.ErrConfig) {
		t.Fatalf("New returned %v, want ErrConfig", err)
	}
	if c != nil {
		t.Error("New returned a Checker with an error")
	}
	// The zero Checker that a caller keeps is as good as none.
	var zero answer.Checker
	if _, err := zero.Check(nil, nil); !errors.Is(err, answer.ErrConfig) {
		t.Errorf("a zero Checker returned %v", err)
	}
}

func TestNewRefusesAConfigurationWithAPartLeftOut(t *testing.T) {
	k := newKit(t)
	base := func(change func(*answer.Config)) answer.Config { return k.config(change) }
	ca := newForeignCA(t, caSpec{})
	t.Run("neither Held nor FloorAnchors", func(t *testing.T) {
		wantConfigRefused(t, base(func(c *answer.Config) { c.Held, c.CABundle = nil, nil }))
	})
	t.Run("both", func(t *testing.T) {
		wantConfigRefused(t, base(func(c *answer.Config) { c.FloorAnchors = [][]byte{ca.file}; c.CABundle, c.Primaries = nil, nil }))
		wantConfigRefused(t, base(func(c *answer.Config) { c.FloorAnchors = [][]byte{ca.file} }))
	})
	t.Run("an empty list of floor anchors", func(t *testing.T) {
		wantConfigRefused(t, floorConfig(t, func(c *answer.Config) { c.FloorAnchors = [][]byte{} }))
	})
	t.Run("a Held made from nothing", func(t *testing.T) {
		wantConfigRefused(t, base(func(c *answer.Config) { c.Held = &rootlist.Held{} }))
	})
	t.Run("a Held with a list that has no roots", func(t *testing.T) {
		wantConfigRefused(t, base(func(c *answer.Config) { c.Held = &rootlist.Held{List: &rootlist.List{Sequence: 7}} }))
	})
	t.Run("no CA bundle", func(t *testing.T) {
		wantConfigRefused(t, base(func(c *answer.Config) { c.CABundle = nil }))
		wantConfigRefused(t, base(func(c *answer.Config) { c.CABundle = []byte{} }))
	})
	t.Run("a CA bundle of other lists and other bundles", func(t *testing.T) {
		held, _ := vectorHeld(t)
		for _, name := range []string{
			"ca-bundle-8-of-list-7.pem", "ca-bundle-8.pem", "ca-bundle-7-extra-certificate.pem", "ca-bundle-7-missing-certificate.pem",
			"ca-bundle-7-wrong-order.pem", "ca-bundle-7-not-a-ca.pem", "ca-bundle-7-signed-by-another-key.pem",
			"ca-bundle-7-issuer-is-another-name.pem",
		} {
			bundle := testrepo.Read(t, "testdata/root-list/v1/bundles", name)
			cfg := vectorConfig(t, readVectorManifest(t))
			cfg.Held, cfg.CABundle = held, bundle
			if name == "ca-bundle-8.pem" {
				// The bundle of list 8 is the bundle of another list than list 7.
				cfg.Held = held
			}
			c, err := answer.New(cfg)
			if !errors.Is(err, answer.ErrConfig) || c != nil {
				t.Errorf("%s: New returned %v", name, err)
			}
		}
	})
	t.Run("a CA bundle that has a byte more or less", func(t *testing.T) {
		for name, b := range map[string][]byte{
			"a line end more":    append(bytes.Clone(k.bundle), '\n'),
			"a byte more":        append(bytes.Clone(k.bundle), 'x'),
			"a byte less":        k.bundle[:len(k.bundle)-1],
			"another sequence":   bytes.Replace(k.bundle, []byte("# trust-sequence: 7"), []byte("# trust-sequence: 8"), 1),
			"no sequence line":   k.bundle[bytes.IndexByte(k.bundle, '\n')+1:],
			"carriage returns":   bytes.ReplaceAll(k.bundle, []byte("\n"), []byte("\r\n")),
			"the sequence in 07": bytes.Replace(k.bundle, []byte("# trust-sequence: 7"), []byte("# trust-sequence: 07"), 1),
		} {
			cfg := k.config(func(c *answer.Config) { c.CABundle = b })
			if _, err := answer.New(cfg); !errors.Is(err, answer.ErrConfig) {
				t.Errorf("%s: New returned %v", name, err)
			}
		}
	})
	t.Run("primaries with the floor", func(t *testing.T) {
		wantConfigRefused(t, floorConfig(t, func(c *answer.Config) { c.Primaries = []handoff.PrimaryRef{k.a.primary.ref()} }, ca))
	})
	t.Run("a CA bundle with the floor", func(t *testing.T) {
		wantConfigRefused(t, floorConfig(t, func(c *answer.Config) { c.CABundle = k.bundle }, ca))
	})
	t.Run("more primaries than the bound", func(t *testing.T) {
		wantConfigRefused(t, base(func(c *answer.Config) {
			c.Primaries = nil
			for i := 0; i < handoff.MaxPrimaries+1; i++ {
				c.Primaries = append(c.Primaries, newPGPKey(t, pgpSubCreated).ref())
			}
		}))
	})
	t.Run("as many primaries as the bound are held", func(t *testing.T) {
		cfg := base(func(c *answer.Config) {
			c.Primaries = nil
			for i := 0; i < handoff.MaxPrimaries; i++ {
				c.Primaries = append(c.Primaries, newPGPKey(t, pgpSubCreated).ref())
			}
		})
		if _, err := answer.New(cfg); err != nil {
			t.Fatalf("New: %v", err)
		}
	})
	primary := func(change func(r *handoff.PrimaryRef)) answer.Config {
		return base(func(c *answer.Config) {
			r := newPGPKey(t, pgpSubCreated).ref()
			change(&r)
			c.Primaries = []handoff.PrimaryRef{r}
		})
	}
	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(r *handoff.PrimaryRef){
		"a nil key":                                      func(r *handoff.PrimaryRef) { r.Key = nil },
		"a key on P-256":                                 func(r *handoff.PrimaryRef) { r.Key = &p256.PublicKey },
		"a creation time with a fraction":                func(r *handoff.PrimaryRef) { r.Created = r.Created.Add(time.Millisecond) },
		"a creation time before 1970":                    func(r *handoff.PrimaryRef) { r.Created = time.Date(1969, 12, 31, 23, 59, 59, 0, time.UTC) },
		"a creation time after 2106":                     func(r *handoff.PrimaryRef) { r.Created = time.Date(2107, 1, 1, 0, 0, 0, 0, time.UTC) },
		"the zero creation time":                         func(r *handoff.PrimaryRef) { r.Created = time.Time{} },
		"a fingerprint in capitals":                      func(r *handoff.PrimaryRef) { r.Fingerprint = strings.ToUpper(r.Fingerprint) },
		"a fingerprint of 39 digits":                     func(r *handoff.PrimaryRef) { r.Fingerprint = r.Fingerprint[:39] },
		"a fingerprint of 41 digits":                     func(r *handoff.PrimaryRef) { r.Fingerprint += "0" },
		"a fingerprint that the key does not give":       func(r *handoff.PrimaryRef) { r.Fingerprint = strings.Repeat("0", 40) },
		"no fingerprint":                                 func(r *handoff.PrimaryRef) { r.Fingerprint = "" },
		"a creation time that gives another fingerprint": func(r *handoff.PrimaryRef) { r.Created = r.Created.Add(time.Second) },
	} {
		t.Run("a primary with "+name, func(t *testing.T) { wantConfigRefused(t, primary(change)) })
	}
	t.Run("two primaries with one fingerprint", func(t *testing.T) {
		wantConfigRefused(t, base(func(c *answer.Config) { c.Primaries = []handoff.PrimaryRef{k.a.primary.ref(), k.a.primary.ref()} }))
	})
	t.Run("a Config with no primaries is held: the check of an OpenPGP answer then cannot be decided", func(t *testing.T) {
		if _, err := answer.New(base(func(c *answer.Config) { c.Primaries = nil })); err != nil {
			t.Fatalf("New: %v", err)
		}
	})
	t.Run("the floor files", func(t *testing.T) {
		two := append(bytes.Clone(ca.file), ca.file...)
		other := newForeignCA(t, caSpec{cn: "Example Other"})
		for name, files := range map[string][][]byte{
			"two certificates in one file":          {two},
			"the same certificate twice":            {ca.file, ca.file},
			"a request":                             {newCSR(t, nil, nil).file},
			"not PEM":                               {[]byte("a CA")},
			"an empty file":                         {{}},
			"a nil file":                            {nil},
			"a file with text before":               {append([]byte("# the CA\n"), ca.file...)},
			"a DER certificate":                     {ca.root.der},
			"a good one and a bad one":              {ca.file, []byte("x")},
			"a certificate file with a header line": {[]byte(strings.Replace(string(ca.file), "\n", "\nProc-Type: 4\n", 1))},
		} {
			cfg := floorConfig(t, func(c *answer.Config) { c.FloorAnchors = files }, other)
			if _, err := answer.New(cfg); !errors.Is(err, answer.ErrConfig) {
				t.Errorf("%s: New returned %v", name, err)
			}
		}
	})
	t.Run("sixty-five floor certificates", func(t *testing.T) {
		var files [][]byte
		for i := 0; i < answer.MaxAnchors+1; i++ {
			files = append(files, newForeignCA(t, caSpec{cn: "Example CA " + string(rune('A'+i%26)) + string(rune('a'+i/26))}).file)
		}
		wantConfigRefused(t, floorConfig(t, func(c *answer.Config) { c.FloorAnchors = files }))
		if _, err := answer.New(floorConfig(t, func(c *answer.Config) { c.FloorAnchors = files[:answer.MaxAnchors] })); err != nil {
			t.Fatalf("sixty-four certificates are held: %v", err)
		}
	})
	t.Run("a floor certificate that is not a CA or has ended is held, and refuses an answer where it is used", func(t *testing.T) {
		notCA := newForeignCA(t, caSpec{notCA: true})
		if _, err := answer.New(floorConfig(t, nil, notCA)); err != nil {
			t.Fatalf("New: %v", err)
		}
	})
	t.Run("the validity", func(t *testing.T) {
		for name, mm := range map[string][2]int{
			"zero":               {0, 0},
			"a minimum of 0":     {0, 14},
			"a negative minimum": {-1, 14},
			"a maximum below":    {13, 12},
			"a maximum of 61":    {12, 61},
			"a minimum of 61":    {61, 61},
			"a negative maximum": {-14, -12},
		} {
			cfg := base(func(c *answer.Config) { c.Validity.MinMonths, c.Validity.MaxMonths = mm[0], mm[1] })
			if _, err := answer.New(cfg); !errors.Is(err, answer.ErrConfig) {
				t.Errorf("%s: New returned %v", name, err)
			}
		}
		for name, mm := range map[string][2]int{"1 to 1": {1, 1}, "60 to 60": {60, 60}, "12 to 14": {12, 14}, "1 to 60": {1, 60}} {
			cfg := base(func(c *answer.Config) { c.Validity.MinMonths, c.Validity.MaxMonths = mm[0], mm[1] })
			if _, err := answer.New(cfg); err != nil {
				t.Errorf("%s: New returned %v", name, err)
			}
		}
	})
	t.Run("no clock", func(t *testing.T) {
		wantConfigRefused(t, base(func(c *answer.Config) { c.Now = nil }))
		wantConfigRefused(t, floorConfig(t, func(c *answer.Config) { c.Now = nil }, ca))
	})
	t.Run("the constants are the ones that the page names", func(t *testing.T) {
		if answer.MaxFileSize != 256*1024 || answer.MaxArtifacts != 4 || answer.MaxReasons != 16 || answer.MaxAnchors != 64 || answer.MaxValidityMonths != 60 || answer.MaxExtensions != 32 {
			t.Errorf("constants %d %d %d %d %d %d", answer.MaxFileSize, answer.MaxArtifacts, answer.MaxReasons, answer.MaxAnchors, answer.MaxValidityMonths, answer.MaxExtensions)
		}
		if answer.FileResult != "result.json" || answer.FileCert != "cert.pem" || answer.FileBound != "bound.pgp" {
			t.Error("the suffixes of the files are not those of the page")
		}
		for code, text := range map[answer.Code]string{
			answer.CodeVersionUnsupported: "version-unsupported", answer.CodeRequestMismatch: "request-mismatch", answer.CodeIssuer: "issuer",
			answer.CodeKeyMismatch: "key-mismatch", answer.CodeProfile: "profile", answer.CodeValidity: "validity", answer.CodeMalformed: "malformed",
		} {
			if string(code) != text {
				t.Errorf("code %q, the page says %q", code, text)
			}
		}
	})
}

// A Checker holds its own copy of everything that it was given.
func TestACheckerHoldsItsOwnCopyOfTheConfiguration(t *testing.T) {
	k := newKit(t)
	cfg := k.config(nil)
	chk := mustChecker(t, cfg)
	x509c, pgpc := k.newX509(nil), k.newPGP("sign")
	if v, err := x509c.check(chk); err != nil || !v.Accepted() {
		t.Fatalf("control: %v", err)
	}
	// Change everything that the Config shares with the caller, then judge the controls again.
	cfg.Primaries[0], cfg.Primaries[1] = cfg.Primaries[1], cfg.Primaries[0]
	cfg.Primaries[0].Fingerprint = strings.Repeat("0", 40)
	cfg.Primaries = nil
	for i := range cfg.CABundle {
		cfg.CABundle[i] = 'x'
	}
	cfg.Held.List.Roots[0].X509SPKISHA256 = strings.Repeat("0", 64)
	cfg.Held.List.Roots[0].OpenPGPFingerprint = strings.Repeat("0", 40)
	cfg.Held.List.Sequence = 1
	cfg.Held.List.ExpiresAt = testNow.Add(-time.Hour)
	cfg.Validity.MinMonths, cfg.Validity.MaxMonths = 1, 1
	if v, err := x509c.check(chk); err != nil || !v.Accepted() || len(v.Warnings) != 0 {
		t.Errorf("an X.509 answer after the Config changed: %v accepted %v warnings %v", err, v.Accepted(), v.Warnings)
	}
	if v, err := pgpc.check(chk); err != nil || !v.Accepted() {
		t.Errorf("an OpenPGP answer after the Config changed: %v accepted %v", err, v.Accepted())
	}

	t.Run("the floor", func(t *testing.T) {
		ca := newForeignCA(t, caSpec{})
		fcfg := floorConfig(t, nil, ca)
		fchk := mustChecker(t, fcfg)
		f := newFloorCase(t, k, ca, certSpec{})
		for i := range fcfg.FloorAnchors[0] {
			fcfg.FloorAnchors[0][i] = 0
		}
		fcfg.FloorAnchors[0] = nil
		v, err := f.check(fchk)
		floorWant(t, v, err, "", floorOK)
	})
}

// A zero Checker, a nil Asked, a nil Answer and an answer with a stem that is not a stem are refused with
// ErrConfig and no verdict.
func TestACheckerThatNewDidNotMakeAndInputsThatAreNotInputsAreRefused(t *testing.T) {
	k := newKit(t)
	chk := k.checker(nil)
	x := k.newX509(nil)
	asked := x.csr.asked(t)
	ans := x.answer()
	var zero answer.Checker
	var nilChecker *answer.Checker
	for name, run := range map[string]func() (answer.Verdict, error){
		"a zero Checker":     func() (answer.Verdict, error) { return zero.Check(asked, ans) },
		"a nil Checker":      func() (answer.Verdict, error) { return nilChecker.Check(asked, ans) },
		"a nil Asked":        func() (answer.Verdict, error) { return chk.Check(nil, ans) },
		"a zero Asked":       func() (answer.Verdict, error) { return chk.Check(&answer.Asked{}, ans) },
		"a nil Answer":       func() (answer.Verdict, error) { return chk.Check(asked, nil) },
		"a stem in capitals": func() (answer.Verdict, error) { return chk.Check(asked, &answer.Answer{Stem: "X", Files: ans.Files}) },
		"no stem":            func() (answer.Verdict, error) { return chk.Check(asked, &answer.Answer{Files: ans.Files}) },
		"a stem of 64": func() (answer.Verdict, error) {
			return chk.Check(asked, &answer.Answer{Stem: strings.Repeat("a", 64), Files: ans.Files})
		},
		"a stem with a dot":  func() (answer.Verdict, error) { return chk.Check(asked, &answer.Answer{Stem: "a.b", Files: ans.Files}) },
		"a stem with a path": func() (answer.Verdict, error) { return chk.Check(asked, &answer.Answer{Stem: "a/b", Files: ans.Files}) },
		"a stem that starts with a hyphen": func() (answer.Verdict, error) {
			return chk.Check(asked, &answer.Answer{Stem: "-a", Files: ans.Files})
		},
	} {
		t.Run(name, func(t *testing.T) {
			v, err := run()
			if !errors.Is(err, answer.ErrConfig) {
				t.Fatalf("error %v, want ErrConfig", err)
			}
			if v.Accepted() || v.AnswerRefused() || v.RequestRefused() || len(v.Checks) != 0 || v.Info != nil {
				t.Errorf("a verdict comes with the error: %+v", v)
			}
		})
	}
	t.Run("a stem of 63 characters and an answer with no map of files", func(t *testing.T) {
		v, err := chk.Check(asked, &answer.Answer{Stem: strings.Repeat("a", 63)})
		want(t, v, err, answer.CodeMalformed, malformedNoVer)
	})
	t.Run("the answer and the request are not changed by a check", func(t *testing.T) {
		before := cloneAnswer(ans)
		if _, err := chk.Check(asked, ans); err != nil {
			t.Fatal(err)
		}
		for name, data := range before.Files {
			if !bytes.Equal(data, ans.Files[name]) {
				t.Errorf("the file %s was changed", name)
			}
		}
		if len(before.Files) != len(ans.Files) {
			t.Error("the files of the answer changed in number")
		}
	})
}

// The requester's own request files.
func TestTheRequestersOwnFilesAreReadByTheRulesOfTheCertifier(t *testing.T) {
	k := newKit(t)
	csr := newCSR(t, nil, nil)
	good := func() *handoff.Request {
		return &handoff.Request{Stem: "example-request", Files: map[string][]byte{
			handoff.FileProof: mustJSONBytes(t, map[string]any{"handoff": 1, "type": "x509-intermediate", "request_sha256": sha256Hex(csr.der), "store": "software"}),
			handoff.FileCSR:   csr.file,
		}}
	}
	t.Run("a good request", func(t *testing.T) {
		a, err := answer.AskedFromRequest(good())
		if err != nil {
			t.Fatal(err)
		}
		x := k.newX509(csr)
		v, err := k.checker(nil).Check(a, x.answer())
		want(t, v, err, "", "ppppppppp")
	})
	refused := func(name string, r *handoff.Request) {
		t.Run(name, func(t *testing.T) {
			a, err := answer.AskedFromRequest(r)
			if !errors.Is(err, answer.ErrConfig) || a != nil {
				t.Fatalf("error %v, Asked %v", err, a)
			}
		})
	}
	refused("a nil request", nil)
	refused("a request with no files", &handoff.Request{Stem: "x"})
	mod := func(f func(r *handoff.Request)) *handoff.Request { r := good(); f(r); return r }
	refused("no proof file", mod(func(r *handoff.Request) { delete(r.Files, handoff.FileProof) }))
	refused("no csr file", mod(func(r *handoff.Request) { delete(r.Files, handoff.FileCSR) }))
	refused("a proof that is not JSON", mod(func(r *handoff.Request) { r.Files[handoff.FileProof] = []byte("x") }))
	refused("a proof of version 2", mod(func(r *handoff.Request) {
		r.Files[handoff.FileProof] = mustJSONBytes(t, map[string]any{"handoff": 2, "type": "x509-intermediate", "request_sha256": sha256Hex(csr.der), "store": "software"})
	}))
	refused("a proof with an unknown member", mod(func(r *handoff.Request) {
		r.Files[handoff.FileProof] = mustJSONBytes(t, map[string]any{"handoff": 1, "type": "x509-intermediate", "request_sha256": sha256Hex(csr.der), "store": "software", "x": 1})
	}))
	refused("a proof of another request", mod(func(r *handoff.Request) {
		r.Files[handoff.FileProof] = mustJSONBytes(t, map[string]any{"handoff": 1, "type": "x509-intermediate", "request_sha256": sha256Hex([]byte("x")), "store": "software"})
	}))
	refused("a proof with the digest of the file and not of the DER", mod(func(r *handoff.Request) {
		r.Files[handoff.FileProof] = mustJSONBytes(t, map[string]any{"handoff": 1, "type": "x509-intermediate", "request_sha256": sha256Hex(csr.file), "store": "software"})
	}))
	refused("a request file that is not a request", mod(func(r *handoff.Request) { r.Files[handoff.FileCSR] = []byte("x") }))
	refused("a proof file over the limit", mod(func(r *handoff.Request) { r.Files[handoff.FileProof] = make([]byte, answer.MaxFileSize+1) }))
	t.Run("the error says what the certifier's reader says", func(t *testing.T) {
		_, err := answer.AskedFromRequest(mod(func(r *handoff.Request) { r.Files[handoff.FileProof] = []byte("x") }))
		if !errors.Is(err, handoff.ErrProofShape) {
			t.Errorf("error %v does not wrap ErrProofShape", err)
		}
	})
	t.Run("AskedX509", func(t *testing.T) {
		for name, file := range map[string][]byte{"nothing": nil, "text": []byte("x"), "a certificate": certPEM(k.a.der), "two blocks": append(bytes.Clone(csr.file), csr.file...)} {
			if a, err := answer.AskedX509(file); !errors.Is(err, answer.ErrConfig) || a != nil {
				t.Errorf("%s: %v %v", name, err, a)
			}
		}
	})
	t.Run("an Asked holds its own copy of the request", func(t *testing.T) {
		file := bytes.Clone(csr.file)
		a, err := answer.AskedX509(file)
		if err != nil {
			t.Fatal(err)
		}
		for i := range file {
			file[i] = 0
		}
		v, err := k.checker(nil).Check(a, k.newX509(csr).answer())
		want(t, v, err, "", "ppppppppp")
		r := good()
		a2, err := answer.AskedFromRequest(r)
		if err != nil {
			t.Fatal(err)
		}
		clear(r.Files)
		v, err = k.checker(nil).Check(a2, k.newX509(csr).answer())
		want(t, v, err, "", "ppppppppp")
	})
	t.Run("an OpenPGP request", func(t *testing.T) {
		r := newPGPRequest(t, []*pgpKey{k.a.primary, k.b.primary}, "sign")
		if _, err := answer.AskedFromRequest(r.request()); err != nil {
			t.Fatal(err)
		}
		refusedP := func(name string, edit func(*handoff.Request)) {
			rq := r.request()
			edit(rq)
			if a, err := answer.AskedFromRequest(rq); !errors.Is(err, answer.ErrConfig) || a != nil {
				t.Errorf("%s: %v %v", name, err, a)
			}
		}
		refusedP("no subkey file", func(q *handoff.Request) { delete(q.Files, handoff.FileSubkey) })
		refusedP("a subkey file over the limit", func(q *handoff.Request) { q.Files[handoff.FileSubkey] = make([]byte, answer.MaxFileSize+1) })
		refusedP("a subkey file of 256 KiB and a byte, with its own digest in the proof", func(q *handoff.Request) {
			big := append(bytes.Clone(r.file()), make([]byte, answer.MaxFileSize+1-len(r.file()))...)
			q.Files[handoff.FileSubkey] = big
			q.Files[handoff.FileProof] = mustJSONBytes(t, map[string]any{"handoff": 1, "type": "openpgp-subkey", "request_sha256": sha256Hex(big),
				"store": "software", "primaries": r.fingerprints(), "capabilities": []string{"sign"}})
		})
		refusedP("a subkey file that is not the digest", func(q *handoff.Request) { q.Files[handoff.FileSubkey] = append(q.Files[handoff.FileSubkey], 0) })
		refusedP("a subkey file that is not packets", func(q *handoff.Request) { q.Files[handoff.FileSubkey] = []byte("x") })
		refusedP("a subkey file with one back-signature for two primaries", func(q *handoff.Request) {
			one := r.subset(1)
			q.Files[handoff.FileSubkey] = one.file()
			q.Files[handoff.FileProof] = mustJSONBytes(t, map[string]any{"handoff": 1, "type": "openpgp-subkey", "request_sha256": sha256Hex(one.file()),
				"store": "software", "primaries": r.fingerprints(), "capabilities": []string{"sign"}})
		})
		two := newPGPRequest(t, []*pgpKey{k.a.primary, k.b.primary}, "sign")
		two.proofEdit = func(m map[string]any) { m["capabilities"] = []string{"sign", "authenticate"} }
		if a, err := answer.AskedFromRequest(two.request()); !errors.Is(err, answer.ErrConfig) || a != nil {
			t.Errorf("two capabilities: %v %v", err, a)
		}
	})
	t.Run("an SSH request is read as far as its digest", func(t *testing.T) {
		c := vectorCase(t, "ssh-piv-valid")
		if a := vectorAsked(t, c); a == nil {
			t.Fatal("no Asked")
		}
		root := vectorRoot(t)
		r, err := handoff.LoadRequest(root, "requests", "ssh-piv-valid")
		if err != nil {
			t.Fatal(err)
		}
		r.Files[handoff.FileSSHKey] = append(r.Files[handoff.FileSSHKey], '\n')
		if a, err := answer.AskedFromRequest(r); !errors.Is(err, answer.ErrConfig) || a != nil {
			t.Errorf("an SSH key file that is not the digest of the proof: %v %v", err, a)
		}
		delete(r.Files, handoff.FileSSHKey)
		if a, err := answer.AskedFromRequest(r); !errors.Is(err, answer.ErrConfig) || a != nil {
			t.Errorf("no SSH key file: %v %v", err, a)
		}
	})
}

// The requester reads the request files of every vector: a request that the certifier accepts is read, one that it
// refuses for its files is refused with ErrConfig or read, and none panics.
func TestTheRequestersReaderMeetsEveryRequestOfTheVectors(t *testing.T) {
	m := readVectorManifest(t)
	if len(m.Requests) < 40 {
		t.Fatalf("the manifest holds %d requests", len(m.Requests))
	}
	read, refused := 0, 0
	for _, c := range m.Requests {
		t.Run(c.ID, func(t *testing.T) {
			stem := ""
			for _, f := range c.Files {
				if s, ok := strings.CutSuffix(path.Base(f), "."+handoff.FileProof); ok {
					stem = s
				}
			}
			if stem == "" {
				t.Fatalf("the case names no proof file: %v", c.Files)
			}
			r, err := handoff.LoadRequest(vectorRoot(t), "requests", stem)
			if err != nil {
				t.Fatalf("LoadRequest: %v", err)
			}
			a, err := answer.AskedFromRequest(r)
			switch {
			case err == nil:
				read++
				if a == nil {
					t.Fatal("no Asked")
				}
			case errors.Is(err, answer.ErrConfig) && a == nil:
				refused++
				if c.Expect == "accept" {
					t.Errorf("a request that the certifier accepts is refused: %v", err)
				}
			default:
				t.Fatalf("error %v, Asked %v", err, a)
			}
		})
	}
	if read < 15 || refused < 10 {
		t.Errorf("%d requests read and %d refused", read, refused)
	}
}

func TestTheSubkeyOfARequestThatIsNotOneThatTheRequesterReadsIsRefusedWithItsOwnDigest(t *testing.T) {
	k := newKit(t)
	r := newPGPRequest(t, []*pgpKey{k.a.primary, k.b.primary}, "sign")
	for name, file := range map[string][]byte{
		"text":                       []byte("not packets"),
		"a signature first":          append(bytes.Clone(r.sigs[0]), r.sigs[1]...),
		"a subkey and no signatures": r.subPacket,
		"a subkey of another curve":  nil,
	} {
		if file == nil {
			continue
		}
		req := r.request()
		req.Files[handoff.FileSubkey] = file
		req.Files[handoff.FileProof] = mustJSONBytes(t, map[string]any{"handoff": 1, "type": "openpgp-subkey", "request_sha256": sha256Hex(file),
			"store": "software", "primaries": r.fingerprints(), "capabilities": []string{"sign"}})
		if a, err := answer.AskedFromRequest(req); !errors.Is(err, answer.ErrConfig) || a != nil {
			t.Errorf("%s: %v %v", name, err, a)
		}
	}
}
