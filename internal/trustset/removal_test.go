package trustset_test

import (
	"bytes"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/jws"
	"ritueel.id/ritueel/internal/rootlist"
	"ritueel.id/ritueel/internal/trustset"
)

// removalParts splits a compact JWS into its three parts and decodes the first two.
func removalParts(t testing.TB, text string) (protected, payload []byte, parts []string) {
	t.Helper()
	parts = strings.Split(text, ".")
	if len(parts) != 3 {
		t.Fatalf("%d parts, want 3", len(parts))
	}
	var err error
	if protected, err = base64.RawURLEncoding.DecodeString(parts[0]); err != nil {
		t.Fatalf("protected: %v", err)
	}
	if payload, err = base64.RawURLEncoding.DecodeString(parts[1]); err != nil {
		t.Fatalf("payload: %v", err)
	}
	return protected, payload, parts
}

func TestNewRemovalIsAValidAuthorisation(t *testing.T) {
	for _, label := range []string{"A", "C", "Z"} {
		r := newRoot(t, label, true)
		text := r.removal(t)
		entry := rootlist.Removal{Label: label, X509SPKISHA256: r.Pin, Authorisation: text}
		// The pin is the only held key, as the host holds it when the key is on its list.
		if err := rootlist.CheckRemoval(entry, nil, []string{r.Pin}); err != nil {
			t.Errorf("%s: %v", label, err)
		}
		// Against a candidate list that no longer holds the key.
		other := &rootlist.List{Version: 1, Sequence: 2, Roots: []rootlist.Root{{Label: "B", X509SPKISHA256: hexOf("another")}}}
		if err := rootlist.CheckRemoval(entry, other, []string{r.Pin}); err != nil {
			t.Errorf("%s against a list without it: %v", label, err)
		}
		// Against a candidate list that still holds the key it does not apply.
		still := &rootlist.List{Version: 1, Sequence: 2, Roots: []rootlist.Root{{Label: label, X509SPKISHA256: r.Pin}}}
		if err := rootlist.CheckRemoval(entry, still, []string{r.Pin}); err == nil {
			t.Errorf("%s: an authorisation was valid for a list that still holds the key", label)
		}
		// It names the key that it is for, and no other.
		if err := rootlist.CheckRemoval(entry, nil, []string{hexOf("another key")}); err == nil {
			t.Errorf("%s: an authorisation was valid for a host that does not hold the key", label)
		}
	}
}

// The text is the compact JWS of the page: ASCII, two dots, no newline, Base64url without padding,
// the four members of the header in the sorted order, the payload exactly the removal statement.
func TestNewRemovalShape(t *testing.T) {
	r := newRoot(t, "B", true)
	text := r.removal(t)
	if !printable(text) || strings.ContainsAny(text, " \n\r\t=+/") {
		t.Errorf("the text has a character that is not Base64url, a dot or printable ASCII: %q", text)
	}
	if strings.Count(text, ".") != 2 || strings.HasSuffix(text, "\n") {
		t.Errorf("the text does not have two dots and no newline")
	}
	protected, payload, parts := removalParts(t, text)
	wantHeader := `{"alg":"ES384","kid":"` + r.Pin + `","typ":"root-removal+json","x5c":["` + base64.StdEncoding.EncodeToString(r.DER) + `"]}`
	if string(protected) != wantHeader {
		t.Errorf("header\n got  %s\n want %s", protected, wantHeader)
	}
	if want := `{"version":1,"x509_spki_sha256":"` + r.Pin + `"}`; string(payload) != want {
		t.Errorf("payload %s, want %s", payload, want)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(sig) != jws.SignatureSize {
		t.Errorf("signature: %d bytes, %v", len(sig), err)
	}
	// The reader of the page reads it as a compact JWS of the type of a removal authorisation, and
	// the signature verifies over what the signer was given.
	c, err := jws.ParseCompact(text, rootlist.RemovalTyp)
	if err != nil {
		t.Fatal(err)
	}
	if c.Header.Kid != r.Pin || c.Header.Typ != "root-removal+json" || c.Header.Alg != "ES384" || jws.Pin(c.Cert) != r.Pin {
		t.Errorf("header read as %+v", c.Header)
	}
	if err := c.Verify(); err != nil {
		t.Errorf("the signature does not verify: %v", err)
	}
	// It is not a root list signature: the other typ is refused.
	if _, err := jws.ParseCompact(text, rootlist.ListTyp); err == nil {
		t.Errorf("the authorisation is read as a signature of a list")
	}
	// It has no sequence, no expiry: the payload has the two members and no more.
	var m map[string]any
	if err := json.Unmarshal(payload, &m); err != nil || len(m) != 2 {
		t.Errorf("payload members: %v, %v", m, err)
	}
}

// The authorisations of the vectors and the ones this package writes have the same shape: with the
// key and the certificate of the one put in the other, the header texts are equal.
func TestNewRemovalHasTheShapeOfTheVector(t *testing.T) {
	m := loadVectors(t)
	mine := newRoot(t, "A", true)
	text := mine.removal(t)
	myHeader, myPayload, _ := removalParts(t, text)
	for _, v := range m.Removals {
		vector := string(vectorFile(t, v.File))
		vHeader, vPayload, _ := removalParts(t, vector)
		var h struct {
			Kid string   `json:"kid"`
			X5C []string `json:"x5c"`
		}
		if err := json.Unmarshal(vHeader, &h); err != nil || len(h.X5C) != 1 {
			t.Fatalf("%s: %v", v.File, err)
		}
		swapped := strings.ReplaceAll(string(vHeader), h.Kid, mine.Pin)
		swapped = strings.ReplaceAll(swapped, h.X5C[0], base64.StdEncoding.EncodeToString(mine.DER))
		if swapped != string(myHeader) {
			t.Errorf("%s: header\n vector %s\n mine   %s", v.File, vHeader, myHeader)
		}
		if got := strings.ReplaceAll(string(vPayload), h.Kid, mine.Pin); got != string(myPayload) {
			t.Errorf("%s: payload\n vector %s\n mine   %s", v.File, vPayload, myPayload)
		}
		if strings.HasSuffix(vector, "\n") {
			t.Errorf("%s: the vector has a trailing newline", v.File)
		}
	}
}

// ECDSA is randomised: two calls give two texts, both valid, with one header and one payload.
func TestNewRemovalTwiceGivesTwoValidTexts(t *testing.T) {
	r := newRoot(t, "A", true)
	one, two := r.removal(t), r.removal(t)
	if one == two {
		t.Fatalf("two calls gave one text")
	}
	h1, p1, parts1 := removalParts(t, one)
	h2, p2, parts2 := removalParts(t, two)
	if !bytes.Equal(h1, h2) || !bytes.Equal(p1, p2) || parts1[2] == parts2[2] {
		t.Errorf("the texts differ in more than the signature")
	}
	for _, text := range []string{one, two} {
		entry := rootlist.Removal{Label: "A", X509SPKISHA256: r.Pin, Authorisation: text}
		if err := rootlist.CheckRemoval(entry, nil, []string{r.Pin}); err != nil {
			t.Error(err)
		}
	}
}

// The signer is asked once, with what the page says it signs, and a copy of it.
func TestNewRemovalAsksOnceForTheSigningInput(t *testing.T) {
	r := newRoot(t, "C", true)
	s := counting(r.signer(t))
	text, err := trustset.NewRemoval(s)
	if err != nil {
		t.Fatal(err)
	}
	if s.count() != 1 {
		t.Fatalf("the signer was asked %d times", s.count())
	}
	_, payload, parts := removalParts(t, text)
	if want := jws.SigningInput(parts[0], payload); !bytes.Equal(s.inputs[0], want) {
		t.Errorf("the signer was given\n %q\nwant\n %q", s.inputs[0], want)
	}
	if want := parts[0] + "." + parts[1]; string(s.inputs[0]) != want {
		t.Errorf("the signing input is not protected || \".\" || payload: %q", s.inputs[0])
	}
}

// A signer that changes the input it was given cannot make the check run over other bytes: the
// signature it made over the right bytes is accepted.
func TestNewRemovalGivesTheSignerACopy(t *testing.T) {
	r := newRoot(t, "A", true)
	inner := r.signer(t)
	s := &scriptedSigner{inner: inner}
	s.sign = func(input []byte) ([]byte, error) {
		sig, err := inner.SignES384(bytes.Clone(input))
		for i := range input {
			input[i] ^= 0xff
		}
		return sig, err
	}
	if _, err := trustset.NewRemoval(s); err != nil {
		t.Errorf("a signer that scribbles on its input: %v", err)
	}
}

// Everything that can be found without the key is found before the key is asked.
func TestNewRemovalRefusesBeforeAskingTheKey(t *testing.T) {
	a := newRoot(t, "A", true)
	p256 := makeCert(t, certOptions{curve: elliptic.P256()})
	rsaCert := makeCert(t, certOptions{rsaKey: true})
	huge := *a.Cert
	huge.Raw = make([]byte, trustset.MaxBytes+1)
	garbage := *a.Cert
	garbage.Raw = []byte("garbage")
	for _, c := range []struct {
		name  string
		label func() string
		cert  func() *x509.Certificate
		kind  error
	}{
		{"a label a", func() string { return "a" }, nil, trustset.ErrParams},
		{"a label of two letters", func() string { return "AB" }, nil, trustset.ErrParams},
		{"an empty label", func() string { return "" }, nil, trustset.ErrParams},
		{"a nil certificate", nil, func() *x509.Certificate { return nil }, trustset.ErrParams},
		{"a P-256 certificate", nil, func() *x509.Certificate { return p256.cert }, trustset.ErrParams},
		{"an RSA certificate", nil, func() *x509.Certificate { return rsaCert.cert }, trustset.ErrParams},
		{"a certificate over the limit", nil, func() *x509.Certificate { return &huge }, trustset.ErrParams},
		{"a certificate that is not DER", nil, func() *x509.Certificate { return &garbage }, trustset.ErrParams},
		{"an empty certificate", nil, func() *x509.Certificate { return &x509.Certificate{} }, trustset.ErrParams},
		{"a Label that panics", func() string { panic("no label") }, nil, trustset.ErrSign},
		{"a Certificate that panics", nil, func() *x509.Certificate { panic("no certificate") }, trustset.ErrSign},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := counting(a.signer(t))
			s.label, s.cert = c.label, c.cert
			text, err := trustset.NewRemoval(s)
			if err == nil {
				t.Fatalf("accepted: %s", text)
			}
			if text != "" {
				t.Errorf("a text comes with the error")
			}
			wantKind(t, err, c.kind)
			if s.count() != 0 {
				t.Errorf("the key was asked %d times", s.count())
			}
		})
	}
	text, err := trustset.NewRemoval(nil)
	if err == nil || text != "" {
		t.Errorf("a nil signer: %q, %v", text, err)
	} else {
		wantParams(t, err)
	}
}

func TestNewRemovalSignerFaults(t *testing.T) {
	a, b := newRoot(t, "A", true), newRoot(t, "B", true)
	byB := b.signer(t)
	cause := errors.New("touch timed out \x1b[31m \xff \u00e9\n")
	good := func(input []byte) []byte {
		sig, err := a.signer(t).SignES384(input)
		if err != nil {
			t.Fatal(err)
		}
		return sig
	}
	reasons := map[string]string{
		"a signature by another key":       "does not verify with the key of its certificate",
		"a signature over other bytes":     "does not verify with the key of its certificate",
		"95 bytes":                         "ES384 needs 96",
		"97 bytes":                         "ES384 needs 96",
		"no bytes":                         "ES384 needs 96",
		"96 zero bytes":                    "does not verify with the key of its certificate",
		"96 bytes of ones":                 "does not verify with the key of its certificate",
		"a signature with one bit changed": "does not verify with the key of its certificate",
		"an ASN.1 signature":               "ES384 needs 96",
		"an error":                         "failed",
		"an error with a signature":        "failed",
		"a panic with a string":            "panicked",
		"a panic with an error":            "panicked",
		"a nil pointer":                    "panicked",
	}
	for _, c := range []struct {
		name string
		sign func(input []byte) ([]byte, error)
	}{
		{"a signature by another key", func(in []byte) ([]byte, error) { return byB.SignES384(in) }},
		{"a signature over other bytes", func([]byte) ([]byte, error) { return good([]byte("other")), nil }},
		{"95 bytes", func(in []byte) ([]byte, error) { return good(in)[:95], nil }},
		{"97 bytes", func(in []byte) ([]byte, error) { return append(good(in), 0), nil }},
		{"no bytes", func([]byte) ([]byte, error) { return nil, nil }},
		{"96 zero bytes", func([]byte) ([]byte, error) { return make([]byte, 96), nil }},
		{"96 bytes of ones", func([]byte) ([]byte, error) { return bytes.Repeat([]byte{0xff}, 96), nil }},
		{"a signature with one bit changed", func(in []byte) ([]byte, error) {
			s := good(in)
			s[10] ^= 1
			return s, nil
		}},
		{"an ASN.1 signature", func([]byte) ([]byte, error) { return []byte{0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01}, nil }},
		{"an error", func([]byte) ([]byte, error) { return nil, cause }},
		{"an error with a signature", func(in []byte) ([]byte, error) { return good(in), cause }},
		{"a panic with a string", func([]byte) ([]byte, error) { panic("the card caught fire") }},
		{"a panic with an error", func([]byte) ([]byte, error) { panic(cause) }},
		{"a nil pointer", func([]byte) ([]byte, error) {
			var p *struct{ x int }
			_ = p.x
			return nil, nil
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := counting(a.signer(t))
			s.sign = c.sign
			text, err := trustset.NewRemoval(s)
			if err == nil {
				t.Fatalf("accepted: %s", text)
			}
			if text != "" {
				t.Errorf("a text comes with the error")
			}
			wantSign(t, err)
			if why := reasons[c.name]; why == "" || !strings.Contains(err.Error(), why) {
				t.Errorf("the refusal %q does not say %q", err, why)
			}
			if s.count() != 1 {
				t.Errorf("the key was asked %d times, want once", s.count())
			}
		})
	}
	// The error of the signer is shown, escaped, and is not part of the chain: errors.Is sees the
	// kind of the package and nothing the signer's error wraps.
	s := counting(a.signer(t))
	s.sign = func([]byte) ([]byte, error) { return nil, cause }
	_, err := trustset.NewRemoval(s)
	wantSign(t, err)
	if errors.Is(err, cause) {
		t.Errorf("the error of the signer is in the chain")
	}
	if err != nil && !strings.Contains(err.Error(), "touch timed out") {
		t.Errorf("the text %q does not show the error of the signer", err)
	}
}

// A signer cannot choose the kind: whatever kind of the package its error wraps, the result is
// ErrSign, and the signer's own chain is not in the result.
func TestNewRemovalSignerErrorCannotChangeTheKind(t *testing.T) {
	a := newRoot(t, "A", true)
	other := errors.New("a sentinel of the signer")
	for _, c := range []struct {
		name string
		err  error
	}{
		{"an error that wraps the parameter kind", fmt.Errorf("%w: pretend", trustset.ErrParams)},
		{"an error that wraps both kinds", errors.Join(trustset.ErrParams, trustset.ErrSign)},
		{"the parameter kind itself", trustset.ErrParams},
		{"an error with a chain of its own", fmt.Errorf("outer: %w", other)},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := counting(a.signer(t))
			s.sign = func([]byte) ([]byte, error) { return nil, c.err }
			text, err := trustset.NewRemoval(s)
			if text != "" {
				t.Errorf("a text comes with the error")
			}
			wantSign(t, err)
			if errors.Is(err, trustset.ErrParams) {
				t.Errorf("the error is also ErrParams")
			}
			if errors.Is(err, other) || errors.Is(err, c.err) {
				t.Errorf("the error of the signer is in the chain")
			}
		})
	}
	// A panic with an error value that wraps the other kind is the same.
	s := counting(a.signer(t))
	s.sign = func([]byte) ([]byte, error) { panic(fmt.Errorf("%w: pretend", trustset.ErrParams)) }
	_, err := trustset.NewRemoval(s)
	wantSign(t, err)
	// A long error of the signer is cut: the text of the refusal stays short.
	s = counting(a.signer(t))
	s.sign = func([]byte) ([]byte, error) { return nil, errors.New(strings.Repeat("long ", 10000)) }
	_, err = trustset.NewRemoval(s)
	wantSign(t, err)
	if err != nil && !strings.HasSuffix(err.Error(), "...") {
		t.Errorf("a long text of the signer is not cut: %.80q", err)
	}
}

// The key and the pin are those of the DER of the certificate, not those in the fields of the struct
// that the signer returned.
func TestNewRemovalTakesTheKeyFromTheDER(t *testing.T) {
	a, b := newRoot(t, "A", true), newRoot(t, "B", true)
	liar := *a.Cert
	liar.PublicKey = b.Cert.PublicKey
	// The key of A signs, the certificate says A in its DER and B in its field: the text is A's.
	s := &scriptedSigner{inner: a.signer(t), cert: func() *x509.Certificate { return &liar }}
	text, err := trustset.NewRemoval(s)
	if err != nil {
		t.Fatal(err)
	}
	entry := rootlist.Removal{Label: "A", X509SPKISHA256: a.Pin, Authorisation: text}
	if err := rootlist.CheckRemoval(entry, nil, []string{a.Pin}); err != nil {
		t.Errorf("the text is not the authorisation of A: %v", err)
	}
	// The key of B signs under the certificate whose field says B and whose DER says A: refused.
	s = &scriptedSigner{inner: b.signer(t), cert: func() *x509.Certificate { return &liar }}
	if text, err := trustset.NewRemoval(s); err == nil {
		t.Errorf("accepted: %s", text)
	} else {
		wantSign(t, err)
	}
}

func TestNewRemovalInParallel(t *testing.T) {
	r := newRoot(t, "A", true)
	s := r.signer(t)
	const workers = 8
	start := make(chan struct{})
	done := make(chan error, workers)
	for i := 0; i < workers; i++ {
		go func() {
			<-start
			text, err := trustset.NewRemoval(s)
			if err == nil {
				err = rootlist.CheckRemoval(rootlist.Removal{Label: "A", X509SPKISHA256: r.Pin, Authorisation: text}, nil, []string{r.Pin})
			}
			done <- err
		}()
	}
	close(start)
	for i := 0; i < workers; i++ {
		if err := <-done; err != nil {
			t.Error(err)
		}
	}
}

// A certificate may be large (under the limit of one certificate), and then the text of the
// authorisation may pass the limit of the file even though no part of it does: it is refused as a
// document over its limit (ErrParams), before the key is asked.
func TestNewRemovalTextOverTheLimit(t *testing.T) {
	big := makeCert(t, certOptions{padding: 150000})
	if len(big.der) > trustset.MaxBytes {
		t.Fatalf("the certificate has %d bytes", len(big.der))
	}
	s, err := trustset.NewKeySigner("A", big.cert, big.key)
	if err != nil {
		t.Fatal(err)
	}
	counted := counting(s)
	text, err := trustset.NewRemoval(counted)
	if err == nil {
		t.Fatalf("a text of %d bytes was made", len(text))
	}
	if text != "" {
		t.Errorf("a text comes with the error")
	}
	wantParams(t, err)
	if !strings.Contains(err.Error(), "the removal authorisation would be") || !strings.Contains(err.Error(), "bytes, longer than 262144 bytes") {
		t.Errorf("the refusal %q does not say that the text is too long", err)
	}
	if counted.count() != 0 {
		t.Errorf("the key was asked %d times for a text that is over the limit", counted.count())
	}

	// A certificate a little smaller gives a text under the limit, which the reader takes.
	mid := makeCert(t, certOptions{padding: 90000})
	s, err = trustset.NewKeySigner("A", mid.cert, mid.key)
	if err != nil {
		t.Fatal(err)
	}
	text, err = trustset.NewRemoval(s)
	if err != nil {
		t.Fatalf("a text under the limit: %v", err)
	}
	if len(text) > trustset.MaxBytes {
		t.Errorf("%d bytes", len(text))
	}
	entry := rootlist.Removal{Label: "A", X509SPKISHA256: mid.pin, Authorisation: text}
	if err := rootlist.CheckRemoval(entry, nil, []string{mid.pin}); err != nil {
		t.Error(err)
	}
}

// removalSizeFor makes an authorisation for a certificate padded by n bytes and returns the length
// of the DER, and the length of the text (accepted) or the length that the refusal names (refused).
func removalSizeFor(t *testing.T, n int) (derLen, size int, accepted bool) {
	t.Helper()
	m := makeCert(t, certOptions{padding: n})
	s, err := trustset.NewKeySigner("A", m.cert, m.key)
	if err != nil {
		t.Fatal(err)
	}
	counted := counting(s)
	text, err := trustset.NewRemoval(counted)
	if err == nil {
		if counted.count() != 1 {
			t.Fatalf("the key was asked %d times", counted.count())
		}
		return len(m.der), len(text), true
	}
	wantParams(t, err)
	if counted.count() != 0 {
		t.Fatalf("the key was asked %d times for a text over the limit", counted.count())
	}
	var got int
	if _, err := fmt.Sscanf(err.Error(), "trustset: invalid parameter: the removal authorisation would be %d bytes, longer than 262144 bytes", &got); err != nil {
		t.Fatalf("the refusal %q does not name the length: %v", err, err)
	}
	return len(m.der), got, false
}

// The limit is on the whole text: a text over MaxBytes is refused before the key is asked and one
// of MaxBytes or fewer is made, and the length that the refusal names is the length that the text
// would have had. The length of the text is one function of the length of the DER (the signature
// of the certificate has a length of its own, so the same padding gives DERs that differ by a few
// bytes): nine more bytes of DER are 12 more characters of x5c and 16 more characters of the text,
// on either side of the limit, so the length that a refusal names counts every part of the text,
// the two dots and the signature too.
func TestNewRemovalLimitIsExact(t *testing.T) {
	// Find the padding where the text passes the limit.
	lo, hi := 90000, 150000
	for hi-lo > 1 {
		mid := (lo + hi) / 2
		if _, _, ok := removalSizeFor(t, mid); ok {
			lo = mid
		} else {
			hi = mid
		}
	}
	type seen struct {
		size     int
		accepted bool
	}
	byLen := map[int]seen{}
	draw := func(p int) {
		n, size, ok := removalSizeFor(t, p)
		if old, dup := byLen[n]; dup && old.size != size {
			t.Fatalf("two certificates of %d bytes give texts of %d and %d bytes", n, old.size, size)
		}
		byLen[n] = seen{size, ok}
		if ok && size > trustset.MaxBytes {
			t.Fatalf("a text of %d bytes was made", size)
		}
		if !ok && size <= trustset.MaxBytes {
			t.Fatalf("a text of %d bytes was refused", size)
		}
	}
	straddle := func() (pairs, crossing int) {
		for n, a := range byLen {
			b, ok := byLen[n+9]
			if !ok {
				continue
			}
			pairs++
			if b.size-a.size != 16 {
				t.Errorf("DER of %d and %d bytes: the texts differ by %d characters, want 16", n, n+9, b.size-a.size)
			}
			if a.accepted && !b.accepted {
				crossing++
			}
		}
		return pairs, crossing
	}
	for p := lo - 30; p <= hi+30; p++ {
		draw(p)
	}
	// The length of a signature is not the choice of the test: draw more until the pairs that
	// stand on both sides of the limit exist (a bounded number of times).
	for extra := 0; extra < 300; extra++ {
		if _, crossing := straddle(); crossing >= 3 {
			break
		}
		draw(lo - 12 + extra%30)
	}
	pairs, crossing := straddle()
	if crossing < 3 {
		t.Fatalf("only %d pairs of certificates stand on both sides of the limit (%d pairs in all)", crossing, pairs)
	}
	var acceptedMax, refusedMin = 0, 1 << 30
	for _, v := range byLen {
		if v.accepted {
			acceptedMax = max(acceptedMax, v.size)
		} else {
			refusedMin = min(refusedMin, v.size)
		}
	}
	if acceptedMax > trustset.MaxBytes || refusedMin <= trustset.MaxBytes {
		t.Errorf("the limit is not between the sizes: accepted up to %d, refused from %d", acceptedMax, refusedMin)
	}
	t.Logf("%d pairs, %d across the limit; accepted up to %d bytes, refused from %d bytes (limit %d)", pairs, crossing, acceptedMax, refusedMin, trustset.MaxBytes)
	if acceptedMax < trustset.MaxBytes-8 || refusedMin > trustset.MaxBytes+8 {
		t.Errorf("the sizes around the limit are too far from it: %d and %d", acceptedMax, refusedMin)
	}
}

// The signer is read once: the label and the certificate are asked for once each, and what the
// signer does to its certificate while it signs, or after, changes neither the text nor its
// check.
func TestNewRemovalReadsTheSignerOnceAndOwnsWhatItRead(t *testing.T) {
	a := newRoot(t, "A", true)
	der := bytes.Clone(a.DER)
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	var labels, certs int
	inner := a.signer(t)
	s := &scriptedSigner{
		inner: inner,
		label: func() string { labels++; return "A" },
		cert:  func() *x509.Certificate { certs++; return cert },
		sign: func(input []byte) ([]byte, error) {
			// The signer scribbles on the bytes of its certificate while it signs.
			for i := range der {
				der[i] ^= 0xff
			}
			return inner.SignES384(input)
		},
	}
	text, err := trustset.NewRemoval(s)
	if err != nil {
		t.Fatal(err)
	}
	if labels != 1 || certs != 1 || s.count() != 1 {
		t.Errorf("Label %d times, Certificate %d times, SignES384 %d times; want once each", labels, certs, s.count())
	}
	entry := rootlist.Removal{Label: "A", X509SPKISHA256: a.Pin, Authorisation: text}
	if err := rootlist.CheckRemoval(entry, nil, []string{a.Pin}); err != nil {
		t.Errorf("the text is not the authorisation of A: %v", err)
	}
	p, _, _ := removalParts(t, text)
	var h struct {
		X5C []string `json:"x5c"`
	}
	if err := json.Unmarshal(p, &h); err != nil || len(h.X5C) != 1 {
		t.Fatalf("header %s: %v", p, err)
	}
	if got, _ := base64.StdEncoding.DecodeString(h.X5C[0]); !bytes.Equal(got, a.DER) {
		t.Errorf("x5c is not the DER of the certificate as it was when the signer was read")
	}
}

// A signer that answers with another label and another certificate at each call is judged by its
// first answers: the pin, the label and the key of one reading.
func TestNewRemovalSignerThatChangesItsAnswers(t *testing.T) {
	a, b := newRoot(t, "A", true), newRoot(t, "B", true)
	calls := 0
	s := &scriptedSigner{
		inner: a.signer(t),
		cert: func() *x509.Certificate {
			calls++
			if calls == 1 {
				return a.Cert
			}
			return b.Cert
		},
	}
	text, err := trustset.NewRemoval(s)
	if err != nil {
		t.Fatal(err)
	}
	if err := rootlist.CheckRemoval(rootlist.Removal{Label: "A", X509SPKISHA256: a.Pin, Authorisation: text}, nil, []string{a.Pin}); err != nil {
		t.Errorf("the text is not the authorisation of A: %v", err)
	}
	if calls != 1 {
		t.Errorf("Certificate was called %d times", calls)
	}
}

// The pin, the kid and the key of the authorisation are those of the DER, not those of the fields
// of the struct that the signer returned: a struct whose parsed copy of the key and whose
// SubjectPublicKeyInfo field say another key than its DER does not change the text.
func TestNewRemovalTakesThePinFromTheDERAndNotFromItsFields(t *testing.T) {
	a, b := newRoot(t, "A", true), newRoot(t, "B", true)
	liar := *a.Cert
	liar.PublicKey = b.Cert.PublicKey
	liar.RawSubjectPublicKeyInfo = b.Cert.RawSubjectPublicKeyInfo
	s := &scriptedSigner{inner: a.signer(t), cert: func() *x509.Certificate { return &liar }}
	text, err := trustset.NewRemoval(s)
	if err != nil {
		t.Fatal(err)
	}
	entry := rootlist.Removal{Label: "A", X509SPKISHA256: a.Pin, Authorisation: text}
	if err := rootlist.CheckRemoval(entry, nil, []string{a.Pin}); err != nil {
		t.Errorf("the text is not the authorisation of A: %v", err)
	}
	if err := rootlist.CheckRemoval(rootlist.Removal{Label: "A", X509SPKISHA256: b.Pin, Authorisation: text}, nil, []string{b.Pin}); err == nil {
		t.Errorf("the text is an authorisation of B")
	}
}
