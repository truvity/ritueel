//go:build linux || darwin

package ceremony_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/ceremony"
	"ritueel.id/ritueel/internal/ceremony/files"
	"ritueel.id/ritueel/internal/history"
	"ritueel.id/ritueel/internal/rootlist"
	"ritueel.id/ritueel/internal/trustset"
)

// The checks of the artifacts of the first apply, after the check of the root certificate: the removal authorisation, the root list,
// the CA bundle, root.json, the plan against the keys that were born, and the two journals. Each
// takes the bytes that will be written and compares them with the plan and the key.

// ---- the removal authorisation ----

func TestAGoodRemovalAuthorisationIsAccepted(t *testing.T) {
	r := mkRemovalSpec{}.build()
	if err := ceremony.CheckRemovalAuthorisation("A", r.Pin, r.Cert, r.Text, []byte(r.Text)); err != nil {
		t.Fatalf("a removal authorisation of the page is refused: %v", err)
	}
}

func TestEveryBreakOfTheRemovalAuthorisationIsRefusedWithTheMemberNamed(t *testing.T) {
	good := mkRemovalSpec{}.build()
	other := mkKeyP384()
	otherPin := mkPin(&other.PublicKey)
	reissued := mkCertSpec{Key: good.Key, Serial: mkSerial(77)}.build().DER
	h, p, s := mkRemovalParts(good.Text)
	cases := []struct {
		name   string
		text   string
		pin    string
		cert   []byte
		stored []byte
		member string
	}{
		{name: "empty", text: "", member: "text"},
		{name: "a line feed at the end", text: good.Text + "\n", member: "text"},
		{name: "a space", text: good.Text + " ", member: "text"},
		{name: "two parts", text: h + "." + p, member: "text"},
		{name: "four parts", text: good.Text + ".x", member: "text"},
		{name: "padding", text: good.Text + "=", member: "text"},
		{name: "not ASCII", text: "é" + good.Text, member: "text"},
		{name: "longer than a file of the root list", text: strings.Repeat("a", 300_000) + ".b.c", member: "text"},
		{name: "a signature with another length", text: h + "." + p + "." + s[:len(s)-4], member: "signature"},
		{name: "a byte of the payload changed", text: h + "." + base64.RawURLEncoding.EncodeToString([]byte(`{"version":1,"x509_spki_sha256":"`+otherPin+`"}`)) + "." + s, member: "signature"},
		{name: "the pin of the check is another key", text: good.Text, pin: otherPin, member: "signature"},
		{name: "a pin that is not a pin", text: good.Text, pin: "abc", member: "signature"},
		{name: "the signature of another key", text: mkRemovalSpec{Key: good.Key, SignKey: other}.build().Text, member: "signature"},
		{name: "a kid that is another pin", text: mkRemovalSpec{Key: good.Key, KidOnly: otherPin}.build().Text, member: "signature"},
		{name: "the type of a root list", text: mkRemovalSpec{Key: good.Key, Typ: "root-list+json"}.build().Text, member: "signature"},
		{name: "an algorithm that is not ES384", text: mkRemovalSpec{Key: good.Key, Alg: "ES256"}.build().Text, member: "signature"},
		{name: "a payload of another pin", text: mkRemovalSpec{Key: good.Key, Payload: `{"version":1,"x509_spki_sha256":"` + otherPin + `"}`}.build().Text, member: "signature"},
		{name: "a payload with a space", text: mkRemovalSpec{Key: good.Key, Payload: `{"version": 1,"x509_spki_sha256":"` + good.Pin + `"}`}.build().Text, member: "signature"},
		{name: "a payload with another member", text: mkRemovalSpec{Key: good.Key, Payload: `{"version":1,"x509_spki_sha256":"` + good.Pin + `","reason":"x"}`}.build().Text, member: "signature"},
		{name: "two certificates in x5c", text: mkRemovalSpec{Key: good.Key, X5C: []string{base64.StdEncoding.EncodeToString(good.Cert), base64.StdEncoding.EncodeToString(good.Cert)}}.build().Text, member: "signature"},
		{name: "a header member that the page does not have", text: mkRemovalSpec{Key: good.Key, Extra: map[string]any{"crit": []string{"b64"}}}.build().Text, member: "signature"},
		{name: "another certificate of the same key in x5c", text: mkRemovalSpec{Key: good.Key, Cert: reissued}.build().Text, member: "x5c"},
		{name: "a certificate that is another certificate of the same key in the check", text: good.Text, cert: reissued, member: "x5c"},
		{name: "a certificate of another key in the check", text: good.Text, cert: mkCertSpec{Key: other}.build().DER, member: "x5c"},
		{name: "no certificate in the check", text: good.Text, cert: []byte{}, member: "x5c"},
		{name: "a stored file that is another text", text: good.Text, stored: []byte(mkRemovalSpec{Key: good.Key}.build().Text), member: "stored file"},
		{name: "a stored file with a line feed", text: good.Text, stored: []byte(good.Text + "\n"), member: "stored file"},
		{name: "a stored file that is empty", text: good.Text, stored: []byte{}, member: "stored file"},
		{name: "a stored file that is missing", text: good.Text, stored: nil, member: "stored file"},
		{name: "a stored file with its first byte changed", text: good.Text, stored: append([]byte{good.Text[0] ^ 1}, good.Text[1:]...), member: "stored file"},
		{name: "a stored file with its last byte changed", text: good.Text, stored: append([]byte(good.Text[:len(good.Text)-1]), good.Text[len(good.Text)-1]^1), member: "stored file"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pin, cert, stored := tc.pin, tc.cert, tc.stored
			if pin == "" {
				pin = good.Pin
			}
			if cert == nil {
				cert = good.Cert
			}
			if stored == nil && tc.name != "a stored file that is missing" {
				stored = []byte(tc.text)
			}
			err := ceremony.CheckRemovalAuthorisation("A", pin, cert, tc.text, stored)
			mkWantArtifactError(t, err, "removal authorisation A", tc.member)
			if len(tc.text) < 5000 && strings.Contains(err.Error(), tc.text) && tc.text != "" {
				t.Errorf("the error shows the text of the authorisation")
			}
		})
	}
}

func TestTheRemovalAuthorisationIsNamedByItsLabel(t *testing.T) {
	r := mkRemovalSpec{}.build()
	err := ceremony.CheckRemovalAuthorisation("Q", "abc", r.Cert, r.Text, []byte(r.Text))
	mkWantArtifactError(t, err, "removal authorisation Q", "signature")
}

// ---- the first trust set: the root list and the CA bundle ----

func TestAGoodFirstTrustSetIsAcceptedAndReadBackByTheReaderOfTheList(t *testing.T) {
	keys := mkRootKeys("A", "B")
	set := mkSetSpec{Keys: keys}.build(t)
	w := mkWantFor(keys, "A")
	list, err := ceremony.CheckRootList(set, w)
	if err != nil {
		t.Fatalf("CheckRootList: %v", err)
	}
	if list.Sequence != 1 || len(list.Roots) != 2 || list.Roots[0].Label != "A" || list.Roots[1].Label != "B" {
		t.Errorf("the list is %+v", list)
	}
	if err := ceremony.CheckCABundle(set.CABundle(), list, w); err != nil {
		t.Fatalf("CheckCABundle: %v", err)
	}
	// The name of the set is the number and the first eight characters of the digest of the list.
	sum := sha256.Sum256(set.ListJSON())
	if want := "1-" + hex.EncodeToString(sum[:])[:8]; set.Name() != want {
		t.Errorf("the name is %q, want %q", set.Name(), want)
	}
	// One signature, and its signer is A.
	if got := set.Signers(); len(got) != 1 || got[0] != "A" {
		t.Errorf("the signers are %v", got)
	}
}

func TestTheListOfAFirstSetHasTheMembersOfThePageAndNoOther(t *testing.T) {
	keys := mkRootKeys("A", "B")
	set := mkSetSpec{Keys: keys}.build(t)
	var m map[string]any
	if err := json.Unmarshal(set.ListJSON(), &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"version", "sequence", "signed_at", "expires_at", "roots"} {
		if _, ok := m[k]; !ok {
			t.Errorf("the list has no member %s", k)
		}
	}
	for k := range m {
		switch k {
		case "version", "sequence", "signed_at", "expires_at", "roots":
		default:
			t.Errorf("the first list has the member %s", k)
		}
	}
	if m["signed_at"] != "2026-11-20T10:00:00Z" || m["expires_at"] != mkAddMonths(pfClock, 13).Format(time.RFC3339) {
		t.Errorf("signed_at %v, expires_at %v", m["signed_at"], m["expires_at"])
	}
	if m["expires_at"] != "2027-12-20T10:00:00Z" {
		t.Errorf("expires_at %v is not 13 calendar months after signed_at", m["expires_at"])
	}
	roots := m["roots"].([]any)
	for i, r := range roots {
		e := r.(map[string]any)
		if len(e) != 2 || e["label"] != keys[i].Label || e["x509_spki_sha256"] != keys[i].Pin {
			t.Errorf("the entry %d is %v", i, e)
		}
	}
}

func TestEveryBreakOfTheRootListIsRefusedWithTheMemberNamed(t *testing.T) {
	keys := mkRootKeys("A", "B")
	three := append(append([]mkRootKey{}, keys...), mkRootKeys("C")...)
	other := mkRootKeys("A", "B")
	good := mkSetSpec{Keys: keys}.build(t)
	zero := &trustset.Set{}
	swap := func(w ceremony.RootListWant) ceremony.RootListWant {
		w.Pins = []string{w.Pins[1], w.Pins[0]}
		return w
	}
	cases := []struct {
		name   string
		set    *trustset.Set
		want   func() ceremony.RootListWant
		member string
	}{
		{"no set", nil, func() ceremony.RootListWant { return mkWantFor(keys, "A") }, "set"},
		{"a zero set", zero, func() ceremony.RootListWant { return mkWantFor(keys, "A") }, "set"},
		{"no keys in the facts", good, func() ceremony.RootListWant { return ceremony.RootListWant{SignedAt: pfClock, Signer: "A"} }, "want"},
		{"fewer pins than labels", good, func() ceremony.RootListWant { w := mkWantFor(keys, "A"); w.Pins = w.Pins[:1]; return w }, "want"},
		{"fewer certificates than labels", good, func() ceremony.RootListWant { w := mkWantFor(keys, "A"); w.Certificates = w.Certificates[:1]; return w }, "want"},
		{"a signer that is not a label", good, func() ceremony.RootListWant { return mkWantFor(keys, "C") }, "want"},
		{"a pin that is not a pin", good, func() ceremony.RootListWant { w := mkWantFor(keys, "A"); w.Pins[1] = "abc"; return w }, "pins"},
		{"another signer than the key that signed", good, func() ceremony.RootListWant { return mkWantFor(keys, "B") }, "signature"},
		{"the pins of other keys", good, func() ceremony.RootListWant { return mkWantFor(other, "A") }, "verdict"},
		{"the pins in the other order", good, func() ceremony.RootListWant { return swap(mkWantFor(keys, "A")) }, "roots"},
		{"another certificate for the signer", good, func() ceremony.RootListWant {
			w := mkWantFor(keys, "A")
			w.Certificates[0] = mkCertSpec{Key: keys[0].Key, Serial: mkSerial(99)}.build().DER
			return w
		}, "signature"},
		{"a ceremony time a day earlier", good, func() ceremony.RootListWant {
			w := mkWantFor(keys, "A")
			w.SignedAt = pfClock.Add(-24 * time.Hour)
			return w
		}, "verdict"},
		{"a ceremony time a second later", good, func() ceremony.RootListWant {
			w := mkWantFor(keys, "A")
			w.SignedAt = pfClock.Add(time.Second)
			return w
		}, "signed_at"},
		{"a set of three keys against two", mkSetSpec{Keys: three}.build(t), func() ceremony.RootListWant { return mkWantFor(keys, "A") }, "verdict"},
		{"the pins of the keys under other labels", good, func() ceremony.RootListWant {
			w := mkWantFor(keys, "A")
			w.Labels = []string{"A", "C"}
			return w
		}, "roots"},
		{"a set of one key against two", mkSetSpec{Keys: keys[:1]}.build(t), func() ceremony.RootListWant { return mkWantFor(keys, "A") }, "verdict"},
		{"a list signed by B against A", mkSetSpec{Keys: keys, Signers: []string{"B"}}.build(t), func() ceremony.RootListWant { return mkWantFor(keys, "A") }, "signature"},
		{"a list signed another second", mkSetSpec{Keys: keys, SignedAt: pfClock.Add(-time.Second)}.build(t), func() ceremony.RootListWant { return mkWantFor(keys, "A") }, "signed_at"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			list, err := ceremony.CheckRootList(tc.set, tc.want())
			if list != nil {
				t.Errorf("a list is returned with the error %v", err)
			}
			mkWantArtifactError(t, err, "root list", tc.member)
			if tc.member == "verdict" {
				// The refusal of the reader of the root list is shown with its check and its code.
				if ae, _ := mkAs[*ceremony.ArtifactError](err); !strings.Contains(ae.Reason, "the reader of the root list refuses it: check ") {
					t.Errorf("the reason does not say which check of the reader refused: %q", ae.Reason)
				}
			}
		})
	}
	// A list signed by B is the right list when the plan names B as the signer.
	byB := mkSetSpec{Keys: keys, Signers: []string{"B"}}.build(t)
	if _, err := ceremony.CheckRootList(byB, mkWantFor(keys, "B")); err != nil {
		t.Errorf("a list signed by the key that the plan names is refused: %v", err)
	}
}

func TestAListThatIsNotTheFirstIsRefused(t *testing.T) {
	keys := mkRootKeys("A", "B")
	first := mkSetSpec{Keys: keys}.build(t)
	// The second list of the same keys: both keys sign, and it carries the end of the history.
	var roots []trustset.Root
	certs := map[string][]byte{}
	for _, k := range keys {
		roots = append(roots, trustset.Root{Label: k.Label, X509SPKISHA256: k.Pin})
		certs[k.Label] = k.Cert.DER
	}
	d, err := trustset.NewDraft(trustset.Input{
		Sequence: 2, SignedAt: pfClock.Add(time.Hour), Roots: roots, Certificates: certs,
		LastRecordSHA256: strings.Repeat("ab", 32), Previous: first.ListJSON(),
		Earlier: []history.RootList{{Name: first.Name(), Keys: []history.RootKey{{Label: "A", Pin: keys[0].Pin}, {Label: "B", Pin: keys[1].Pin}}}},
	})
	if err != nil {
		t.Fatalf("the builder of the lists refuses a second list: %v", err)
	}
	cert, err := x509ParseCertificate(keys[0].Cert.DER)
	if err != nil {
		t.Fatal(err)
	}
	sg, err := trustset.NewKeySigner("A", cert, keys[0].Key)
	if err != nil {
		t.Fatal(err)
	}
	second, err := d.Sign([]trustset.Signer{sg}, nil)
	if err != nil {
		t.Fatalf("the builder of the lists refuses to sign a second list: %v", err)
	}
	w := mkWantFor(keys, "A")
	w.SignedAt = pfClock.Add(time.Hour)
	_, err = ceremony.CheckRootList(second, w)
	mkWantArtifactError(t, err, "root list", "sequence")
}

func TestAGoodCABundleIsTheCertificatesInTheOrderOfTheList(t *testing.T) {
	keys := mkRootKeys("A", "B")
	set := mkSetSpec{Keys: keys}.build(t)
	w := mkWantFor(keys, "A")
	list, err := ceremony.CheckRootList(set, w)
	if err != nil {
		t.Fatal(err)
	}
	bundle := set.CABundle()
	if !bytes.HasPrefix(bundle, []byte("# trust-sequence: 1\n")) {
		t.Fatalf("the bundle starts with %.30q", bundle)
	}
	// The blocks are the certificates, in the order of the list, byte for byte.
	rest := bundle[len("# trust-sequence: 1\n"):]
	for i, k := range keys {
		blk, next := pem.Decode(rest)
		if blk == nil || blk.Type != "CERTIFICATE" || !bytes.Equal(blk.Bytes, k.Cert.DER) {
			t.Fatalf("the block %d of the bundle is not the certificate of %s", i+1, k.Label)
		}
		rest = next
	}
	if len(rest) != 0 {
		t.Fatalf("bytes after the last certificate: %q", rest)
	}
	if err := ceremony.CheckCABundle(bundle, list, w); err != nil {
		t.Fatalf("CheckCABundle: %v", err)
	}
}

func TestEveryBreakOfTheCABundleIsRefusedWithTheMemberNamed(t *testing.T) {
	keys := mkRootKeys("A", "B")
	set := mkSetSpec{Keys: keys}.build(t)
	w := mkWantFor(keys, "A")
	list, err := ceremony.CheckRootList(set, w)
	if err != nil {
		t.Fatal(err)
	}
	block := func(der []byte) []byte { return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}) }
	first := []byte("# trust-sequence: 1\n")
	join := func(parts ...[]byte) []byte { return bytes.Join(parts, nil) }
	reissued := mkCertSpec{Key: keys[0].Key, Serial: mkSerial(55)}.build().DER
	cases := []struct {
		name   string
		bundle []byte
		list   *rootlist.List
		want   func() ceremony.RootListWant
		member string
	}{
		{"no list", set.CABundle(), nil, nil, "list"},
		{"facts that are not whole", set.CABundle(), list, func() ceremony.RootListWant { return ceremony.RootListWant{} }, "list"},
		{"empty", nil, list, nil, "verdict"},
		{"the first line missing", join(block(keys[0].Cert.DER), block(keys[1].Cert.DER)), list, nil, "verdict"},
		{"another sequence", join([]byte("# trust-sequence: 2\n"), block(keys[0].Cert.DER), block(keys[1].Cert.DER)), list, nil, "verdict"},
		{"the order swapped", join(first, block(keys[1].Cert.DER), block(keys[0].Cert.DER)), list, nil, "verdict"},
		{"one certificate", join(first, block(keys[0].Cert.DER)), list, nil, "verdict"},
		{"an extra block", join(first, block(keys[0].Cert.DER), block(keys[1].Cert.DER), block(keys[1].Cert.DER)), list, nil, "verdict"},
		{"a text after the blocks", join(set.CABundle(), []byte("x\n")), list, nil, "verdict"},
		{"a blank line after the blocks", join(set.CABundle(), []byte("\n")), list, nil, "verdict"},
		{"CRLF line ends", bytes.ReplaceAll(set.CABundle(), []byte("\n"), []byte("\r\n")), list, nil, "verdict"},
		{"another certificate of the same key", join(first, block(reissued), block(keys[1].Cert.DER)), list, nil, "certificate"},
		{"a certificate of another key in the facts", set.CABundle(), list, func() ceremony.RootListWant {
			x := mkWantFor(keys, "A")
			x.Certificates[1] = mkCertSpec{Label: "B"}.build().DER
			return x
		}, "certificate"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wt := w
			if tc.want != nil {
				wt = tc.want()
			}
			err := ceremony.CheckCABundle(tc.bundle, tc.list, wt)
			mkWantArtifactError(t, err, "ca-bundle.pem", tc.member)
		})
	}
}

// ---- root.json ----

func mkRootJSON(t testing.TB, edit func(*files.RootJSON)) []byte {
	t.Helper()
	d := files.RootJSON{
		Version: 1, Label: "A", Store: "software", Test: true, CreatedAt: "2026-11-20T10:00:00Z",
		X509SPKISHA256: strings.Repeat("ab", 32), RemovalSHA256: strings.Repeat("cd", 32),
	}
	if edit != nil {
		edit(&d)
	}
	b, err := d.Canonical()
	if err != nil {
		t.Fatalf("Canonical: %v", err)
	}
	return b
}

func mkRootJSONWant() ceremony.RootJSONWant {
	return ceremony.RootJSONWant{Label: "A", Pin: strings.Repeat("ab", 32), CreatedAt: pfClock, RemovalSHA256: strings.Repeat("cd", 32)}
}

func TestAGoodRootJSONIsAccepted(t *testing.T) {
	if err := ceremony.CheckRootJSON(mkRootJSON(t, nil), mkRootJSONWant()); err != nil {
		t.Fatalf("CheckRootJSON: %v", err)
	}
}

func TestEveryBreakOfRootJSONIsRefusedWithTheMemberNamed(t *testing.T) {
	good := mkRootJSON(t, nil)
	cases := []struct {
		name   string
		b      []byte
		want   func(*ceremony.RootJSONWant)
		member string
	}{
		{"empty", nil, nil, "file"},
		{"not JSON", []byte("x"), nil, "file"},
		{"a line feed at the end", append(append([]byte{}, good...), '\n'), nil, "file"},
		{"a space after the colon", bytes.Replace(good, []byte(`"label":`), []byte(`"label": `), 1), nil, "file"},
		{"members in another order", []byte(`{"version":1,"label":"A","store":"software","test":true,"created_at":"2026-11-20T10:00:00Z","x509_spki_sha256":"` + strings.Repeat("ab", 32) + `","removal_sha256":"` + strings.Repeat("cd", 32) + `"}`), nil, "file"},
		{"an unknown member", bytes.Replace(good, []byte(`"label"`), []byte(`"labels":1,"label"`), 1), nil, "file"},
		{"another label", mkRootJSON(t, func(r *files.RootJSON) { r.Label = "B" }), nil, "label"},
		{"another store", mkRootJSON(t, func(r *files.RootJSON) { r.Store = "piv" }), nil, "store"},
		{"not a test root", mkRootJSON(t, func(r *files.RootJSON) { r.Test = false }), nil, "test"},
		{"another time", mkRootJSON(t, func(r *files.RootJSON) { r.CreatedAt = "2026-11-20T10:00:01Z" }), nil, "created_at"},
		{"another pin", mkRootJSON(t, func(r *files.RootJSON) { r.X509SPKISHA256 = strings.Repeat("ba", 32) }), nil, "x509_spki_sha256"},
		{"another removal digest", mkRootJSON(t, func(r *files.RootJSON) { r.RemovalSHA256 = strings.Repeat("dc", 32) }), nil, "removal_sha256"},
		{"no removal digest", mkRootJSON(t, func(r *files.RootJSON) { r.RemovalSHA256 = "" }), nil, "removal_sha256"},
		{"an OpenPGP key besides the X.509 key", mkRootJSON(t, func(r *files.RootJSON) {
			r.OpenPGPFingerprint, r.OpenPGPCreated = strings.Repeat("ab", 20), "2026-11-20T10:00:00Z"
			r.Revocations = map[string]string{"compromised": strings.Repeat("11", 32), "superseded": strings.Repeat("22", 32)}
		}), nil, "openpgp_fingerprint"},
		{"the facts name another label", good, func(w *ceremony.RootJSONWant) { w.Label = "B" }, "label"},
		{"the facts name another pin", good, func(w *ceremony.RootJSONWant) { w.Pin = strings.Repeat("11", 32) }, "x509_spki_sha256"},
		{"the facts name another time", good, func(w *ceremony.RootJSONWant) { w.CreatedAt = pfClock.Add(time.Second) }, "created_at"},
		{"the facts name another removal digest", good, func(w *ceremony.RootJSONWant) { w.RemovalSHA256 = strings.Repeat("22", 32) }, "removal_sha256"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := mkRootJSONWant()
			if tc.want != nil {
				tc.want(&w)
			}
			mkWantArtifactError(t, ceremony.CheckRootJSON(tc.b, w), "root.json "+w.Label, tc.member)
		})
	}
}

// ---- the plan against the born keys ----

func mkPlanAndKeys(t testing.TB) (*ceremony.PlanOut, []ceremony.BornKey, []ceremony.MadeSignature) {
	t.Helper()
	p := pfPlan(t, pfFiles())
	var born []ceremony.BornKey
	pins := map[string]string{}
	for i, b := range p.Births {
		pin := strings.Repeat(string("abcdef"[i]), 64)
		pins[b.Label] = pin
		born = append(born, ceremony.BornKey{Label: b.Label, Store: b.Store, Place: b.Place, Pin: pin})
	}
	var made []ceremony.MadeSignature
	for _, s := range p.Signatures {
		made = append(made, ceremony.MadeSignature{N: s.N, Kind: s.Kind, Subject: s.Subject, Key: pins[s.Subject], SignatureSHA256: strings.Repeat("5", 64)})
	}
	return p, born, made
}

func TestThePlanAndTheKeysThatWereBornAgree(t *testing.T) {
	p, born, made := mkPlanAndKeys(t)
	if err := ceremony.CheckPlanAgainstKeys(p, born, made); err != nil {
		t.Fatalf("CheckPlanAgainstKeys: %v", err)
	}
	if len(born) != 2 || len(made) != 5 {
		t.Fatalf("the plan has %d births and %d signatures; the first apply has 2 and 5", len(born), len(made))
	}
}

func TestEveryDisagreementOfThePlanAndTheKeysIsRefusedWithTheMemberNamed(t *testing.T) {
	cases := []struct {
		name   string
		edit   func(p **ceremony.PlanOut, born *[]ceremony.BornKey, made *[]ceremony.MadeSignature)
		member string
	}{
		{"no plan", func(p **ceremony.PlanOut, _ *[]ceremony.BornKey, _ *[]ceremony.MadeSignature) { *p = nil }, "plan"},
		{"an empty plan", func(p **ceremony.PlanOut, _ *[]ceremony.BornKey, _ *[]ceremony.MadeSignature) {
			*p = &ceremony.PlanOut{}
		}, "plan"},
		{"one key was born and the plan lists two", func(_ **ceremony.PlanOut, b *[]ceremony.BornKey, _ *[]ceremony.MadeSignature) { *b = (*b)[:1] }, "births"},
		{"three keys were born", func(_ **ceremony.PlanOut, b *[]ceremony.BornKey, _ *[]ceremony.MadeSignature) {
			*b = append(*b, (*b)[0])
		}, "births"},
		{"no key was born", func(_ **ceremony.PlanOut, b *[]ceremony.BornKey, _ *[]ceremony.MadeSignature) { *b = nil }, "births"},
		{"the keys in the other order", func(_ **ceremony.PlanOut, b *[]ceremony.BornKey, _ *[]ceremony.MadeSignature) {
			(*b)[0], (*b)[1] = (*b)[1], (*b)[0]
		}, "births"},
		{"another label", func(_ **ceremony.PlanOut, b *[]ceremony.BornKey, _ *[]ceremony.MadeSignature) { (*b)[1].Label = "C" }, "births"},
		{"another store", func(_ **ceremony.PlanOut, b *[]ceremony.BornKey, _ *[]ceremony.MadeSignature) { (*b)[0].Store = "piv" }, "births"},
		{"the store saved another name", func(_ **ceremony.PlanOut, b *[]ceremony.BornKey, _ *[]ceremony.MadeSignature) {
			(*b)[0].Place = "A.x509.key.pem.tmp"
		}, "births"},
		{"a pin that is not a pin", func(_ **ceremony.PlanOut, b *[]ceremony.BornKey, _ *[]ceremony.MadeSignature) { (*b)[0].Pin = "abc" }, "births"},
		{"a pin in upper case", func(_ **ceremony.PlanOut, b *[]ceremony.BornKey, _ *[]ceremony.MadeSignature) {
			(*b)[0].Pin = strings.ToUpper((*b)[0].Pin)
		}, "births"},
		{"a signature is missing", func(_ **ceremony.PlanOut, _ *[]ceremony.BornKey, m *[]ceremony.MadeSignature) { *m = (*m)[:4] }, "signatures"},
		{"a signature is made twice", func(_ **ceremony.PlanOut, _ *[]ceremony.BornKey, m *[]ceremony.MadeSignature) {
			*m = append(*m, (*m)[4])
		}, "signatures"},
		{"no signature was made", func(_ **ceremony.PlanOut, _ *[]ceremony.BornKey, m *[]ceremony.MadeSignature) { *m = nil }, "signatures"},
		{"the signatures in the wrong order", func(_ **ceremony.PlanOut, _ *[]ceremony.BornKey, m *[]ceremony.MadeSignature) {
			(*m)[0], (*m)[1] = (*m)[1], (*m)[0]
		}, "signatures"},
		{"a wrong number", func(_ **ceremony.PlanOut, _ *[]ceremony.BornKey, m *[]ceremony.MadeSignature) { (*m)[2].N = 9 }, "signatures"},
		{"a number that repeats", func(_ **ceremony.PlanOut, _ *[]ceremony.BornKey, m *[]ceremony.MadeSignature) { (*m)[2].N = 2 }, "signatures"},
		{"another kind", func(_ **ceremony.PlanOut, _ *[]ceremony.BornKey, m *[]ceremony.MadeSignature) {
			(*m)[0].Kind = "root-removal"
		}, "signatures"},
		{"another subject", func(_ **ceremony.PlanOut, _ *[]ceremony.BornKey, m *[]ceremony.MadeSignature) { (*m)[0].Subject = "B" }, "signatures"},
		{"a key that is not a pin", func(_ **ceremony.PlanOut, _ *[]ceremony.BornKey, m *[]ceremony.MadeSignature) { (*m)[0].Key = "" }, "signatures"},
		{"a digest that is not a digest", func(_ **ceremony.PlanOut, _ *[]ceremony.BornKey, m *[]ceremony.MadeSignature) {
			(*m)[0].SignatureSHA256 = strings.Repeat("g", 64)
		}, "signatures"},
		{"no digest", func(_ **ceremony.PlanOut, _ *[]ceremony.BornKey, m *[]ceremony.MadeSignature) {
			(*m)[4].SignatureSHA256 = ""
		}, "signatures"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, born, made := mkPlanAndKeys(t)
			tc.edit(&p, &born, &made)
			mkWantArtifactError(t, ceremony.CheckPlanAgainstKeys(p, born, made), "plan against the keys", tc.member)
		})
	}
}

// ---- the journals ----

func mkJournals(t testing.TB, p *ceremony.PlanOut) (pins map[string]string, births, sigs ceremony.JournalRead) {
	t.Helper()
	pins = map[string]string{}
	for i, b := range p.Births {
		pin := strings.Repeat(string("abcdef"[i]), 64)
		pins[b.Label] = pin
		line, err := (&files.BirthLine{At: "2026-11-20T10:00:01Z", Label: b.Label, Purpose: b.Purpose, Store: b.Store, Place: b.Place, PublicKeySHA256: pin}).Canonical()
		if err != nil {
			t.Fatal(err)
		}
		births.Lines = append(births.Lines, line)
	}
	for _, s := range p.Signatures {
		line, err := (&files.SignatureLine{At: "2026-11-20T10:00:02Z", N: s.N, Kind: s.Kind, Key: pins[s.Subject], SignatureSHA256: strings.Repeat("5", 64)}).Canonical()
		if err != nil {
			t.Fatal(err)
		}
		sigs.Lines = append(sigs.Lines, line)
	}
	return pins, births, sigs
}

func TestJournalsThatAreWholeAndInTheOrderOfThePlanAreAccepted(t *testing.T) {
	p := pfPlan(t, pfFiles())
	pins, b, s := mkJournals(t, p)
	if err := ceremony.CheckJournals(p, pins, b, s); err != nil {
		t.Fatalf("CheckJournals: %v", err)
	}
}

func TestEveryBreakOfTheJournalsIsRefusedWithTheMemberNamed(t *testing.T) {
	cases := []struct {
		name   string
		edit   func(p **ceremony.PlanOut, pins map[string]string, b, s *ceremony.JournalRead)
		member string
	}{
		{"no plan", func(p **ceremony.PlanOut, _ map[string]string, _, _ *ceremony.JournalRead) { *p = nil }, "plan"},
		{"a half line at the end of the births", func(_ **ceremony.PlanOut, _ map[string]string, b, _ *ceremony.JournalRead) {
			b.Partial = []byte(`{"at":"2026`)
		}, "journal"},
		{"a half line at the end of the signatures", func(_ **ceremony.PlanOut, _ map[string]string, _, s *ceremony.JournalRead) {
			s.Partial = []byte(`{"at":`)
		}, "journal"},
		{"a birth line is missing", func(_ **ceremony.PlanOut, _ map[string]string, b, _ *ceremony.JournalRead) { b.Lines = b.Lines[:1] }, "births.jsonl"},
		{"a birth line twice", func(_ **ceremony.PlanOut, _ map[string]string, b, _ *ceremony.JournalRead) {
			b.Lines = [][]byte{b.Lines[0], b.Lines[0]}
		}, "births.jsonl"},
		{"a birth line extra", func(_ **ceremony.PlanOut, _ map[string]string, b, _ *ceremony.JournalRead) {
			b.Lines = append(b.Lines, b.Lines[0])
		}, "births.jsonl"},
		{"the birth lines in the other order", func(_ **ceremony.PlanOut, _ map[string]string, b, _ *ceremony.JournalRead) {
			b.Lines[0], b.Lines[1] = b.Lines[1], b.Lines[0]
		}, "births.jsonl"},
		{"a birth line that is not a line", func(_ **ceremony.PlanOut, _ map[string]string, b, _ *ceremony.JournalRead) {
			b.Lines[0] = []byte("not json")
		}, "births.jsonl"},
		{"a birth line that is empty", func(_ **ceremony.PlanOut, _ map[string]string, b, _ *ceremony.JournalRead) { b.Lines[1] = nil }, "births.jsonl"},
		{"another place in a birth line", func(_ **ceremony.PlanOut, _ map[string]string, b, _ *ceremony.JournalRead) {
			b.Lines[0] = bytes.Replace(b.Lines[0], []byte("x509-root-a"), []byte("x509-root-z"), 1)
		}, "births.jsonl"},
		{"another store in a birth line", func(_ **ceremony.PlanOut, _ map[string]string, b, _ *ceremony.JournalRead) {
			b.Lines[0] = bytes.Replace(b.Lines[0], []byte(`"software"`), []byte(`"piv"`), 1)
		}, "births.jsonl"},
		{"another purpose in a birth line", func(_ **ceremony.PlanOut, _ map[string]string, b, _ *ceremony.JournalRead) {
			b.Lines[0] = bytes.Replace(b.Lines[0], []byte(`"x509-root"`), []byte(`"ssh-ca"`), 1)
		}, "births.jsonl"},
		{"another pin in a birth line", func(_ **ceremony.PlanOut, pins map[string]string, _, _ *ceremony.JournalRead) {
			pins["A"] = strings.Repeat("9", 64)
		}, "births.jsonl"},
		{"no pin for a label", func(_ **ceremony.PlanOut, pins map[string]string, _, _ *ceremony.JournalRead) { delete(pins, "B") }, "births.jsonl"},
		{"a signature line is missing", func(_ **ceremony.PlanOut, _ map[string]string, _, s *ceremony.JournalRead) { s.Lines = s.Lines[:4] }, "signatures.jsonl"},
		{"a signature line extra", func(_ **ceremony.PlanOut, _ map[string]string, _, s *ceremony.JournalRead) {
			s.Lines = append(s.Lines, s.Lines[0])
		}, "signatures.jsonl"},
		{"no signature line", func(_ **ceremony.PlanOut, _ map[string]string, _, s *ceremony.JournalRead) { s.Lines = nil }, "signatures.jsonl"},
		{"the signature lines in the other order", func(_ **ceremony.PlanOut, _ map[string]string, _, s *ceremony.JournalRead) {
			s.Lines[0], s.Lines[1] = s.Lines[1], s.Lines[0]
		}, "signatures.jsonl"},
		{"a signature line twice", func(_ **ceremony.PlanOut, _ map[string]string, _, s *ceremony.JournalRead) {
			s.Lines[1] = s.Lines[0]
		}, "signatures.jsonl"},
		{"a signature line that is not a line", func(_ **ceremony.PlanOut, _ map[string]string, _, s *ceremony.JournalRead) {
			s.Lines[2] = []byte("{}")
		}, "signatures.jsonl"},
		{"another kind in a signature line", func(_ **ceremony.PlanOut, _ map[string]string, _, s *ceremony.JournalRead) {
			s.Lines[0] = bytes.Replace(s.Lines[0], []byte(`"root-certificate"`), []byte(`"root-removal"`), 1)
		}, "signatures.jsonl"},
		{"the pin of another key in a signature line", func(_ **ceremony.PlanOut, pins map[string]string, _, _ *ceremony.JournalRead) {
			// The certificate of A is signed by A: a line that holds the pin of B is wrong.
			pins["A"], pins["B"] = pins["B"], pins["A"]
		}, "births.jsonl"},
		{"the key of the list line is the other key", func(_ **ceremony.PlanOut, pins map[string]string, _, s *ceremony.JournalRead) {
			s.Lines[4] = bytes.Replace(s.Lines[4], []byte(pins["A"]), []byte(pins["B"]), 1)
		}, "signatures.jsonl"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := pfPlan(t, pfFiles())
			pins, b, s := mkJournals(t, p)
			// A copy of the lines, so that a case edits its own.
			b.Lines = append([][]byte(nil), b.Lines...)
			s.Lines = append([][]byte(nil), s.Lines...)
			tc.edit(&p, pins, &b, &s)
			mkWantArtifactError(t, ceremony.CheckJournals(p, pins, b, s), "journals", tc.member)
		})
	}
}

func TestACertificateLineOfTheJournalHoldsTheKeyThatSignedAndTheRemovalLineToo(t *testing.T) {
	// Each signature line holds the pin of the subject of the signature in the plan.
	p := pfPlan(t, pfFiles())
	pins, b, s := mkJournals(t, p)
	for i, sg := range p.Signatures {
		l, err := files.ReadSignatureLine(s.Lines[i])
		if err != nil {
			t.Fatal(err)
		}
		if l.Key != pins[sg.Subject] {
			t.Errorf("the line %d holds the pin %s, the subject is %s", i+1, l.Key, sg.Subject)
		}
	}
	// And a line with the pin of the other label is refused wherever it stands.
	for i, sg := range p.Signatures {
		other := "A"
		if sg.Subject == "A" {
			other = "B"
		}
		lines := append([][]byte(nil), s.Lines...)
		lines[i] = bytes.Replace(lines[i], []byte(pins[sg.Subject]), []byte(pins[other]), 1)
		if err := ceremony.CheckJournals(p, pins, b, ceremony.JournalRead{Lines: lines}); err == nil {
			t.Errorf("the line %d with the pin of %s is accepted", i+1, other)
		}
	}
}

// ---- the readers do not change what they are given ----

func TestTheChecksDoNotChangeTheirInput(t *testing.T) {
	c := mkGoodCert()
	der := append([]byte(nil), c.DER...)
	_ = ceremony.CheckRootCertificate(c.DER, c.Want)
	if !bytes.Equal(der, c.DER) {
		t.Error("CheckRootCertificate changed the certificate")
	}
	r := mkRemovalSpec{}.build()
	stored := []byte(r.Text)
	cert := append([]byte(nil), r.Cert...)
	_ = ceremony.CheckRemovalAuthorisation("A", r.Pin, r.Cert, r.Text, stored)
	if string(stored) != r.Text || !bytes.Equal(cert, r.Cert) {
		t.Error("CheckRemovalAuthorisation changed its input")
	}
	p := pfPlan(t, pfFiles())
	pins, b, s := mkJournals(t, p)
	before := append([]byte(nil), b.Lines[0]...)
	_ = ceremony.CheckJournals(p, pins, b, s)
	if !bytes.Equal(before, b.Lines[0]) || len(pins) != 2 {
		t.Error("CheckJournals changed its input")
	}
}

// ---- the first list is signed by one of the two keys ----

// mkCountingSigner counts the calls that ask it to sign.
type mkCountingSigner struct {
	trustset.Signer
	calls *int
}

func (c mkCountingSigner) SignES384(input []byte) ([]byte, error) {
	*c.calls++
	return c.Signer.SignES384(input)
}

func TestTheFirstListNeedsOneOfTheTwoKeysAndAsksNoKeyForTwo(t *testing.T) {
	keys := mkRootKeys("A", "B")
	var roots []trustset.Root
	certs := map[string][]byte{}
	for _, k := range keys {
		roots = append(roots, trustset.Root{Label: k.Label, X509SPKISHA256: k.Pin})
		certs[k.Label] = k.Cert.DER
	}
	d, err := trustset.NewDraft(trustset.Input{Sequence: 1, SignedAt: pfClock, Roots: roots, Certificates: certs})
	if err != nil {
		t.Fatal(err)
	}
	if d.Kind() != trustset.KindFirst || len(d.Required()) != 0 || strings.Join(d.OneOf(), ",") != "A,B" {
		t.Fatalf("the first list is of the kind %v, requires %v, one of %v", d.Kind(), d.Required(), d.OneOf())
	}
	calls := 0
	var signers []trustset.Signer
	for _, k := range keys {
		cert, err := x509ParseCertificate(k.Cert.DER)
		if err != nil {
			t.Fatal(err)
		}
		sg, err := trustset.NewKeySigner(k.Label, cert, k.Key)
		if err != nil {
			t.Fatal(err)
		}
		signers = append(signers, mkCountingSigner{Signer: sg, calls: &calls})
	}
	if _, err := d.Sign(signers, nil); !errors.Is(err, trustset.ErrSigners) {
		t.Fatalf("two signers for the first list: %v, want ErrSigners", err)
	}
	if calls != 0 {
		t.Errorf("%d keys were asked to sign before the refusal", calls)
	}
	if _, err := d.Sign(signers[:1], nil); err != nil || calls != 1 {
		t.Errorf("one signer: %v, %d calls", err, calls)
	}
}

// ---- hostile input to the checks ----

func TestHostileInputToTheChecksIsRefusedAndDoesNotCrash(t *testing.T) {
	p := pfPlan(t, pfFiles())
	pins, births, sigs := mkJournals(t, p)
	big := bytes.Repeat([]byte("x"), 4<<20)
	manyLines := make([][]byte, 200000)
	for i := range manyLines {
		manyLines[i] = births.Lines[0]
	}
	deep := []byte(strings.Repeat("[", 100000))
	keys := mkRootKeys("A", "B")
	set := mkSetSpec{Keys: keys}.build(t)
	w := mkWantFor(keys, "A")
	list, err := ceremony.CheckRootList(set, w)
	if err != nil {
		t.Fatal(err)
	}
	c := mkGoodCert()
	r := mkRemovalSpec{}.build()
	for name, fn := range map[string]func() error{
		"a certificate of 4 MiB":           func() error { return ceremony.CheckRootCertificate(big, c.Want) },
		"a certificate that is nested":     func() error { return ceremony.CheckRootCertificate(deep, c.Want) },
		"a removal text of 4 MiB":          func() error { return ceremony.CheckRemovalAuthorisation("A", r.Pin, r.Cert, string(big), big) },
		"a removal text that is only dots": func() error { return ceremony.CheckRemovalAuthorisation("A", r.Pin, r.Cert, "..", []byte("..")) },
		"a removal stored file of 4 MiB":   func() error { return ceremony.CheckRemovalAuthorisation("A", r.Pin, r.Cert, r.Text, big) },
		"a CA bundle of 4 MiB":             func() error { return ceremony.CheckCABundle(big, list, w) },
		"a CA bundle that is nested":       func() error { return ceremony.CheckCABundle(deep, list, w) },
		"a root.json of 4 MiB":             func() error { return ceremony.CheckRootJSON(big, mkRootJSONWant()) },
		"a root.json that is nested":       func() error { return ceremony.CheckRootJSON(deep, mkRootJSONWant()) },
		"200000 birth lines":               func() error { return ceremony.CheckJournals(p, pins, ceremony.JournalRead{Lines: manyLines}, sigs) },
		"200000 signature lines":           func() error { return ceremony.CheckJournals(p, pins, births, ceremony.JournalRead{Lines: manyLines}) },
		"a birth line of 4 MiB": func() error {
			return ceremony.CheckJournals(p, pins, ceremony.JournalRead{Lines: [][]byte{big, big}}, sigs)
		},
		"a signature line of 4 MiB": func() error {
			return ceremony.CheckJournals(p, pins, births, ceremony.JournalRead{Lines: [][]byte{big, big, big, big, big}})
		},
		"a half line of 4 MiB": func() error {
			return ceremony.CheckJournals(p, pins, ceremony.JournalRead{Lines: births.Lines, Partial: big}, sigs)
		},
		"a nested journal line": func() error {
			return ceremony.CheckJournals(p, pins, ceremony.JournalRead{Lines: [][]byte{deep, deep}}, sigs)
		},
	} {
		t.Run(name, func(t *testing.T) {
			start := time.Now()
			err := fn()
			if err == nil {
				t.Fatal("accepted")
			}
			if _, ok := mkAs[*ceremony.ArtifactError](err); !ok || !pfPrintable(err.Error()) || len(err.Error()) > 4000 {
				t.Errorf("the error is %T, printable %v, %d bytes", err, pfPrintable(err.Error()), len(err.Error()))
			}
			if time.Since(start) > 20*time.Second {
				t.Errorf("the check took %v", time.Since(start))
			}
		})
	}
}
