package kms_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"reflect"
	"strings"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/handoff"
	"ritueel.id/ritueel/internal/handoff/evidence/kms"
)

func mustKeyARN(t testing.TB, s string) kms.KeyARN {
	t.Helper()
	a, err := kms.ParseKeyARN(s)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func read(t testing.TB, api kms.API) (*kms.Reading, error) {
	t.Helper()
	return kms.Read(t.(*testing.T).Context(), api, mustKeyARN(t, keyARN))
}

func wantFault(t testing.TB, err error, fault kms.Fault) *kms.Refusal {
	t.Helper()
	var r *kms.Refusal
	if !errors.As(err, &r) {
		t.Fatalf("error %v (%T), want a *kms.Refusal with the fault %q", err, err, fault)
	}
	if r.Fault != fault {
		t.Fatalf("fault %q (%s), want %q", r.Fault, r.Detail, fault)
	}
	if r.Error() != r.Detail {
		t.Fatalf("Error() is %q, Detail is %q", r.Error(), r.Detail)
	}
	if !printable(r.Detail) {
		t.Fatalf("the detail holds a character outside printable ASCII: %q", r.Detail)
	}
	if errors.Is(err, kms.ErrUndecided) {
		t.Fatalf("a refusal that is undecided as well: %v", err)
	}
	return r
}

func TestReadOfAGoodKey(t *testing.T) {
	api := newFake(t)
	rd, err := read(t, api)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"DescribeKey", "GetPublicKey", "GetKeyPolicy"}; !reflect.DeepEqual(api.callLog(), want) {
		t.Fatalf("calls %v, want %v", api.callLog(), want)
	}
	for i, a := range api.arns {
		if a != keyARN {
			t.Fatalf("call %d was for %q", i, a)
		}
	}
	if len(api.names) != 1 || api.names[0] != "default" || kms.PolicyName != "default" {
		t.Fatalf("the policy name asked for: %v", api.names)
	}
	if !reflect.DeepEqual(rd.Description, *api.desc) {
		t.Fatalf("description %+v, want %+v", rd.Description, *api.desc)
	}
	if !bytes.Equal(rd.PublicKeyDER, api.pub.PublicKey) {
		t.Fatal("the bytes of the key are not the bytes KMS gave")
	}
	want, err := x509.ParsePKIXPublicKey(api.pub.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if !rd.Key.Equal(want) {
		t.Fatal("the key is not the key KMS gave")
	}
	sum := sha256.Sum256([]byte(api.policy))
	if rd.PolicySHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("policy digest %s", rd.PolicySHA256)
	}
	if !reflect.DeepEqual(rd.SignPrincipals, []handoff.Principal{role("example-key-holder")}) {
		t.Fatalf("principals %+v", rd.SignPrincipals)
	}
}

func TestReadAcceptsAMultiRegionKeyAndRecordsIt(t *testing.T) {
	arn := "arn:aws:kms:eu-west-1:123456789012:key/" + mrk
	api := newFake(t)
	api.desc = goodDescription(arn)
	api.desc.MultiRegion = true
	api.pub.KeyID = arn
	rd, err := kms.Read(t.Context(), api, mustKeyARN(t, arn))
	if err != nil {
		t.Fatal(err)
	}
	if !rd.Description.MultiRegion {
		t.Fatal("the multi-Region flag is lost")
	}
}

// The policy digest is the digest of the text exactly as the service gave it, not of a re-written form.
func TestThePolicyDigestIsOfTheTextAsReturned(t *testing.T) {
	base := holderPolicy(t)
	texts := []string{base, base + "\n", " " + base, strings.ReplaceAll(base, `"Version":`, `"Version" : `), base + "  \t"}
	seen := map[string]bool{}
	for _, text := range texts {
		api := newFake(t)
		api.policy = text
		rd, err := read(t, api)
		if err != nil {
			t.Fatalf("%q: %v", text, err)
		}
		sum := sha256.Sum256([]byte(text))
		if rd.PolicySHA256 != hex.EncodeToString(sum[:]) {
			t.Fatalf("digest %s for %q", rd.PolicySHA256, text)
		}
		seen[rd.PolicySHA256] = true
	}
	if len(seen) != len(texts) {
		t.Fatalf("%d digests for %d different texts", len(seen), len(texts))
	}
}

func TestReadOfADescriptionThatIsWrong(t *testing.T) {
	// Each row changes one member. Its twin is TestReadOfAGoodKey, which differs in that member only.
	rows := []struct {
		name   string
		change func(d *kms.KeyDescription)
		fault  kms.Fault
	}{
		{"state Disabled", func(d *kms.KeyDescription) { d.KeyState = "Disabled" }, kms.FaultState},
		{"state PendingDeletion", func(d *kms.KeyDescription) { d.KeyState = "PendingDeletion" }, kms.FaultState},
		{"state PendingImport", func(d *kms.KeyDescription) { d.KeyState = "PendingImport" }, kms.FaultState},
		{"state PendingReplicaDeletion", func(d *kms.KeyDescription) { d.KeyState = "PendingReplicaDeletion" }, kms.FaultState},
		{"state Creating", func(d *kms.KeyDescription) { d.KeyState = "Creating" }, kms.FaultState},
		{"state Unavailable", func(d *kms.KeyDescription) { d.KeyState = "Unavailable" }, kms.FaultState},
		{"state enabled in lower case", func(d *kms.KeyDescription) { d.KeyState = "enabled" }, kms.FaultState},
		{"state ENABLED", func(d *kms.KeyDescription) { d.KeyState = "ENABLED" }, kms.FaultState},
		{"state with a trailing space", func(d *kms.KeyDescription) { d.KeyState = "Enabled " }, kms.FaultState},
		{"state empty", func(d *kms.KeyDescription) { d.KeyState = "" }, kms.FaultState},
		{"usage ENCRYPT_DECRYPT", func(d *kms.KeyDescription) { d.KeyUsage = "ENCRYPT_DECRYPT" }, kms.FaultUsage},
		{"usage GENERATE_VERIFY_MAC", func(d *kms.KeyDescription) { d.KeyUsage = "GENERATE_VERIFY_MAC" }, kms.FaultUsage},
		{"usage KEY_AGREEMENT", func(d *kms.KeyDescription) { d.KeyUsage = "KEY_AGREEMENT" }, kms.FaultUsage},
		{"usage in lower case", func(d *kms.KeyDescription) { d.KeyUsage = "sign_verify" }, kms.FaultUsage},
		{"usage empty", func(d *kms.KeyDescription) { d.KeyUsage = "" }, kms.FaultUsage},
		{"spec ECC_NIST_P256", func(d *kms.KeyDescription) { d.KeySpec = "ECC_NIST_P256" }, kms.FaultSpec},
		{"spec ECC_NIST_P521", func(d *kms.KeyDescription) { d.KeySpec = "ECC_NIST_P521" }, kms.FaultSpec},
		{"spec RSA_2048", func(d *kms.KeyDescription) { d.KeySpec = "RSA_2048" }, kms.FaultSpec},
		{"spec SYMMETRIC_DEFAULT", func(d *kms.KeyDescription) { d.KeySpec = "SYMMETRIC_DEFAULT" }, kms.FaultSpec},
		{"spec ECC_SECG_P256K1", func(d *kms.KeyDescription) { d.KeySpec = "ECC_SECG_P256K1" }, kms.FaultSpec},
		{"spec in lower case", func(d *kms.KeyDescription) { d.KeySpec = "ecc_nist_p384" }, kms.FaultSpec},
		{"spec empty", func(d *kms.KeyDescription) { d.KeySpec = "" }, kms.FaultSpec},
		{"origin EXTERNAL", func(d *kms.KeyDescription) { d.Origin = "EXTERNAL" }, kms.FaultOrigin},
		{"origin AWS_CLOUDHSM", func(d *kms.KeyDescription) { d.Origin = "AWS_CLOUDHSM" }, kms.FaultOrigin},
		{"origin EXTERNAL_KEY_STORE", func(d *kms.KeyDescription) { d.Origin = "EXTERNAL_KEY_STORE" }, kms.FaultOrigin},
		{"origin in lower case", func(d *kms.KeyDescription) { d.Origin = "aws_kms" }, kms.FaultOrigin},
		{"origin empty", func(d *kms.KeyDescription) { d.Origin = "" }, kms.FaultOrigin},
		{"manager AWS", func(d *kms.KeyDescription) { d.KeyManager = "AWS" }, kms.FaultManager},
		{"manager in lower case", func(d *kms.KeyDescription) { d.KeyManager = "customer" }, kms.FaultManager},
		{"manager empty", func(d *kms.KeyDescription) { d.KeyManager = "" }, kms.FaultManager},
		{"ARN differs in the last character", func(d *kms.KeyDescription) { d.ARN = d.ARN[:len(d.ARN)-1] + "6" }, kms.FaultARN},
		{"ARN differs in the Region", func(d *kms.KeyDescription) { d.ARN = strings.Replace(d.ARN, "eu-west-1", "eu-west-2", 1) }, kms.FaultARN},
		{"ARN differs in the account", func(d *kms.KeyDescription) { d.ARN = strings.Replace(d.ARN, "123456789012", "000000000000", 1) }, kms.FaultARN},
		{"ARN is the key id only", func(d *kms.KeyDescription) { d.ARN = d.KeyID }, kms.FaultARN},
		{"ARN differs in case only", func(d *kms.KeyDescription) { d.ARN = strings.ToUpper(d.ARN) }, kms.FaultARN},
		{"ARN has a trailing space", func(d *kms.KeyDescription) { d.ARN += " " }, kms.FaultARN},
		{"ARN has a leading space", func(d *kms.KeyDescription) { d.ARN = " " + d.ARN }, kms.FaultARN},
		{"ARN has a trailing newline", func(d *kms.KeyDescription) { d.ARN += "\n" }, kms.FaultARN},
		{"ARN is empty", func(d *kms.KeyDescription) { d.ARN = "" }, kms.FaultARN},
	}
	for _, tc := range rows {
		t.Run(tc.name, func(t *testing.T) {
			api := newFake(t)
			tc.change(api.desc)
			rd, err := read(t, api)
			if rd != nil {
				t.Fatalf("a reading beside an error: %+v", rd)
			}
			_ = wantFault(t, err, tc.fault)
			if got := api.callLog(); !reflect.DeepEqual(got, []string{"DescribeKey"}) {
				t.Fatalf("calls %v: a refusal of the description must stop the read", got)
			}
		})
	}
}

// Members that are not rules do not refuse a key.
func TestReadIgnoresTheMembersThatAreNotRules(t *testing.T) {
	api := newFake(t)
	api.desc.KeyID = "something-else"
	api.desc.SigningAlgorithms = nil
	api.desc.MultiRegion = true
	if _, err := read(t, api); err != nil {
		t.Fatal(err)
	}
	api = newFake(t)
	api.desc.SigningAlgorithms = []string{"RSASSA_PKCS1_V1_5_SHA_256"}
	if _, err := read(t, api); err != nil {
		t.Fatal(err)
	}
}

// publicKeyRows are public key answers that are wrong, each in one way.
func publicKeyRows(t testing.TB) map[string]func(a *kms.PublicKeyAnswer) {
	t.Helper()
	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p521, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der := func(pub any) []byte {
		b, err := x509.MarshalPKIXPublicKey(pub)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	good := newKey(t)
	goodDER := der(&good.PublicKey)
	off := bytes.Clone(goodDER)
	off[len(off)-1] ^= 0x01 // a point that is not on the curve
	compressed := compressedP384(t, &good.PublicKey)
	set := func(b []byte) func(a *kms.PublicKeyAnswer) {
		return func(a *kms.PublicKeyAnswer) { a.PublicKey = b }
	}
	return map[string]func(a *kms.PublicKeyAnswer){
		"P-256":                      set(der(&p256.PublicKey)),
		"P-521":                      set(der(&p521.PublicKey)),
		"Ed25519":                    set(der(edPub)),
		"RSA":                        set(der(&rsaKey.PublicKey)),
		"garbage":                    set([]byte("not a key")),
		"one zero byte":              set([]byte{0}),
		"empty":                      set([]byte{}),
		"nil":                        set(nil),
		"1025 bytes":                 set(append(bytes.Clone(goodDER), make([]byte, 1025-len(goodDER))...)),
		"1024 bytes of padding":      set(append(bytes.Clone(goodDER), make([]byte, 1024-len(goodDER))...)),
		"trailing bytes":             set(append(bytes.Clone(goodDER), 0)),
		"a leading byte":             set(append([]byte{0}, goodDER...)),
		"a point not on the curve":   set(off),
		"a compressed point":         set(compressed),
		"a truncated key":            set(goodDER[:len(goodDER)-1]),
		"the point alone":            set(goodDER[len(goodDER)-97:]),
		"explicit curve parameters":  set(explicitParametersP384(t, &good.PublicKey)),
		"a PEM block":                set([]byte("-----BEGIN PUBLIC KEY-----\n" + "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE\n" + "-----END PUBLIC KEY-----\n")),
		"the key id of another key":  func(a *kms.PublicKeyAnswer) { a.KeyID = strings.Replace(a.KeyID, "5555", "5556", 1) },
		"the key id is the bare id":  func(a *kms.PublicKeyAnswer) { a.KeyID = "11111111-2222-3333-4444-555555555555" },
		"the key id is empty":        func(a *kms.PublicKeyAnswer) { a.KeyID = "" },
		"the key id in upper case":   func(a *kms.PublicKeyAnswer) { a.KeyID = strings.ToUpper(a.KeyID) },
		"the key spec P-256":         func(a *kms.PublicKeyAnswer) { a.KeySpec = "ECC_NIST_P256" },
		"the key spec is empty":      func(a *kms.PublicKeyAnswer) { a.KeySpec = "" },
		"the key spec in lower case": func(a *kms.PublicKeyAnswer) { a.KeySpec = "ecc_nist_p384" },
	}
}

// compressedP384 is the SubjectPublicKeyInfo of the key with the point in its compressed form.
func compressedP384(t testing.TB, pub *ecdsa.PublicKey) []byte {
	t.Helper()
	full := keyDER(t, pub)
	// The last 97 bytes are 0x04 X Y. The compressed form is 0x02 or 0x03 and X, 49 bytes, and the lengths of
	// the structure change with it.
	x := full[len(full)-96 : len(full)-48]
	y := full[len(full)-48:]
	prefix := byte(0x02)
	if y[len(y)-1]&1 == 1 {
		prefix = 0x03
	}
	point := append([]byte{prefix}, x...)
	algo := full[2 : 2+2+7+2+5] // SEQUENCE { id-ecPublicKey, secp384r1 } as written in full
	bits := append([]byte{0x03, byte(len(point) + 1), 0x00}, point...)
	body := append(bytes.Clone(algo), bits...)
	return append([]byte{0x30, byte(len(body))}, body...)
}

// explicitParametersP384 is a SubjectPublicKeyInfo whose algorithm parameters spell the curve out as numbers
// instead of naming it.
func explicitParametersP384(t testing.TB, pub *ecdsa.PublicKey) []byte {
	t.Helper()
	type fieldID struct {
		FieldType asn1.ObjectIdentifier
		Prime     *big.Int
	}
	type curve struct{ A, B []byte }
	type ecParameters struct {
		Version  int
		FieldID  fieldID
		Curve    curve
		Base     []byte
		Order    *big.Int
		Cofactor int
	}
	type algorithm struct {
		Algorithm  asn1.ObjectIdentifier
		Parameters ecParameters
	}
	type spki struct {
		Algorithm algorithm
		PublicKey asn1.BitString
	}
	c := elliptic.P384().Params()
	a := new(big.Int).Sub(c.P, big.NewInt(3))
	point := keyDER(t, pub)
	point = point[len(point)-97:]
	der, err := asn1.Marshal(spki{
		Algorithm: algorithm{
			Algorithm: asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1},
			Parameters: ecParameters{
				Version: 1,
				FieldID: fieldID{FieldType: asn1.ObjectIdentifier{1, 2, 840, 10045, 1, 1}, Prime: c.P},
				Curve:   curve{A: a.FillBytes(make([]byte, 48)), B: c.B.FillBytes(make([]byte, 48))},
				Base:    append([]byte{4}, append(c.Gx.FillBytes(make([]byte, 48)), c.Gy.FillBytes(make([]byte, 48))...)...),
				Order:   c.N, Cofactor: 1,
			},
		},
		PublicKey: asn1.BitString{Bytes: point, BitLength: 8 * len(point)},
	})
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestReadOfAPublicKeyThatIsWrong(t *testing.T) {
	for name, change := range publicKeyRows(t) {
		t.Run(name, func(t *testing.T) {
			api := newFake(t)
			change(api.pub)
			rd, err := read(t, api)
			if rd != nil {
				t.Fatalf("a reading beside an error: %+v", rd)
			}
			var r *kms.Refusal
			if !errors.As(err, &r) {
				t.Fatalf("error %v (%T), want a refusal", err, err)
			}
			if r.Fault != kms.FaultKey && r.Fault != kms.FaultARN && r.Fault != kms.FaultSpec {
				t.Fatalf("fault %q", r.Fault)
			}
			_ = wantFault(t, err, r.Fault)
			if got := api.callLog(); !reflect.DeepEqual(got, []string{"DescribeKey", "GetPublicKey"}) {
				t.Fatalf("calls %v: a refusal of the key must stop the read before the policy", got)
			}
		})
	}
}

// The members of the rows that name the fault: the key id and the spec are not a fault of the key bytes.
func TestReadNamesTheFaultOfAPublicKey(t *testing.T) {
	rows := map[string]kms.Fault{
		"the key id of another key": kms.FaultARN,
		"the key id is empty":       kms.FaultARN,
		"the key spec P-256":        kms.FaultSpec,
		"the key spec is empty":     kms.FaultSpec,
		"P-256":                     kms.FaultKey,
		"garbage":                   kms.FaultKey,
		"trailing bytes":            kms.FaultKey,
		"1025 bytes":                kms.FaultKey,
		"empty":                     kms.FaultKey,
	}
	all := publicKeyRows(t)
	for name, fault := range rows {
		api := newFake(t)
		all[name](api.pub)
		_, err := read(t, api)
		if r := wantFault(t, err, fault); r.Detail == "" {
			t.Fatalf("%s: no detail", name)
		}
	}
	// The limit is its own refusal: a text of 1025 bytes and one of 1024 are not refused for the same words.
	long, short := newFake(t), newFake(t)
	all["1025 bytes"](long.pub)
	all["1024 bytes of padding"](short.pub)
	_, errLong := read(t, long)
	_, errShort := read(t, short)
	if errLong.Error() == errShort.Error() {
		t.Fatalf("the limit of the key length gives the same words as a key that does not parse: %v", errLong)
	}
}

func TestTheReadingSharesNothingWithTheAnswers(t *testing.T) {
	api := newFake(t)
	first, err := read(t, api)
	if err != nil {
		t.Fatal(err)
	}
	wantDER := bytes.Clone(api.pub.PublicKey)
	wantARN := api.desc.ARN
	wantAlgs := []string{"ECDSA_SHA_384"}

	// The caller changes what it holds: nothing the first Reading holds changes.
	api.pub.PublicKey[len(api.pub.PublicKey)-1] ^= 1
	api.desc.ARN = "changed"
	api.desc.SigningAlgorithms[0] = "changed"
	if !bytes.Equal(first.PublicKeyDER, wantDER) {
		t.Fatal("PublicKeyDER shares its bytes with the answer")
	}
	if first.Description.ARN != wantARN || !reflect.DeepEqual(first.Description.SigningAlgorithms, wantAlgs) {
		t.Fatalf("the description shares memory with the answer: %+v", first.Description)
	}

	// The reading is changed: the next reading of the same key is the key of the answer.
	api = newFake(t)
	a, err := read(t, api)
	if err != nil {
		t.Fatal(err)
	}
	a.Key.X.SetInt64(7) //nolint:staticcheck // the test writes through the key to see that nothing is shared
	a.PublicKeyDER[0] = 0
	a.SignPrincipals = append(a.SignPrincipals[:0], handoff.Principal{})
	b, err := read(t, api)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := x509.ParsePKIXPublicKey(api.pub.PublicKey)
	if !b.Key.Equal(want) {
		t.Fatal("the key of the second reading is not the key of the answer")
	}
	if b.PublicKeyDER[0] != 0x30 {
		t.Fatal("the bytes of the second reading were changed through the first")
	}
}

func TestReadOfAPolicyThatIsTooLong(t *testing.T) {
	api := newFake(t)
	api.policy = strings.Repeat(" ", kms.MaxPolicyBytes+1)
	rd, err := read(t, api)
	if rd != nil {
		t.Fatalf("a reading beside an error: %+v", rd)
	}
	r := wantFault(t, err, kms.FaultPolicy)
	if !strings.Contains(r.Detail, "longer than the limit") {
		t.Fatalf("the refusal is not for the length: %s", r.Detail)
	}
	// The twin: exactly the limit is read.
	api = newFake(t)
	doc := holderPolicy(t)
	api.policy = doc + strings.Repeat(" ", kms.MaxPolicyBytes-len(doc))
	if _, err := read(t, api); err != nil {
		t.Fatal(err)
	}
}

func TestReadOfAPolicyThatIsRefused(t *testing.T) {
	for name, policy := range map[string]string{
		"empty": "", "not JSON": "x", "a list": "[]", "a float": `{"Version":"2012-10-17","Statement":[],"Id":1.5}`,
		"an unknown member": `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"kms:Sign","Extra":1}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			api := newFake(t)
			api.policy = policy
			rd, err := read(t, api)
			if rd != nil {
				t.Fatalf("a reading beside an error: %+v", rd)
			}
			_ = wantFault(t, err, kms.FaultPolicy)
			if got := api.callLog(); len(got) != 3 {
				t.Fatalf("calls %v", got)
			}
		})
	}
}

func TestReadOfAZeroKeyARN(t *testing.T) {
	api := newFake(t)
	rd, err := kms.Read(t.Context(), api, kms.KeyARN{})
	if rd != nil {
		t.Fatalf("a reading: %+v", rd)
	}
	_ = wantFault(t, err, kms.FaultARN)
	if got := api.callLog(); len(got) != 0 {
		t.Fatalf("calls %v for a zero ARN", got)
	}
	for _, a := range []kms.KeyARN{
		{Partition: "aws", Region: "eu-west-1", Account: "123456789012", ID: "x"},
		{Partition: "aws", Region: "EU", Account: "123456789012", ID: uuid},
		{Partition: "aws", Region: "eu-west-1", Account: "1", ID: uuid},
		{Partition: "aws:", Region: "eu-west-1", Account: "123456789012", ID: uuid},
		{Partition: "aws", Region: "eu-west-1", Account: "123456789012", ID: uuid + "/x"},
	} {
		_, err := kms.Read(t.Context(), api, a)
		_ = wantFault(t, err, kms.FaultARN)
	}
	if got := api.callLog(); len(got) != 0 {
		t.Fatalf("calls %v for a bad ARN", got)
	}
}

func TestReadOfACallThatIsWrong(t *testing.T) {
	t.Run("no context", func(t *testing.T) {
		//nolint:staticcheck // a nil context is the case under test
		_, err := kms.Read(nil, newFake(t), mustKeyARN(t, keyARN)) //nolint:revive
		if !errors.Is(err, kms.ErrConfig) {
			t.Fatalf("error %v", err)
		}
	})
	t.Run("no API", func(t *testing.T) {
		if _, err := kms.Read(t.Context(), nil, mustKeyARN(t, keyARN)); !errors.Is(err, kms.ErrConfig) {
			t.Fatalf("error %v", err)
		}
	})
	t.Run("an API that holds a nil pointer", func(t *testing.T) {
		var api *fakeAPI
		if _, err := kms.Read(t.Context(), api, mustKeyARN(t, keyARN)); !errors.Is(err, kms.ErrConfig) {
			t.Fatalf("error %v", err)
		}
	})
	t.Run("DescribeKey answers nothing", func(t *testing.T) {
		api := newFake(t)
		api.desc = nil
		_, err := read(t, api)
		wantUndecided(t, err)
		if got := api.callLog(); !reflect.DeepEqual(got, []string{"DescribeKey"}) {
			t.Fatalf("calls %v", got)
		}
	})
	t.Run("GetPublicKey answers nothing", func(t *testing.T) {
		api := newFake(t)
		api.pub = nil
		_, err := read(t, api)
		wantUndecided(t, err)
		if got := api.callLog(); !reflect.DeepEqual(got, []string{"DescribeKey", "GetPublicKey"}) {
			t.Fatalf("calls %v", got)
		}
	})
}

// codes are the codes that refuse, with the fault of each.
var refusingCodes = map[string]kms.Fault{
	"AccessDeniedException":         kms.FaultAccess,
	"AccessDenied":                  kms.FaultAccess,
	"NotFoundException":             kms.FaultNotFound,
	"InvalidArnException":           kms.FaultARN,
	"DisabledException":             kms.FaultState,
	"KMSInvalidStateException":      kms.FaultState,
	"UnsupportedOperationException": kms.FaultSpec,
	"InvalidKeyUsageException":      kms.FaultUsage,
}

var undecidedCodes = []string{
	"ThrottlingException", "KMSInternalException", "DependencyTimeoutException", "LimitExceededException", "InternalFailure",
	"ServiceUnavailable", "RequestTimeout", "SomethingElse", "", "accessdeniedexception", "AccessDeniedException ", "NotFound",
	"InvalidGrantTokenException", "KeyUnavailableException", "ExpiredTokenException", "ValidationException",
}

// failures lists the ways that a call can fail, one for each of the three calls.
func failingCall(api *fakeAPI, call string, err error) {
	switch call {
	case "DescribeKey":
		api.desc, api.descErr = nil, err
	case "GetPublicKey":
		api.pub, api.pubErr = nil, err
	case "GetKeyPolicy":
		api.policy, api.policyErr = "", err
	}
}

func TestReadOfACallThatFails(t *testing.T) {
	calls := []string{"DescribeKey", "GetPublicKey", "GetKeyPolicy"}
	for i, call := range calls {
		for code, fault := range refusingCodes {
			t.Run(call+" "+code, func(t *testing.T) {
				api := newFake(t)
				failingCall(api, call, &kms.APIError{Code: code})
				rd, err := read(t, api)
				if rd != nil {
					t.Fatalf("a reading beside an error: %+v", rd)
				}
				_ = wantFault(t, err, fault)
				if got := api.callLog(); len(got) != i+1 {
					t.Fatalf("calls %v", got)
				}
			})
			t.Run(call+" "+code+" wrapped", func(t *testing.T) {
				api := newFake(t)
				failingCall(api, call, fmt.Errorf("the service said no: %w", &kms.APIError{Code: code}))
				_, err := read(t, api)
				_ = wantFault(t, err, fault)
			})
		}
		for _, code := range undecidedCodes {
			t.Run(call+" undecided "+code, func(t *testing.T) {
				api := newFake(t)
				failingCall(api, call, &kms.APIError{Code: code})
				rd, err := read(t, api)
				if rd != nil {
					t.Fatalf("a reading beside an error: %+v", rd)
				}
				wantUndecided(t, err)
				if got := api.callLog(); len(got) != i+1 {
					t.Fatalf("calls %v", got)
				}
			})
		}
		for name, e := range map[string]error{
			"a plain error": errors.New("connection reset"), "Canceled": context.Canceled, "DeadlineExceeded": context.DeadlineExceeded,
			"a wrapped Canceled": fmt.Errorf("x: %w", context.Canceled),
		} {
			t.Run(call+" "+name, func(t *testing.T) {
				api := newFake(t)
				failingCall(api, call, e)
				_, err := read(t, api)
				wantUndecided(t, err)
				if errors.Is(e, context.Canceled) != errors.Is(err, context.Canceled) {
					t.Fatalf("the context error is not kept: %v", err)
				}
				if errors.Is(e, context.DeadlineExceeded) != errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("the context error is not kept: %v", err)
				}
			})
		}
	}
}

// A hostile API cannot make its own error read as a refusal: the error is not wrapped, only a code of the
// service is shown, escaped.
func TestAnErrorOfTheAPIIsNeverReadAsARefusal(t *testing.T) {
	const secret = "SECRET-TOKEN-1234"
	hostile := map[string]error{
		"a kms refusal":        &kms.Refusal{Fault: kms.FaultAccess, Detail: secret},
		"a code error":         &handoff.CodeError{Code: handoff.CodeProofInvalid, Detail: secret},
		"a wrapped code error": fmt.Errorf("%s: %w", secret, &handoff.CodeError{Code: handoff.CodeMalformed}),
		"ErrConfig":            fmt.Errorf("%s: %w", secret, kms.ErrConfig),
		"a plain error":        errors.New(secret),
	}
	for name, e := range hostile {
		for _, call := range []string{"DescribeKey", "GetPublicKey", "GetKeyPolicy"} {
			t.Run(name+" "+call, func(t *testing.T) {
				api := newFake(t)
				failingCall(api, call, e)
				_, err := read(t, api)
				wantUndecided(t, err)
				if errors.Is(err, kms.ErrConfig) {
					t.Fatalf("the caller's error made the result a configuration error: %v", err)
				}
				if strings.Contains(err.Error(), secret) {
					t.Fatalf("the text of the caller's error is in the result: %v", err)
				}
			})
		}
	}
	// A code of the service is shown, escaped one to one and cut.
	api := newFake(t)
	failingCall(api, "DescribeKey", &kms.APIError{Code: "Thrott\x00ling\xe2\x80\xae " + strings.Repeat("x", 500)})
	_, err := read(t, api)
	wantUndecided(t, err)
	if !printable(err.Error()) || len(err.Error()) > 400 {
		t.Fatalf("the error is not short printable ASCII: %q", err.Error())
	}
}

func TestAPIErrorWords(t *testing.T) {
	if got := (&kms.APIError{Code: "AccessDeniedException"}).Error(); !strings.Contains(got, "AccessDeniedException") {
		t.Fatalf("the code is not in %q", got)
	}
	var nilErr *kms.APIError
	if nilErr.Error() == "" {
		t.Fatal("a nil APIError has no words")
	}
	hostile := (&kms.APIError{Code: "a\nb\x00c\xff" + strings.Repeat("z", 1000)}).Error()
	if !printable(hostile) || len(hostile) > 300 {
		t.Fatalf("not short printable ASCII: %q", hostile)
	}
	var nilRefusal *kms.Refusal
	if nilRefusal.Error() == "" {
		t.Fatal("a nil Refusal has no words")
	}
}

// The refusal words that show a value from the service show it escaped and cut.
func TestARefusalShowsAValueEscapedAndCut(t *testing.T) {
	hostile := "Ena\xe2\x80\xaebled\x00\n\"" + strings.Repeat("y", 400)
	rows := map[string]func(a *fakeAPI){
		"state":        func(a *fakeAPI) { a.desc.KeyState = hostile },
		"usage":        func(a *fakeAPI) { a.desc.KeyUsage = hostile },
		"spec":         func(a *fakeAPI) { a.desc.KeySpec = hostile },
		"origin":       func(a *fakeAPI) { a.desc.Origin = hostile },
		"manager":      func(a *fakeAPI) { a.desc.KeyManager = hostile },
		"public spec":  func(a *fakeAPI) { a.pub.KeySpec = hostile },
		"ARN reported": func(a *fakeAPI) { a.desc.ARN = hostile },
		"key id":       func(a *fakeAPI) { a.pub.KeyID = hostile },
	}
	for name, change := range rows {
		t.Run(name, func(t *testing.T) {
			api := newFake(t)
			change(api)
			_, err := read(t, api)
			var r *kms.Refusal
			if !errors.As(err, &r) {
				t.Fatalf("error %v", err)
			}
			if !printable(r.Detail) {
				t.Fatalf("the detail is not printable ASCII: %q", r.Detail)
			}
			if len(r.Detail) > 300 {
				t.Fatalf("the detail is %d bytes: a value is not cut", len(r.Detail))
			}
			if strings.Contains(r.Detail, strings.Repeat("y", 200)) {
				t.Fatalf("the value is not cut: %q", r.Detail)
			}
		})
	}
}

// A done context makes no call, and a context that ends during a call stops the read before the next one.
func TestReadWithAContextThatEnds(t *testing.T) {
	t.Run("already cancelled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		api := newFake(t)
		rd, err := kms.Read(ctx, api, mustKeyARN(t, keyARN))
		if rd != nil {
			t.Fatalf("a reading: %+v", rd)
		}
		wantUndecided(t, err)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("the context error is not kept: %v", err)
		}
		if got := api.callLog(); len(got) != 0 {
			t.Fatalf("calls %v with a cancelled context", got)
		}
	})
	t.Run("already past its deadline", func(t *testing.T) {
		ctx, cancel := context.WithDeadline(t.Context(), time.Now().Add(-time.Hour))
		defer cancel()
		api := newFake(t)
		_, err := kms.Read(ctx, api, mustKeyARN(t, keyARN))
		wantUndecided(t, err)
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("the context error is not kept: %v", err)
		}
		if got := api.callLog(); len(got) != 0 {
			t.Fatalf("calls %v", got)
		}
	})
	for i, call := range []string{"DescribeKey", "GetPublicKey", "GetKeyPolicy"} {
		t.Run("cancelled during "+call, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			api := newFake(t)
			api.hook = func(c string) {
				if c == call {
					cancel()
				}
			}
			rd, err := kms.Read(ctx, api, mustKeyARN(t, keyARN))
			if call == "GetKeyPolicy" {
				// The last call has answered: the read is whole, and the answer is read.
				if err != nil || rd == nil {
					t.Fatalf("the last call answered, and the read gave %v", err)
				}
				return
			}
			if rd != nil {
				t.Fatalf("a reading: %+v", rd)
			}
			wantUndecided(t, err)
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("the context error is not kept: %v", err)
			}
			if got := api.callLog(); len(got) != i+1 {
				t.Fatalf("calls %v", got)
			}
		})
	}
	t.Run("an API that returns the error of the context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		api := newFake(t)
		api.descErr = ctx.Err()
		cancel()
		api.descErr = context.Canceled
		_, err := kms.Read(t.Context(), api, mustKeyARN(t, keyARN))
		wantUndecided(t, err)
	})
}

// Read leaves the descriptions alone: an API that returns the same value twice is read twice alike.
func TestReadTwiceGivesTheSameReading(t *testing.T) {
	api := newFake(t)
	a, err := read(t, api)
	if err != nil {
		t.Fatal(err)
	}
	b, err := read(t, api)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(a.Description, b.Description) || a.PolicySHA256 != b.PolicySHA256 || !a.Key.Equal(b.Key) {
		t.Fatal("two readings of one key differ")
	}
}

func FuzzReadPublicKey(f *testing.F) {
	key := newKey(f)
	good := keyDER(f, &key.PublicKey)
	for _, s := range [][]byte{nil, {}, good, good[:50], append(bytes.Clone(good), 0), []byte("x"), bytes.Repeat([]byte{0x30}, 2000)} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, der []byte) {
		api := &fakeAPI{
			desc:   goodDescription(keyARN),
			pub:    &kms.PublicKeyAnswer{KeyID: keyARN, KeySpec: "ECC_NIST_P384", PublicKey: der},
			policy: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"` + holder + `"},"Action":"kms:Sign"}]}`,
		}
		rd, err := kms.Read(t.Context(), api, mustKeyARN(t, keyARN))
		if err != nil {
			if rd != nil {
				t.Fatal("a reading beside an error")
			}
			var r *kms.Refusal
			if !errors.As(err, &r) || r.Fault != kms.FaultKey {
				t.Fatalf("error %v", err)
			}
			return
		}
		if !bytes.Equal(rd.PublicKeyDER, der) {
			t.Fatal("an accepted key is not in its one spelling")
		}
		if rd.Key == nil || rd.Key.Curve != elliptic.P384() || len(der) > kms.MaxPublicKey {
			t.Fatalf("an accepted key that is not one P-384 key of at most %d bytes", kms.MaxPublicKey)
		}
		back, err := x509.MarshalPKIXPublicKey(rd.Key)
		if err != nil || !bytes.Equal(back, der) {
			t.Fatal("the key does not write back to its bytes")
		}
	})
}

// The limits are the numbers that the maker of the page fixed for this package; a test that reads a bound
// through its constant cannot see the constant change, so the numbers are pinned here.
func TestTheLimits(t *testing.T) {
	for name, pair := range map[string][2]int{
		"MaxPolicyBytes": {kms.MaxPolicyBytes, 64 << 10}, "MaxStatements": {kms.MaxStatements, 200}, "MaxPrincipals": {kms.MaxPrincipals, 1000},
		"MaxTextLength": {kms.MaxTextLength, 2048}, "MaxActions": {kms.MaxActions, 1000}, "MaxPatternLen": {kms.MaxPatternLen, 256},
		"MaxPublicKey": {kms.MaxPublicKey, 1024},
	} {
		if pair[0] != pair[1] {
			t.Errorf("%s is %d, want %d", name, pair[0], pair[1])
		}
	}
	if kms.PolicyName != "default" {
		t.Errorf("PolicyName is %q", kms.PolicyName)
	}
}

// A value that the words name is in them, escaped, and a value that is longer than 120 characters is cut
// with three dots.
func TestARefusalNamesTheValueItFound(t *testing.T) {
	api := newFake(t)
	api.desc.KeyState = "PendingDeletion"
	_, err := read(t, api)
	r := wantFault(t, err, kms.FaultState)
	if !strings.Contains(r.Detail, "PendingDeletion") {
		t.Fatalf("the detail does not name the state: %q", r.Detail)
	}

	api = newFake(t)
	api.desc.KeyUsage = strings.Repeat("u", 120)
	_, err = read(t, api)
	r = wantFault(t, err, kms.FaultUsage)
	if !strings.Contains(r.Detail, strings.Repeat("u", 120)) || strings.Contains(r.Detail, "...") {
		t.Fatalf("a value of 120 characters is shown whole: %q", r.Detail)
	}

	api = newFake(t)
	api.desc.KeyUsage = strings.Repeat("u", 121)
	_, err = read(t, api)
	r = wantFault(t, err, kms.FaultUsage)
	if !strings.Contains(r.Detail, strings.Repeat("u", 120)+"...") || strings.Contains(r.Detail, strings.Repeat("u", 121)) {
		t.Fatalf("a value of 121 characters is cut: %q", r.Detail)
	}

	// The text is escaped one to one: a backslash is doubled and a space is written out, so that two
	// different values never read alike.
	api = newFake(t)
	api.desc.KeyManager = "a b" + "\\" + "c"
	_, err = read(t, api)
	r = wantFault(t, err, kms.FaultManager)
	if !strings.Contains(r.Detail, `a\x20b\\c`) {
		t.Fatalf("the value is not escaped one to one: %q", r.Detail)
	}
	if code := (&kms.APIError{Code: "a b"}).Error(); !strings.HasSuffix(code, `a\x20b`) {
		t.Fatalf("the code is not escaped one to one: %q", code)
	}

	// The same for the code of a service error.
	short := (&kms.APIError{Code: strings.Repeat("c", 120)}).Error()
	long := (&kms.APIError{Code: strings.Repeat("c", 121)}).Error()
	if !strings.HasSuffix(short, strings.Repeat("c", 120)) {
		t.Fatalf("a code of 120 characters: %q", short)
	}
	if !strings.HasSuffix(long, strings.Repeat("c", 120)+"...") {
		t.Fatalf("a code of 121 characters: %q", long)
	}
}

// Each refusal names its own rule, so that a person reading it knows which one failed.
func TestEachDescriptionRuleHasItsOwnWords(t *testing.T) {
	seen := map[string]string{}
	rows := map[string]func(d *kms.KeyDescription){
		"arn":     func(d *kms.KeyDescription) { d.ARN += "x" },
		"state":   func(d *kms.KeyDescription) { d.KeyState = "x" },
		"usage":   func(d *kms.KeyDescription) { d.KeyUsage = "x" },
		"spec":    func(d *kms.KeyDescription) { d.KeySpec = "x" },
		"origin":  func(d *kms.KeyDescription) { d.Origin = "x" },
		"manager": func(d *kms.KeyDescription) { d.KeyManager = "x" },
	}
	for name, change := range rows {
		api := newFake(t)
		change(api.desc)
		_, err := read(t, api)
		var r *kms.Refusal
		if !errors.As(err, &r) {
			t.Fatal(err)
		}
		if other, ok := seen[r.Detail]; ok {
			t.Fatalf("%s and %s give the same words: %q", name, other, r.Detail)
		}
		seen[r.Detail] = name
	}
}

// mapConnector and funcAPI are types whose nil value is a nil map or a nil function, which an interface holds
// as something that is not nil.
type mapConnector map[string]kms.API

func (m mapConnector) Open(context.Context, string) (kms.API, error) { return m["x"], nil }

type funcAPI func()

func (funcAPI) DescribeKey(context.Context, string) (*kms.KeyDescription, error) {
	return nil, errors.New("not called")
}

func (funcAPI) GetPublicKey(context.Context, string) (*kms.PublicKeyAnswer, error) {
	return nil, errors.New("not called")
}

func (funcAPI) GetKeyPolicy(context.Context, string, string) (string, error) {
	return "", errors.New("not called")
}

type sliceAPI []string

func (sliceAPI) DescribeKey(context.Context, string) (*kms.KeyDescription, error) {
	return nil, errors.New("not called")
}

func (sliceAPI) GetPublicKey(context.Context, string) (*kms.PublicKeyAnswer, error) {
	return nil, errors.New("not called")
}

func (sliceAPI) GetKeyPolicy(context.Context, string, string) (string, error) {
	return "", errors.New("not called")
}

// A nil value of any kind that an interface can hold is a missing connector or API, and is refused.
func TestNilsOfEveryKindAreMissing(t *testing.T) {
	var nilMap mapConnector
	if _, err := kms.New(kms.Config{Connector: nilMap}); !errors.Is(err, kms.ErrConfig) {
		t.Fatalf("a nil map connector: %v", err)
	}
	// The twin: a map that is not nil is a connector.
	if _, err := kms.New(kms.Config{Connector: mapConnector{}}); err != nil {
		t.Fatalf("a connector of an empty map: %v", err)
	}
	var nilFunc funcAPI
	if _, err := kms.Read(t.Context(), nilFunc, mustKeyARN(t, keyARN)); !errors.Is(err, kms.ErrConfig) {
		t.Fatalf("a nil function API: %v", err)
	}
	var nilSlice sliceAPI
	if _, err := kms.Read(t.Context(), nilSlice, mustKeyARN(t, keyARN)); !errors.Is(err, kms.ErrConfig) {
		t.Fatalf("a nil slice API: %v", err)
	}
	// The twin: an API of the same kinds that is not nil is read (and answers with its fault).
	_, err := kms.Read(t.Context(), funcAPI(func() {}), mustKeyARN(t, keyARN))
	wantUndecided(t, err)
	_, err = kms.Read(t.Context(), sliceAPI{}, mustKeyARN(t, keyARN))
	wantUndecided(t, err)

	// A connector that answers a nil map or a nil function as the API.
	var apiOfNilFunc kms.API = nilFunc
	v := newVerifier(t, &fakeConnector{api: apiOfNilFunc}, nil)
	_, err = v.Verify(t.Context(), nil, proofFor(t, keyARN, someDER(t)), testNow)
	wantUndecided(t, err)
}

// An error that is a nil *APIError inside an error interface is not a service answer, and is no panic.
func TestANilAPIErrorInsideAnErrorIsUndecided(t *testing.T) {
	var nilErr *kms.APIError
	for _, call := range []string{"DescribeKey", "GetPublicKey", "GetKeyPolicy"} {
		api := newFake(t)
		failingCall(api, call, nilErr)
		_, err := read(t, api)
		wantUndecided(t, err)
	}
	v, conn, _, proof := goodVerifier(t)
	conn.err = nilErr
	ev, err := v.Verify(t.Context(), nil, proof, testNow)
	if ev != nil {
		t.Fatal("evidence")
	}
	wantUndecided(t, err)
}

// No bytes at all is a refusal with the words of the limit, and bytes that do not parse have other words.
func TestNoKeyBytesHaveTheirOwnWords(t *testing.T) {
	var words []string
	for _, der := range [][]byte{nil, {}, []byte("not a key")} {
		api := newFake(t)
		api.pub.PublicKey = der
		_, err := read(t, api)
		var r *kms.Refusal
		if !errors.As(err, &r) || r.Fault != kms.FaultKey {
			t.Fatalf("error %v", err)
		}
		words = append(words, r.Detail)
	}
	if words[0] != words[1] || words[0] == words[2] {
		t.Fatalf("words %q", words)
	}
}
