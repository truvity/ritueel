package kms_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/handoff"
	"ritueel.id/ritueel/internal/handoff/evidence/kms"
)

// goodVerifier is a Verifier over a connector that answers with a good key, and the proof for that key.
func goodVerifier(t testing.TB) (*kms.Verifier, *fakeConnector, *fakeAPI, *handoff.Proof) {
	t.Helper()
	api := newFake(t)
	conn := &fakeConnector{api: api}
	return newVerifier(t, conn, nil), conn, api, proofFor(t, keyARN, api.pub.PublicKey)
}

func TestVerifyOfAGoodKey(t *testing.T) {
	v, conn, api, proof := goodVerifier(t)
	ev, err := v.Verify(t.Context(), nil, proof, testNow)
	if err != nil {
		t.Fatal(err)
	}
	want, err := x509.ParsePKIXPublicKey(api.pub.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if ev.Key == nil || !ev.Key.Equal(want) {
		t.Fatal("the key is not the key KMS gave")
	}
	if ev.Unprotected || ev.Firmware != "" || ev.PINPolicy != "" || ev.TouchPolicy != "" {
		t.Fatalf("members that are not for KMS are set: %+v", ev)
	}
	if !reflect.DeepEqual(ev.SignPrincipals, []handoff.Principal{role("example-key-holder")}) {
		t.Fatalf("principals %+v", ev.SignPrincipals)
	}
	if got := api.callLog(); !reflect.DeepEqual(got, []string{"DescribeKey", "GetPublicKey", "GetKeyPolicy"}) {
		t.Fatalf("calls %v", got)
	}
	if !reflect.DeepEqual(conn.roles, []string{""}) {
		t.Fatalf("Open was given %q, want the own credentials", conn.roles)
	}
	pubSum := sha256.Sum256(api.pub.PublicKey)
	polSum := sha256.Sum256([]byte(api.policy))
	wantDetails := map[string]string{
		"key_arn": keyARN, "account": account, "spec": "ECC_NIST_P384", "usage": "SIGN_VERIFY", "origin": "AWS_KMS",
		"manager": "CUSTOMER", "state": "Enabled", "multi_region": "false",
		"public_key_sha256": hex.EncodeToString(pubSum[:]), "policy_sha256": hex.EncodeToString(polSum[:]),
		"checked_at": "2026-11-15T12:00:00Z",
	}
	if !reflect.DeepEqual(ev.Details, wantDetails) {
		t.Fatalf("details %v, want %v", ev.Details, wantDetails)
	}
}

// The members of Details are exactly the set of the constants, and no other.
func TestTheMembersOfDetails(t *testing.T) {
	consts := map[string]string{
		kms.DetailKeyARN: "key_arn", kms.DetailAccount: "account", kms.DetailReadRole: "read_role", kms.DetailSpec: "spec",
		kms.DetailUsage: "usage", kms.DetailOrigin: "origin", kms.DetailManager: "manager", kms.DetailState: "state",
		kms.DetailMultiRegion: "multi_region", kms.DetailPublicKeySHA256: "public_key_sha256",
		kms.DetailPolicySHA256: "policy_sha256", kms.DetailCheckedAt: "checked_at",
	}
	for got, want := range consts {
		if got != want {
			t.Errorf("the constant is %q, want %q", got, want)
		}
	}
	if len(consts) != 12 {
		t.Fatalf("%d names", len(consts))
	}

	// A direct read: eleven members, no read_role.
	v, _, _, proof := goodVerifier(t)
	ev, err := v.Verify(t.Context(), nil, proof, testNow)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for k := range ev.Details {
		names = append(names, k)
	}
	sort.Strings(names)
	if len(names) != 11 {
		t.Fatalf("members %v", names)
	}
	if _, ok := ev.Details[kms.DetailReadRole]; ok {
		t.Fatal("read_role for a direct read")
	}

	// A read through a role: twelve, and read_role is the role.
	api := newFake(t)
	conn := &fakeConnector{api: api}
	v = newVerifier(t, conn, map[string]string{account: readRole})
	ev, err = v.Verify(t.Context(), nil, proofFor(t, keyARN, api.pub.PublicKey), testNow)
	if err != nil {
		t.Fatal(err)
	}
	if len(ev.Details) != 12 || ev.Details[kms.DetailReadRole] != readRole {
		t.Fatalf("details %v", ev.Details)
	}
	for k, val := range ev.Details {
		if !printable(val) {
			t.Fatalf("the value of %s holds a character outside printable ASCII: %q", k, val)
		}
	}
}

func TestMultiRegionIsRecordedAsTrueOrFalse(t *testing.T) {
	arn := "arn:aws:kms:eu-west-1:123456789012:key/" + mrk
	for _, multi := range []bool{false, true} {
		api := newFake(t)
		api.desc = goodDescription(arn)
		api.desc.MultiRegion = multi
		api.pub.KeyID = arn
		v := newVerifier(t, &fakeConnector{api: api}, nil)
		ev, err := v.Verify(t.Context(), nil, proofFor(t, arn, api.pub.PublicKey), testNow)
		if err != nil {
			t.Fatal(err)
		}
		if want := fmt.Sprint(multi); ev.Details[kms.DetailMultiRegion] != want {
			t.Fatalf("multi_region is %q, want %q", ev.Details[kms.DetailMultiRegion], want)
		}
	}
}

func TestCheckedAtIsTheClockInUTCToTheSecond(t *testing.T) {
	zone := time.FixedZone("example", 5*3600+1800)
	for name, now := range map[string]time.Time{
		"UTC":                  time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC),
		"a zone":               time.Date(2026, 11, 15, 17, 30, 5, 0, zone),
		"nanoseconds":          time.Date(2026, 11, 15, 12, 0, 59, 999999999, time.UTC),
		"a zone and nanos":     time.Date(2026, 1, 2, 3, 4, 5, 6, zone),
		"midnight at the zone": time.Date(2026, 12, 31, 0, 0, 0, 0, zone),
	} {
		t.Run(name, func(t *testing.T) {
			v, _, _, proof := goodVerifier(t)
			ev, err := v.Verify(t.Context(), nil, proof, now)
			if err != nil {
				t.Fatal(err)
			}
			want := now.UTC().Truncate(time.Second).Format("2006-01-02T15:04:05Z")
			if got := ev.Details[kms.DetailCheckedAt]; got != want {
				t.Fatalf("checked_at %q, want %q", got, want)
			}
		})
	}
}

func TestTheEvidenceSharesNothingWithTheNextRead(t *testing.T) {
	v, _, _, proof := goodVerifier(t)
	first, err := v.Verify(t.Context(), nil, proof, testNow)
	if err != nil {
		t.Fatal(err)
	}
	wantKey, err := x509.ParsePKIXPublicKey(keyDER(t, first.Key))
	if err != nil {
		t.Fatal(err)
	}
	first.Key.X.SetInt64(7) //nolint:staticcheck // the test writes through the key to see that nothing is shared
	first.SignPrincipals[0] = handoff.Principal{ARN: "changed", Kind: handoff.PrincipalWildcard}
	first.Details["state"] = "changed"
	delete(first.Details, "account")
	second, err := v.Verify(t.Context(), nil, proof, testNow)
	if err != nil {
		t.Fatal(err)
	}
	if !second.Key.Equal(wantKey) {
		t.Fatal("the key of the second answer was changed through the first")
	}
	if !reflect.DeepEqual(second.SignPrincipals, []handoff.Principal{role("example-key-holder")}) {
		t.Fatalf("principals %+v", second.SignPrincipals)
	}
	if second.Details["state"] != "Enabled" || second.Details["account"] != account {
		t.Fatalf("details %v", second.Details)
	}
}

// The zero value, a nil pointer, a nil context, a nil proof and a proof of another store are the caller's
// mistakes: an error that wraps ErrConfig, no refusal, no evidence, and no call.
func TestVerifyOfACallThatIsWrong(t *testing.T) {
	conn := &fakeConnector{api: newFake(t)}
	good := newVerifier(t, conn, nil)
	proof := proofFor(t, keyARN, someDER(t))
	other := *proof
	other.Store = handoff.StorePIV
	soft := *proof
	soft.Store = handoff.StoreSoftware
	empty := *proof
	empty.Store = ""

	var nilVerifier *kms.Verifier
	rows := map[string]struct {
		v *kms.Verifier
		//nolint:containedctx // the context is the case under test
		ctx context.Context
		p   *handoff.Proof
	}{
		"a zero Verifier":     {&kms.Verifier{}, t.Context(), proof},
		"a nil Verifier":      {nilVerifier, t.Context(), proof},
		"a nil context":       {good, nil, proof},
		"a nil proof":         {good, t.Context(), nil},
		"a proof of piv":      {good, t.Context(), &other},
		"a proof of software": {good, t.Context(), &soft},
		"a proof of no store": {good, t.Context(), &empty},
	}
	for name, tc := range rows {
		t.Run(name, func(t *testing.T) {
			ev, err := tc.v.Verify(tc.ctx, nil, tc.p, testNow) //nolint:staticcheck // a nil context is the case under test
			if ev != nil {
				t.Fatalf("evidence beside an error: %+v", ev)
			}
			if !errors.Is(err, kms.ErrConfig) {
				t.Fatalf("error %v, want one that wraps ErrConfig", err)
			}
			var ce *handoff.CodeError
			if errors.As(err, &ce) {
				t.Fatalf("a mistake of the caller is a refusal: %v", err)
			}
			if errors.Is(err, kms.ErrUndecided) {
				t.Fatalf("a mistake of the caller is undecided: %v", err)
			}
		})
	}
	if conn.opens() != 0 {
		t.Fatalf("Open was called %d times", conn.opens())
	}
	// The twin: the same proof is read by the good verifier.
	if _, err := good.Verify(t.Context(), nil, proof, testNow); err != nil {
		t.Fatalf("the twin is refused: %v", err)
	}
}

func TestVerifyDoesNotReadTheRequest(t *testing.T) {
	v, _, _, proof := goodVerifier(t)
	for _, r := range []*handoff.Request{nil, {}, {Stem: "x", Files: map[string][]byte{"proof.json": []byte("not read")}}} {
		if _, err := v.Verify(t.Context(), r, proof, testNow); err != nil {
			t.Fatalf("a request %+v: %v", r, err)
		}
	}
}

func TestNew(t *testing.T) {
	conn := &fakeConnector{api: newFake(t)}
	const other = "arn:aws:iam::111122223333:role/example-certifier-read"
	var nilConn *fakeConnector
	var nilFunc kms.Connector = (*fakeConnector)(nil)
	bad := map[string]kms.Config{
		"no connector":                         {},
		"a connector that holds a nil pointer": {Connector: nilConn},
		"a typed nil connector":                {Connector: nilFunc},
		"a negative timeout":                   {Connector: conn, Timeout: -1},
		"a very negative timeout":              {Connector: conn, Timeout: -time.Hour},
		"a key of 11 digits":                   {Connector: conn, ReadRoles: map[string]string{"12345678901": readRole}},
		"a key of 13 digits":                   {Connector: conn, ReadRoles: map[string]string{"1234567890123": readRole}},
		"a key that is not digits":             {Connector: conn, ReadRoles: map[string]string{"12345678901a": readRole}},
		"an empty account":                     {Connector: conn, ReadRoles: map[string]string{"": readRole}},
		"a role of another account":            {Connector: conn, ReadRoles: map[string]string{account: other}},
		"a non-role ARN":                       {Connector: conn, ReadRoles: map[string]string{account: "arn:aws:iam::123456789012:user/example"}},
		"the account root":                     {Connector: conn, ReadRoles: map[string]string{account: "arn:aws:iam::123456789012:root"}},
		"a key ARN":                            {Connector: conn, ReadRoles: map[string]string{account: keyARN}},
		"an empty role":                        {Connector: conn, ReadRoles: map[string]string{account: ""}},
		"a role with a space":                  {Connector: conn, ReadRoles: map[string]string{account: "arn:aws:iam::123456789012:role/a b"}},
		"one good entry and one bad":           {Connector: conn, ReadRoles: map[string]string{account: readRole, "111122223333": readRole}},
		"a good entry and an empty one":        {Connector: conn, ReadRoles: map[string]string{account: readRole, "111122223333": ""}},
	}
	for name, cfg := range bad {
		t.Run("refuses "+name, func(t *testing.T) {
			v, err := kms.New(cfg)
			if !errors.Is(err, kms.ErrConfig) {
				t.Fatalf("error %v, want ErrConfig", err)
			}
			if v != nil {
				t.Fatal("a Verifier beside an error")
			}
			if !printable(err.Error()) {
				t.Fatalf("the error is not printable ASCII: %q", err.Error())
			}
		})
	}
	good := map[string]kms.Config{
		"a connector only":     {Connector: conn},
		"a nil role map":       {Connector: conn, ReadRoles: nil},
		"an empty role map":    {Connector: conn, ReadRoles: map[string]string{}},
		"one role":             {Connector: conn, ReadRoles: map[string]string{account: readRole}},
		"two roles":            {Connector: conn, ReadRoles: map[string]string{account: readRole, "111122223333": other}},
		"a timeout":            {Connector: conn, Timeout: time.Second},
		"the smallest timeout": {Connector: conn, Timeout: 1},
	}
	for name, cfg := range good {
		t.Run("accepts "+name, func(t *testing.T) {
			v, err := kms.New(cfg)
			if err != nil || v == nil {
				t.Fatalf("refused: %v", err)
			}
		})
	}
}

func TestNewCopiesTheRoleMap(t *testing.T) {
	api := newFake(t)
	conn := &fakeConnector{api: api}
	roles := map[string]string{account: readRole}
	v := newVerifier(t, conn, roles)
	roles[account] = "arn:aws:iam::123456789012:role/changed"
	delete(roles, account)
	roles["444455556666"] = "arn:aws:iam::444455556666:role/added"
	if _, err := v.Verify(t.Context(), nil, proofFor(t, keyARN, api.pub.PublicKey), testNow); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(conn.roles, []string{readRole}) {
		t.Fatalf("Open was given %q, want the role of the map as it was when New read it", conn.roles)
	}
}

func TestTheRoleComesFromTheListByTheAccountOfTheKey(t *testing.T) {
	const otherAccount = "111122223333"
	const otherRole = "arn:aws:iam::111122223333:role/example-certifier-read"
	const otherKey = "arn:aws:kms:eu-west-1:111122223333:key/66666666-7777-8888-9999-000000000000"
	roles := map[string]string{otherAccount: otherRole}

	rows := []struct {
		name  string
		roles map[string]string
		arn   string
		want  string
	}{
		{"an account that is listed", roles, otherKey, otherRole},
		{"an account that is not listed", roles, keyARN, ""},
		{"a nil map", nil, otherKey, ""},
		{"an empty map", map[string]string{}, otherKey, ""},
		{"both accounts listed, the first", map[string]string{account: readRole, otherAccount: otherRole}, keyARN, readRole},
		{"both accounts listed, the second", map[string]string{account: readRole, otherAccount: otherRole}, otherKey, otherRole},
	}
	for _, tc := range rows {
		t.Run(tc.name, func(t *testing.T) {
			api := newFake(t)
			api.desc = goodDescription(tc.arn)
			api.pub.KeyID = tc.arn
			conn := &fakeConnector{api: api}
			v := newVerifier(t, conn, tc.roles)
			ev, err := v.Verify(t.Context(), nil, proofFor(t, tc.arn, api.pub.PublicKey), testNow)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(conn.roles, []string{tc.want}) {
				t.Fatalf("Open was given %q, want %q", conn.roles, tc.want)
			}
			if got, ok := ev.Details[kms.DetailReadRole]; tc.want == "" && ok || got != tc.want {
				t.Fatalf("read_role is %q (present %v), want %q", got, ok, tc.want)
			}
		})
	}
}

// The proof has no member that can name a role, and one that tries is refused before any call.
func TestAProofThatNamesARoleIsMalformedAndMakesNoCall(t *testing.T) {
	api := newFake(t)
	conn := &fakeConnector{api: api}
	v := newVerifier(t, conn, map[string]string{account: readRole})
	der := base64.StdEncoding.EncodeToString(api.pub.PublicKey)
	for _, member := range []string{"role_arn", "role", "read_role", "assume_role", "region", "account", "key_id", "policy", "description"} {
		raw := fmt.Sprintf(`{"key_arn":%q,"public_key":%q,%q:"arn:aws:iam::123456789012:role/attacker"}`, keyARN, der, member)
		_, err := v.Verify(t.Context(), nil, proofRaw(raw), testNow)
		_ = wantCode(t, err, handoff.CodeMalformed)
	}
	if conn.opens() != 0 {
		t.Fatalf("Open was called %d times", conn.opens())
	}
	// The twin: without the member the proof is read.
	raw := fmt.Sprintf(`{"key_arn":%q,"public_key":%q}`, keyARN, der)
	if _, err := v.Verify(t.Context(), nil, proofRaw(raw), testNow); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyOfEvidenceThatIsMalformed(t *testing.T) {
	api := newFake(t)
	conn := &fakeConnector{api: api}
	v := newVerifier(t, conn, nil)
	der := api.pub.PublicKey
	good := base64.StdEncoding.EncodeToString(der)
	q := func(s string) string { return `"` + s + `"` }
	// A key of 120 bytes has no padding; 100 bytes of anything do, and the padding is the point of its row.
	padded := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{'a'}, 100))
	if !strings.HasSuffix(padded, "=") {
		t.Fatal("the padded text has no padding")
	}
	rows := map[string]string{
		"nothing":                         "",
		"not JSON":                        "x",
		"a list":                          "[]",
		"null":                            "null",
		"a string":                        q(good),
		"an empty object":                 "{}",
		"no key_arn":                      `{"public_key":` + q(good) + `}`,
		"no public_key":                   `{"key_arn":` + q(keyARN) + `}`,
		"key_arn as a number":             `{"key_arn":7,"public_key":` + q(good) + `}`,
		"key_arn as a list":               `{"key_arn":[` + q(keyARN) + `],"public_key":` + q(good) + `}`,
		"public_key as a number":          `{"key_arn":` + q(keyARN) + `,"public_key":7}`,
		"public_key as a list":            `{"key_arn":` + q(keyARN) + `,"public_key":[` + q(good) + `]}`,
		"key_arn null":                    `{"key_arn":null,"public_key":` + q(good) + `}`,
		"public_key null":                 `{"key_arn":` + q(keyARN) + `,"public_key":null}`,
		"an unknown member":               `{"key_arn":` + q(keyARN) + `,"public_key":` + q(good) + `,"extra":1}`,
		"key_arn twice":                   `{"key_arn":` + q(keyARN) + `,"key_arn":` + q(keyARN) + `,"public_key":` + q(good) + `}`,
		"public_key twice":                `{"key_arn":` + q(keyARN) + `,"public_key":` + q(good) + `,"public_key":` + q(good) + `}`,
		"a member in another case":        `{"Key_arn":` + q(keyARN) + `,"public_key":` + q(good) + `}`,
		"a trailing object":               `{"key_arn":` + q(keyARN) + `,"public_key":` + q(good) + `}{}`,
		"public_key empty":                `{"key_arn":` + q(keyARN) + `,"public_key":""}`,
		"public_key not Base64":           `{"key_arn":` + q(keyARN) + `,"public_key":"!!!"}`,
		"public_key without padding":      `{"key_arn":` + q(keyARN) + `,"public_key":` + q(strings.TrimRight(padded, "=")) + `}`,
		"public_key in URL spelling":      `{"key_arn":` + q(keyARN) + `,"public_key":` + q(strings.NewReplacer("+", "-", "/", "_").Replace(good)) + `}`,
		"public_key with a newline":       `{"key_arn":` + q(keyARN) + `,"public_key":` + q(good[:20]+`\n`+good[20:]) + `}`,
		"public_key with a space":         `{"key_arn":` + q(keyARN) + `,"public_key":` + q(good[:20]+" "+good[20:]) + `}`,
		"public_key with trailing text":   `{"key_arn":` + q(keyARN) + `,"public_key":` + q(good+"A") + `}`,
		"public_key not in one spelling":  `{"key_arn":` + q(keyARN) + `,"public_key":"QR=="}`,
		"public_key of a PEM":             `{"key_arn":` + q(keyARN) + `,"public_key":"-----BEGIN PUBLIC KEY-----"}`,
		"key_arn an alias":                `{"key_arn":"alias/example","public_key":` + q(good) + `}`,
		"key_arn a bare id":               `{"key_arn":` + q(uuid) + `,"public_key":` + q(good) + `}`,
		"key_arn empty":                   `{"key_arn":"","public_key":` + q(good) + `}`,
		"key_arn in upper case":           `{"key_arn":` + q(strings.ToUpper(keyARN)) + `,"public_key":` + q(good) + `}`,
		"key_arn with a trailing space":   `{"key_arn":` + q(keyARN+" ") + `,"public_key":` + q(good) + `}`,
		"key_arn with a trailing newline": `{"key_arn":` + q(keyARN+`\n`) + `,"public_key":` + q(good) + `}`,
		"key_arn of a role":               `{"key_arn":` + q(holder) + `,"public_key":` + q(good) + `}`,
		"key_arn with a float beside":     `{"key_arn":` + q(keyARN) + `,"public_key":` + q(good) + `,"x":1.5}`,
	}
	for name, raw := range rows {
		t.Run(name, func(t *testing.T) {
			ev, err := v.Verify(t.Context(), nil, proofRaw(raw), testNow)
			if ev != nil {
				t.Fatalf("evidence beside an error: %+v", ev)
			}
			ce := wantCode(t, err, handoff.CodeMalformed)
			if !printable(ce.Detail) || ce.Detail == "" {
				t.Fatalf("the detail is %q", ce.Detail)
			}
			if strings.Contains(ce.Detail, "alias/example") || strings.Contains(ce.Detail, good[:30]) {
				t.Fatalf("the detail repeats the input: %q", ce.Detail)
			}
		})
	}
	if conn.opens() != 0 {
		t.Fatalf("Open was called %d times for evidence that is malformed", conn.opens())
	}
	// The twin: the one good spelling.
	if _, err := v.Verify(t.Context(), nil, proofRaw(`{"key_arn":`+q(keyARN)+`,"public_key":`+q(good)+`}`), testNow); err != nil {
		t.Fatalf("the twin is refused: %v", err)
	}
	// An empty Evidence and a nil Evidence.
	for _, e := range [][]byte{nil, {}} {
		_, err := v.Verify(t.Context(), nil, &handoff.Proof{Store: handoff.StoreKMS, Evidence: e}, testNow)
		_ = wantCode(t, err, handoff.CodeMalformed)
	}
}

func TestEvidenceOverTheSizeLimitIsMalformed(t *testing.T) {
	v, conn, api, _ := goodVerifier(t)
	good := base64.StdEncoding.EncodeToString(api.pub.PublicKey)
	// A key_arn of MaxFileSize bytes: the object is over the limit and is refused unread.
	raw := `{"key_arn":"` + strings.Repeat("a", handoff.MaxFileSize) + `","public_key":"` + good + `"}`
	_, err := v.Verify(t.Context(), nil, proofRaw(raw), testNow)
	_ = wantCode(t, err, handoff.CodeMalformed)
	// A public key of 300 KiB.
	raw = `{"key_arn":"` + keyARN + `","public_key":"` + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 300<<10)) + `"}`
	_, err = v.Verify(t.Context(), nil, proofRaw(raw), testNow)
	_ = wantCode(t, err, handoff.CodeMalformed)
	if conn.opens() != 0 {
		t.Fatalf("Open was called %d times", conn.opens())
	}
}

// A public_key in the proof that is valid Base64 of anything is not compared with the key KMS gave: that is
// check 8's, and a verifier that refused here would give the wrong code.
func TestTheProofsPublicKeyIsNotComparedWithTheKeyOfKMS(t *testing.T) {
	v, _, api, _ := goodVerifier(t)
	for name, der := range map[string][]byte{
		"another P-384 key": someDER(t), "bytes that are not a key": []byte("not a key"), "one byte": {0},
	} {
		t.Run(name, func(t *testing.T) {
			ev, err := v.Verify(t.Context(), nil, proofFor(t, keyARN, der), testNow)
			if err != nil {
				t.Fatal(err)
			}
			want, _ := x509.ParsePKIXPublicKey(api.pub.PublicKey)
			if !ev.Key.Equal(want) {
				t.Fatal("the key is not the key of KMS")
			}
		})
	}
}

func TestAKeyThatIsRefusedIsProofInvalid(t *testing.T) {
	rows := map[string]func(a *fakeAPI){
		"a disabled key":               func(a *fakeAPI) { a.desc.KeyState = "Disabled" },
		"a key in P-256":               func(a *fakeAPI) { a.desc.KeySpec = "ECC_NIST_P256" },
		"another usage":                func(a *fakeAPI) { a.desc.KeyUsage = "ENCRYPT_DECRYPT" },
		"an external key":              func(a *fakeAPI) { a.desc.Origin = "EXTERNAL" },
		"an AWS managed key":           func(a *fakeAPI) { a.desc.KeyManager = "AWS" },
		"another ARN":                  func(a *fakeAPI) { a.desc.ARN = strings.ToUpper(a.desc.ARN) },
		"a public key of P-256":        func(a *fakeAPI) { a.pub.KeySpec = "ECC_NIST_P256" },
		"a policy that is not JSON":    func(a *fakeAPI) { a.policy = "{" },
		"a public key that is garbage": func(a *fakeAPI) { a.pub.PublicKey = []byte("x") },
	}
	for name, change := range rows {
		t.Run(name, func(t *testing.T) {
			v, _, api, proof := goodVerifier(t)
			change(api)
			ev, err := v.Verify(t.Context(), nil, proof, testNow)
			if ev != nil {
				t.Fatalf("evidence beside an error: %+v", ev)
			}
			ce := wantCode(t, err, handoff.CodeProofInvalid)
			if ce.Detail == "" || !printable(ce.Detail) {
				t.Fatalf("detail %q", ce.Detail)
			}
		})
	}
}

// Every code of the service that refuses gives proof-invalid, from Open and from each of the three calls, and
// every other error is undecided and never a refusal.
func TestVerifyOfServiceErrors(t *testing.T) {
	places := []string{"Open", "DescribeKey", "GetPublicKey", "GetKeyPolicy"}
	setup := func(t testing.TB, place string, err error) (*kms.Verifier, *fakeConnector, *fakeAPI, *handoff.Proof) {
		v, conn, api, proof := goodVerifier(t)
		if place == "Open" {
			conn.err = err
		} else {
			failingCall(api, place, err)
		}
		return v, conn, api, proof
	}
	for _, place := range places {
		for code := range refusingCodes {
			t.Run(place+" "+code, func(t *testing.T) {
				v, _, _, proof := setup(t, place, &kms.APIError{Code: code})
				ev, err := v.Verify(t.Context(), nil, proof, testNow)
				if ev != nil {
					t.Fatalf("evidence beside an error: %+v", ev)
				}
				ce := wantCode(t, err, handoff.CodeProofInvalid)
				if !printable(ce.Detail) {
					t.Fatalf("detail %q", ce.Detail)
				}
			})
		}
		for _, code := range undecidedCodes {
			t.Run(place+" undecided "+code, func(t *testing.T) {
				v, _, _, proof := setup(t, place, &kms.APIError{Code: code})
				ev, err := v.Verify(t.Context(), nil, proof, testNow)
				if ev != nil {
					t.Fatalf("evidence beside an error: %+v", ev)
				}
				wantUndecided(t, err)
			})
		}
		for name, e := range map[string]error{
			"a plain error": errors.New("connection reset"), "Canceled": context.Canceled, "DeadlineExceeded": context.DeadlineExceeded,
			"a code error": &handoff.CodeError{Code: handoff.CodeProofInvalid, Detail: "x"},
			"a refusal":    &kms.Refusal{Fault: kms.FaultAccess, Detail: "x"},
		} {
			t.Run(place+" "+name, func(t *testing.T) {
				v, _, _, proof := setup(t, place, e)
				ev, err := v.Verify(t.Context(), nil, proof, testNow)
				if ev != nil {
					t.Fatalf("evidence beside an error: %+v", ev)
				}
				wantUndecided(t, err)
			})
		}
	}
	// The words of an Open that is refused are the fixed words of the page.
	v, _, _, proof := setup(t, "Open", &kms.APIError{Code: "AccessDenied"})
	_, err := v.Verify(t.Context(), nil, proof, testNow)
	if ce := wantCode(t, err, handoff.CodeProofInvalid); ce.Detail != "the key cannot be read" {
		t.Fatalf("detail %q", ce.Detail)
	}
}

func TestAConnectorOrAPIThatAnswersNothingIsUndecided(t *testing.T) {
	t.Run("Open gives a nil API", func(t *testing.T) {
		v, conn, _, proof := goodVerifier(t)
		conn.api = nil
		ev, err := v.Verify(t.Context(), nil, proof, testNow)
		if ev != nil {
			t.Fatal("evidence")
		}
		wantUndecided(t, err)
	})
	t.Run("Open gives an API that holds a nil pointer", func(t *testing.T) {
		v, conn, _, proof := goodVerifier(t)
		var api *fakeAPI
		conn.api = api
		_, err := v.Verify(t.Context(), nil, proof, testNow)
		wantUndecided(t, err)
	})
	t.Run("every method answers nothing", func(t *testing.T) {
		v, conn, _, proof := goodVerifier(t)
		conn.api = &fakeAPI{}
		ev, err := v.Verify(t.Context(), nil, proof, testNow)
		if ev != nil {
			t.Fatal("evidence")
		}
		wantUndecided(t, err)
	})
	t.Run("an empty policy", func(t *testing.T) {
		v, _, api, proof := goodVerifier(t)
		api.policy = ""
		ev, err := v.Verify(t.Context(), nil, proof, testNow)
		if ev != nil {
			t.Fatal("evidence")
		}
		_ = wantCode(t, err, handoff.CodeProofInvalid)
	})
	t.Run("a description with nothing in it", func(t *testing.T) {
		v, _, api, proof := goodVerifier(t)
		api.desc = &kms.KeyDescription{}
		_, err := v.Verify(t.Context(), nil, proof, testNow)
		_ = wantCode(t, err, handoff.CodeProofInvalid)
	})
	t.Run("a public key answer with nothing in it", func(t *testing.T) {
		v, _, api, proof := goodVerifier(t)
		api.pub = &kms.PublicKeyAnswer{}
		_, err := v.Verify(t.Context(), nil, proof, testNow)
		_ = wantCode(t, err, handoff.CodeProofInvalid)
	})
}

func TestEveryRefusalStopsTheReadAtItsCall(t *testing.T) {
	rows := []struct {
		name   string
		break_ func(a *fakeAPI)
		calls  []string
	}{
		{"the description", func(a *fakeAPI) { a.desc.KeyState = "Disabled" }, []string{"DescribeKey"}},
		{"the public key", func(a *fakeAPI) { a.pub.PublicKey = []byte("x") }, []string{"DescribeKey", "GetPublicKey"}},
		{"the policy", func(a *fakeAPI) { a.policy = "x" }, []string{"DescribeKey", "GetPublicKey", "GetKeyPolicy"}},
		{"a denied DescribeKey", func(a *fakeAPI) { failingCall(a, "DescribeKey", &kms.APIError{Code: "AccessDeniedException"}) }, []string{"DescribeKey"}},
		{"a denied GetPublicKey", func(a *fakeAPI) { failingCall(a, "GetPublicKey", &kms.APIError{Code: "AccessDeniedException"}) }, []string{"DescribeKey", "GetPublicKey"}},
	}
	for _, tc := range rows {
		t.Run(tc.name, func(t *testing.T) {
			v, _, api, proof := goodVerifier(t)
			tc.break_(api)
			if _, err := v.Verify(t.Context(), nil, proof, testNow); err == nil {
				t.Fatal("accepted")
			}
			if got := api.callLog(); !reflect.DeepEqual(got, tc.calls) {
				t.Fatalf("calls %v, want %v", got, tc.calls)
			}
		})
	}
}

// The deadline that the connector sees is the earlier of the caller's and the Timeout from the start.
func TestTheDeadlineOfTheConnector(t *testing.T) {
	newV := func(timeout time.Duration) (*kms.Verifier, *fakeConnector, *handoff.Proof) {
		api := newFake(t)
		conn := &fakeConnector{api: api}
		v, err := kms.New(kms.Config{Connector: conn, Timeout: timeout})
		if err != nil {
			t.Fatal(err)
		}
		return v, conn, proofFor(t, keyARN, api.pub.PublicKey)
	}
	between := func(t *testing.T, got, lo, hi time.Time) {
		t.Helper()
		if got.Before(lo) || got.After(hi) {
			t.Fatalf("deadline %s is not between %s and %s", got, lo, hi)
		}
	}
	t.Run("the default timeout", func(t *testing.T) {
		v, conn, proof := newV(0)
		before := time.Now()
		if _, err := v.Verify(t.Context(), nil, proof, testNow); err != nil {
			t.Fatal(err)
		}
		after := time.Now()
		if !conn.hasDL[0] {
			t.Fatal("the context has no deadline")
		}
		between(t, conn.deadlines[0], before.Add(kms.DefaultTimeout), after.Add(kms.DefaultTimeout))
		if kms.DefaultTimeout != 30*time.Second {
			t.Fatalf("DefaultTimeout is %s", kms.DefaultTimeout)
		}
	})
	t.Run("a timeout of the verifier", func(t *testing.T) {
		v, conn, proof := newV(5 * time.Minute)
		before := time.Now()
		if _, err := v.Verify(t.Context(), nil, proof, testNow); err != nil {
			t.Fatal(err)
		}
		after := time.Now()
		between(t, conn.deadlines[0], before.Add(5*time.Minute), after.Add(5*time.Minute))
	})
	t.Run("an earlier deadline of the caller wins", func(t *testing.T) {
		v, conn, proof := newV(5 * time.Minute)
		own := time.Now().Add(time.Minute)
		ctx, cancel := context.WithDeadline(t.Context(), own)
		defer cancel()
		if _, err := v.Verify(ctx, nil, proof, testNow); err != nil {
			t.Fatal(err)
		}
		if !conn.deadlines[0].Equal(own) {
			t.Fatalf("deadline %s, want the caller's %s", conn.deadlines[0], own)
		}
	})
	t.Run("a later deadline of the caller does not extend the timeout", func(t *testing.T) {
		v, conn, proof := newV(time.Minute)
		ctx, cancel := context.WithDeadline(t.Context(), time.Now().Add(time.Hour))
		defer cancel()
		before := time.Now()
		if _, err := v.Verify(ctx, nil, proof, testNow); err != nil {
			t.Fatal(err)
		}
		after := time.Now()
		between(t, conn.deadlines[0], before.Add(time.Minute), after.Add(time.Minute))
	})
	t.Run("the same deadline for every call of one verify", func(t *testing.T) {
		api := newFake(t)
		var seen []time.Time
		api.hook = nil
		conn := &fakeConnector{api: &deadlineAPI{fakeAPI: api, seen: &seen}}
		v := newVerifier(t, conn, nil)
		if _, err := v.Verify(t.Context(), nil, proofFor(t, keyARN, api.pub.PublicKey), testNow); err != nil {
			t.Fatal(err)
		}
		if len(seen) != 3 {
			t.Fatalf("%d calls with a deadline", len(seen))
		}
		for _, d := range seen {
			if !d.Equal(conn.deadlines[0]) {
				t.Fatalf("a call has the deadline %s, Open had %s", d, conn.deadlines[0])
			}
		}
	})
	t.Run("a timeout is not shared between two verifies", func(t *testing.T) {
		v, conn, proof := newV(time.Minute)
		for i := 0; i < 2; i++ {
			if _, err := v.Verify(t.Context(), nil, proof, testNow); err != nil {
				t.Fatal(err)
			}
		}
		if conn.deadlines[1].Before(conn.deadlines[0]) {
			t.Fatal("the second verify has an earlier deadline")
		}
	})
}

// deadlineAPI records the deadline that each call sees.
type deadlineAPI struct {
	*fakeAPI
	seen *[]time.Time
}

func (d *deadlineAPI) DescribeKey(ctx context.Context, arn string) (*kms.KeyDescription, error) {
	dl, _ := ctx.Deadline()
	*d.seen = append(*d.seen, dl)
	return d.fakeAPI.DescribeKey(ctx, arn)
}

func (d *deadlineAPI) GetPublicKey(ctx context.Context, arn string) (*kms.PublicKeyAnswer, error) {
	dl, _ := ctx.Deadline()
	*d.seen = append(*d.seen, dl)
	return d.fakeAPI.GetPublicKey(ctx, arn)
}

func (d *deadlineAPI) GetKeyPolicy(ctx context.Context, arn, name string) (string, error) {
	dl, _ := ctx.Deadline()
	*d.seen = append(*d.seen, dl)
	return d.fakeAPI.GetKeyPolicy(ctx, arn, name)
}

// No sleep and no timer: a context that is already done makes no call at all.
func TestAContextThatIsDoneMakesNoCall(t *testing.T) {
	t.Run("cancelled", func(t *testing.T) {
		v, conn, api, proof := goodVerifier(t)
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		ev, err := v.Verify(ctx, nil, proof, testNow)
		if ev != nil {
			t.Fatal("evidence")
		}
		wantUndecided(t, err)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("the context error is not kept: %v", err)
		}
		if conn.opens() != 0 || len(api.callLog()) != 0 {
			t.Fatalf("opens %d, calls %v", conn.opens(), api.callLog())
		}
	})
	t.Run("past its deadline", func(t *testing.T) {
		v, conn, api, proof := goodVerifier(t)
		ctx, cancel := context.WithDeadline(t.Context(), time.Now().Add(-time.Hour))
		defer cancel()
		_, err := v.Verify(ctx, nil, proof, testNow)
		wantUndecided(t, err)
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("the context error is not kept: %v", err)
		}
		if conn.opens() != 0 || len(api.callLog()) != 0 {
			t.Fatalf("opens %d, calls %v", conn.opens(), api.callLog())
		}
	})
	t.Run("cancelled while Open runs", func(t *testing.T) {
		v, conn, api, proof := goodVerifier(t)
		ctx, cancel := context.WithCancel(t.Context())
		conn.hook = cancel
		ev, err := v.Verify(ctx, nil, proof, testNow)
		if ev != nil {
			t.Fatal("evidence")
		}
		wantUndecided(t, err)
		if len(api.callLog()) != 0 {
			t.Fatalf("calls %v after the context ended", api.callLog())
		}
	})
	t.Run("cancelled while the second call runs", func(t *testing.T) {
		v, _, api, proof := goodVerifier(t)
		ctx, cancel := context.WithCancel(t.Context())
		api.hook = func(call string) {
			if call == "GetPublicKey" {
				cancel()
			}
		}
		ev, err := v.Verify(ctx, nil, proof, testNow)
		if ev != nil {
			t.Fatal("evidence")
		}
		wantUndecided(t, err)
		if got := api.callLog(); !reflect.DeepEqual(got, []string{"DescribeKey", "GetPublicKey"}) {
			t.Fatalf("calls %v", got)
		}
	})
	t.Run("an API that gives the error of the context", func(t *testing.T) {
		v, _, api, proof := goodVerifier(t)
		ctx, cancel := context.WithCancel(t.Context())
		api.hook = func(call string) {
			if call == "DescribeKey" {
				cancel()
			}
		}
		api.descErr = context.Canceled
		api.desc = nil
		_, err := v.Verify(ctx, nil, proof, testNow)
		wantUndecided(t, err)
	})
}

// A refusal Detail never holds the policy, the key, or text of KMS that is not escaped.
func TestARefusalDetailDoesNotLeakHostileText(t *testing.T) {
	const marker = "SECRET-MARKER-77c1"
	hostile := marker + "\x00\n\"\\\xff" + strings.Repeat("q", 600)
	policy := func() string {
		st := stmt(holder, "kms:Sign")
		st["Sid"] = hostile
		st["Unknown"] = hostile
		return policyOf(t, st)
	}()
	// A value that the words name is shown, escaped one to one and cut at 120 characters; everything else is
	// never shown.
	shownEscaped := map[string]bool{"state": true, "usage": true, "spec": true, "origin": true, "manager": true, "key spec": true, "service code": true}
	rows := map[string]func(a *fakeAPI){
		"state":        func(a *fakeAPI) { a.desc.KeyState = hostile },
		"usage":        func(a *fakeAPI) { a.desc.KeyUsage = hostile },
		"spec":         func(a *fakeAPI) { a.desc.KeySpec = hostile },
		"origin":       func(a *fakeAPI) { a.desc.Origin = hostile },
		"manager":      func(a *fakeAPI) { a.desc.KeyManager = hostile },
		"ARN":          func(a *fakeAPI) { a.desc.ARN = hostile },
		"key spec":     func(a *fakeAPI) { a.pub.KeySpec = hostile },
		"key id":       func(a *fakeAPI) { a.pub.KeyID = hostile },
		"key bytes":    func(a *fakeAPI) { a.pub.PublicKey = []byte(hostile) },
		"policy text":  func(a *fakeAPI) { a.policy = policy },
		"policy junk":  func(a *fakeAPI) { a.policy = hostile },
		"policy long":  func(a *fakeAPI) { a.policy = hostile + strings.Repeat("x", kms.MaxPolicyBytes) },
		"service code": func(a *fakeAPI) { failingCall(a, "GetKeyPolicy", &kms.APIError{Code: hostile}) },
	}
	for name, change := range rows {
		t.Run(name, func(t *testing.T) {
			v, _, api, proof := goodVerifier(t)
			change(api)
			_, err := v.Verify(t.Context(), nil, proof, testNow)
			if err == nil {
				t.Fatal("accepted")
			}
			text := err.Error()
			var ce *handoff.CodeError
			if errors.As(err, &ce) {
				text += " " + ce.Detail
			}
			if !shownEscaped[name] && strings.Contains(text, marker) {
				t.Fatalf("the error holds a text from outside: %q", text)
			}
			if !printable(text) {
				t.Fatalf("the error holds a character outside printable ASCII: %q", text)
			}
			if len(text) > 600 {
				t.Fatalf("the error is %d bytes", len(text))
			}
		})
	}
}

// A policy full of text that is not ASCII gives evidence in which nothing is outside printable ASCII.
func TestEvidenceOfAPolicyWithHostileTextIsPrintable(t *testing.T) {
	v, _, api, proof := goodVerifier(t)
	st := stmt([]string{holder, "arn:aws:iam::123456789012:role/ex\xc3\xa4mple", "\xe2\x80\xae", "a\x00b", "a\nb", "\xef\xbf\xbd"}, "kms:Sign")
	st["Sid"] = "\xe2\x80\xae\x00\n"
	api.policy = policyOf(t, st)
	ev, err := v.Verify(t.Context(), nil, proof, testNow)
	if err != nil {
		t.Fatal(err)
	}
	if len(ev.SignPrincipals) != 6 {
		t.Fatalf("principals %+v", ev.SignPrincipals)
	}
	for _, p := range ev.SignPrincipals {
		if !printable(p.ARN) {
			t.Fatalf("principal text %q", p.ARN)
		}
	}
	for k, val := range ev.Details {
		if !printable(val) {
			t.Fatalf("the value of %s: %q", k, val)
		}
	}
	// No two of them read as one.
	seen := map[string]bool{}
	for _, p := range ev.SignPrincipals {
		seen[p.ARN] = true
	}
	if len(seen) != 6 {
		t.Fatalf("%d texts for 6 principals", len(seen))
	}
}

func TestOneVerifierServesEightGoroutinesWithDifferentKeys(t *testing.T) {
	const n = 8
	type one struct {
		account, role, arn string
		api                *fakeAPI
	}
	var list []one
	roles := map[string]string{}
	for i := 0; i < n; i++ {
		acct := fmt.Sprintf("%s%02d", "0000000000", i+1)
		arn := fmt.Sprintf("arn:aws:kms:eu-west-1:%s:key/11111111-2222-3333-4444-%012d", acct, i)
		r := fmt.Sprintf("arn:aws:iam::%s:role/example-certifier-read", acct)
		api := newFake(t)
		api.desc = goodDescription(arn)
		api.pub.KeyID = arn
		api.policy = policyOf(t, stmt(fmt.Sprintf("arn:aws:iam::%s:role/example-holder-%d", acct, i), "kms:Sign"))
		list = append(list, one{acct, r, arn, api})
		roles[acct] = r
	}
	conn := &fakeConnector{apiFor: func(role string) kms.API {
		for _, o := range list {
			if o.role == role {
				return o.api
			}
		}
		return &fakeAPI{descErr: &kms.APIError{Code: "AccessDenied"}}
	}}
	v := newVerifier(t, conn, roles)

	var wg sync.WaitGroup
	errs := make(chan error, n*4)
	for i, o := range list {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for round := 0; round < 4; round++ {
				ev, err := v.Verify(context.Background(), nil, proofFor(t, o.arn, o.api.pub.PublicKey), testNow)
				if err != nil {
					errs <- fmt.Errorf("goroutine %d: %w", i, err)
					return
				}
				want := fmt.Sprintf("arn:aws:iam::%s:role/example-holder-%d", o.account, i)
				if len(ev.SignPrincipals) != 1 || ev.SignPrincipals[0].ARN != want {
					errs <- fmt.Errorf("goroutine %d: principals %+v", i, ev.SignPrincipals)
					return
				}
				if ev.Details[kms.DetailKeyARN] != o.arn || ev.Details[kms.DetailReadRole] != o.role {
					errs <- fmt.Errorf("goroutine %d: details %v", i, ev.Details)
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

func FuzzVerifyEvidence(f *testing.F) {
	key := newKey(f)
	der := keyDER(f, &key.PublicKey)
	good := `{"key_arn":"` + keyARN + `","public_key":"` + base64.StdEncoding.EncodeToString(der) + `"}`
	for _, s := range []string{
		"", "{}", "[]", "null", good, strings.Replace(good, "key_arn", "role_arn", 1), good + good,
		`{"key_arn":"alias/x","public_key":"AA=="}`, `{"key_arn":"` + keyARN + `","public_key":"AA==","x":1.5}`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, evidence []byte) {
		api := &fakeAPI{
			desc:   goodDescription(keyARN),
			pub:    &kms.PublicKeyAnswer{KeyID: keyARN, KeySpec: "ECC_NIST_P384", PublicKey: der},
			policy: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"` + holder + `"},"Action":"kms:Sign"}]}`,
		}
		conn := &fakeConnector{api: api}
		v, err := kms.New(kms.Config{Connector: conn})
		if err != nil {
			t.Fatal(err)
		}
		ev, err := v.Verify(t.Context(), nil, &handoff.Proof{Store: handoff.StoreKMS, Evidence: evidence}, testNow)
		if err != nil {
			if ev != nil {
				t.Fatal("evidence beside an error")
			}
			var ce *handoff.CodeError
			if errors.As(err, &ce) && ce.Code == handoff.CodeMalformed && conn.opens() != 0 {
				t.Fatalf("a call was made for evidence that was refused as malformed: %v", err)
			}
			return
		}
		// Evidence that is accepted names a key ARN of the form of the page, and the verifier asked for that
		// ARN and no other.
		for _, a := range api.arns {
			if _, err := kms.ParseKeyARN(a); err != nil {
				t.Fatalf("a call for %q", a)
			}
		}
		if ev.Key == nil || ev.Details[kms.DetailKeyARN] != keyARN {
			t.Fatalf("evidence %+v", ev)
		}
	})
}
