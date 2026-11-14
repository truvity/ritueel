package kmsreplay_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"

	"ritueel.id/ritueel/internal/handoff/evidence/kms"
	"ritueel.id/ritueel/internal/handoff/evidence/kms/kmsreplay"
	"ritueel.id/ritueel/internal/testrepo"
)

const (
	arn    = "arn:aws:kms:eu-west-1:123456789012:key/11111111-2222-3333-4444-555555555555"
	other  = "arn:aws:kms:eu-west-1:123456789012:key/99999999-2222-3333-4444-555555555555"
	roleA  = "arn:aws:iam::123456789012:role/example-certifier-read"
	roleB  = "arn:aws:iam::123456789012:role/example-other"
	policy = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:role/example-key-holder"},"Action":"kms:Sign"}]}`
)

// stubOf is a stub of the shape of the vectors, as a Go value, so that a test changes one thing at a time.
func stubOf() map[string]any {
	return map[string]any{
		"describe_key": map[string]any{"KeyMetadata": map[string]any{
			"Arn": arn, "KeyId": "11111111-2222-3333-4444-555555555555", "KeySpec": "ECC_NIST_P384", "KeyUsage": "SIGN_VERIFY",
			"KeyState": "Enabled", "Origin": "AWS_KMS", "KeyManager": "CUSTOMER", "MultiRegion": false,
			"SigningAlgorithms": []string{"ECDSA_SHA_384"},
		}},
		"get_public_key": map[string]any{"KeyId": arn, "KeySpec": "ECC_NIST_P384", "PublicKey": base64.StdEncoding.EncodeToString([]byte("der bytes"))},
		"get_key_policy": map[string]any{"PolicyName": "default", "Policy": policy},
	}
}

func withRole(m map[string]any) map[string]any {
	m["assume_role"] = map[string]any{"RoleArn": roleA}
	return m
}

func render(t testing.TB, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mustParse(t testing.TB, data []byte) *kmsreplay.Replay {
	t.Helper()
	r, err := kmsreplay.Parse(data)
	if err != nil {
		t.Fatalf("refused: %v\n%.400s", err, data)
	}
	return r
}

func wantRefused(t testing.TB, data []byte) error {
	t.Helper()
	r, err := kmsreplay.Parse(data)
	if err == nil || r != nil {
		t.Fatalf("accepted: %.400s", data)
	}
	return err
}

func vectorFiles(t testing.TB) []string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(testrepo.Path(t, "testdata", "hand-off", "v1", "requests"), "*.kms-stub.json"))
	if err != nil {
		t.Fatal(err)
	}
	return files
}

func TestParseReadsEveryStubOfTheVectors(t *testing.T) {
	files := vectorFiles(t)
	if len(files) != 9 {
		t.Fatalf("%d stubs in the vectors, want the nine of the manifest", len(files))
	}
	for _, f := range files {
		t.Run(filepath.Base(f), func(t *testing.T) {
			data, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			mustParse(t, data)
		})
	}
}

func TestParseRefusesAStubThatIsNotOfTheShape(t *testing.T) {
	type edit func(m map[string]any)
	set := func(path string, v any) edit {
		return func(m map[string]any) {
			parts := strings.Split(path, ".")
			cur := m
			for _, p := range parts[:len(parts)-1] {
				cur = cur[p].(map[string]any)
			}
			cur[parts[len(parts)-1]] = v
		}
	}
	del := func(path string) edit {
		return func(m map[string]any) {
			parts := strings.Split(path, ".")
			cur := m
			for _, p := range parts[:len(parts)-1] {
				cur = cur[p].(map[string]any)
			}
			delete(cur, parts[len(parts)-1])
		}
	}
	rows := map[string]edit{
		"an unknown top-level member":                         set("extra", 1),
		"a top-level member in another case":                  set("Describe_key", map[string]any{}),
		"no describe_key":                                     del("describe_key"),
		"no get_public_key":                                   del("get_public_key"),
		"no get_key_policy":                                   del("get_key_policy"),
		"describe_key null":                                   set("describe_key", nil),
		"get_public_key null":                                 set("get_public_key", nil),
		"get_key_policy null":                                 set("get_key_policy", nil),
		"describe_key empty":                                  set("describe_key", map[string]any{}),
		"get_public_key empty":                                set("get_public_key", map[string]any{}),
		"get_key_policy empty":                                set("get_key_policy", map[string]any{}),
		"describe_key a string":                               set("describe_key", "x"),
		"describe_key a list":                                 set("describe_key", []any{}),
		"describe_key with a value and error":                 set("describe_key.error", "AccessDeniedException"),
		"get_public_key with a value and error":               set("get_public_key.error", "AccessDeniedException"),
		"get_key_policy with a value and error":               set("get_key_policy.error", "AccessDeniedException"),
		"get_public_key with an error and only PublicKey":     set("get_public_key", map[string]any{"error": "AccessDeniedException", "PublicKey": "AAAA"}),
		"get_public_key with an error and only KeyId":         set("get_public_key", map[string]any{"error": "AccessDeniedException", "KeyId": arn}),
		"get_public_key with an error and only KeySpec":       set("get_public_key", map[string]any{"error": "AccessDeniedException", "KeySpec": "ECC_NIST_P384"}),
		"get_key_policy with an error and only Policy":        set("get_key_policy", map[string]any{"error": "AccessDeniedException", "Policy": policy}),
		"get_key_policy with an error and only PolicyName":    set("get_key_policy", map[string]any{"error": "AccessDeniedException", "PolicyName": "default"}),
		"describe_key with an error and an empty KeyMetadata": set("describe_key", map[string]any{"error": "AccessDeniedException", "KeyMetadata": map[string]any{}}),
		"KeyMetadata with an unknown member":                  set("describe_key.KeyMetadata.Extra", 1),
		"KeyMetadata null":                                    set("describe_key.KeyMetadata", nil),
		"KeyMetadata a list":                                  set("describe_key.KeyMetadata", []any{}),
		"no Arn":                                              del("describe_key.KeyMetadata.Arn"),
		"no KeyId":                                            del("describe_key.KeyMetadata.KeyId"),
		"no KeySpec":                                          del("describe_key.KeyMetadata.KeySpec"),
		"no KeyUsage":                                         del("describe_key.KeyMetadata.KeyUsage"),
		"no KeyState":                                         del("describe_key.KeyMetadata.KeyState"),
		"no Origin":                                           del("describe_key.KeyMetadata.Origin"),
		"no KeyManager":                                       del("describe_key.KeyMetadata.KeyManager"),
		"no MultiRegion":                                      del("describe_key.KeyMetadata.MultiRegion"),
		"no SigningAlgorithms":                                del("describe_key.KeyMetadata.SigningAlgorithms"),
		"Arn a number":                                        set("describe_key.KeyMetadata.Arn", 7),
		"Arn null":                                            set("describe_key.KeyMetadata.Arn", nil),
		"KeyState a list":                                     set("describe_key.KeyMetadata.KeyState", []string{"Enabled"}),
		"MultiRegion a string":                                set("describe_key.KeyMetadata.MultiRegion", "false"),
		"MultiRegion a number":                                set("describe_key.KeyMetadata.MultiRegion", 0),
		"MultiRegion a float":                                 set("describe_key.KeyMetadata.MultiRegion", 0.5),
		"MultiRegion null":                                    set("describe_key.KeyMetadata.MultiRegion", nil),
		"SigningAlgorithms a string":                          set("describe_key.KeyMetadata.SigningAlgorithms", "ECDSA_SHA_384"),
		"SigningAlgorithms null":                              set("describe_key.KeyMetadata.SigningAlgorithms", nil),
		"SigningAlgorithms with a number":                     set("describe_key.KeyMetadata.SigningAlgorithms", []any{1}),
		"no public KeyId":                                     del("get_public_key.KeyId"),
		"no public KeySpec":                                   del("get_public_key.KeySpec"),
		"no PublicKey":                                        del("get_public_key.PublicKey"),
		"PublicKey a list":                                    set("get_public_key.PublicKey", []any{"AAAA"}),
		"PublicKey a list of numbers":                         set("get_public_key.PublicKey", []any{1, 2, 3}),
		"PublicKey a number":                                  set("get_public_key.PublicKey", 7),
		"PublicKey null":                                      set("get_public_key.PublicKey", nil),
		"PublicKey in the URL spelling":                       set("get_public_key.PublicKey", "-_-_"),
		"PublicKey without padding":                           set("get_public_key.PublicKey", "AAA"),
		"PublicKey with a space":                              set("get_public_key.PublicKey", "AA AA"),
		"PublicKey with a newline":                            set("get_public_key.PublicKey", "AAAA\nAAAA"),
		"PublicKey not in one spelling":                       set("get_public_key.PublicKey", "QR=="),
		"public member unknown":                               set("get_public_key.Extra", 1),
		"public KeyId a number":                               set("get_public_key.KeyId", 1),
		"no PolicyName":                                       del("get_key_policy.PolicyName"),
		"no Policy":                                           del("get_key_policy.Policy"),
		"PolicyName not default":                              set("get_key_policy.PolicyName", "other"),
		"PolicyName in upper case":                            set("get_key_policy.PolicyName", "Default"),
		"PolicyName empty":                                    set("get_key_policy.PolicyName", ""),
		"Policy a number":                                     set("get_key_policy.Policy", 1),
		"Policy an object":                                    set("get_key_policy.Policy", map[string]any{}),
		"Policy null":                                         set("get_key_policy.Policy", nil),
		"policy member unknown":                               set("get_key_policy.Extra", 1),
		"the description and the key are for two keys":        set("get_public_key.KeyId", other),
		"the public KeyId is the bare id":                     set("get_public_key.KeyId", "11111111-2222-3333-4444-555555555555"),
		"assume_role null":                                    set("assume_role", nil),
		"assume_role empty":                                   set("assume_role", map[string]any{}),
		"assume_role a string":                                set("assume_role", roleA),
		"assume_role a list":                                  set("assume_role", []any{}),
		"assume_role with another member":                     set("assume_role", map[string]any{"RoleArn": roleA, "ExternalId": "x"}),
		"RoleArn a number":                                    set("assume_role", map[string]any{"RoleArn": 1}),
		"RoleArn null":                                        set("assume_role", map[string]any{"RoleArn": nil}),
		"RoleArn empty":                                       set("assume_role", map[string]any{"RoleArn": ""}),
		"RoleArn a user":                                      set("assume_role", map[string]any{"RoleArn": "arn:aws:iam::123456789012:user/example"}),
		"RoleArn a key":                                       set("assume_role", map[string]any{"RoleArn": arn}),
		"RoleArn with a space":                                set("assume_role", map[string]any{"RoleArn": "arn:aws:iam::123456789012:role/a b"}),
		"RoleArn in another case":                             set("assume_role", map[string]any{"Rolearn": roleA}),
	}
	for name, change := range rows {
		t.Run(name, func(t *testing.T) {
			m := stubOf()
			change(m)
			err := wantRefused(t, render(t, m))
			if !strings.HasPrefix(err.Error(), "kmsreplay:") {
				t.Fatalf("the error is not one of the package: %v", err)
			}
		})
	}
	// The twin of every row: the stub as it is, with and without a role.
	mustParse(t, render(t, stubOf()))
	mustParse(t, render(t, withRole(stubOf())))
}

func TestParseOfErrorAnswers(t *testing.T) {
	allErrors := func(code string) map[string]any {
		return map[string]any{
			"describe_key": map[string]any{"error": code}, "get_public_key": map[string]any{"error": code}, "get_key_policy": map[string]any{"error": code},
		}
	}
	for _, code := range []string{"AccessDeniedException", "a", "A_b.c-d", "NotFoundException", strings.Repeat("a", 128), "0"} {
		mustParse(t, render(t, allErrors(code)))
	}
	for name, code := range map[string]string{
		"empty": "", "129 characters": strings.Repeat("a", 129), "a space": "Access Denied", "a colon": "a:b", "a slash": "a/b",
		"a newline": "a\nb", "non-ASCII": "caf\xc3\xa9", "a NUL": "a\x00", "a quote": `a"b`, "a star": "a*",
	} {
		t.Run("refuses a code with "+name, func(t *testing.T) {
			for _, member := range []string{"describe_key", "get_public_key", "get_key_policy"} {
				m := stubOf()
				m[member] = map[string]any{"error": code}
				_ = wantRefused(t, render(t, m))
			}
		})
	}
	t.Run("an error code that is not a string", func(t *testing.T) {
		for _, v := range []any{1, nil, []string{"x"}, true, map[string]any{}} {
			m := stubOf()
			m["describe_key"] = map[string]any{"error": v}
			_ = wantRefused(t, render(t, m))
		}
	})
	t.Run("mixed value and error answers", func(t *testing.T) {
		m := stubOf()
		m["describe_key"] = map[string]any{"error": "AccessDeniedException"}
		mustParse(t, render(t, m))
		m = stubOf()
		m["get_public_key"] = map[string]any{"error": "KMSInvalidStateException"}
		mustParse(t, render(t, m))
		m = stubOf()
		m["get_key_policy"] = map[string]any{"error": "AccessDeniedException"}
		mustParse(t, render(t, m))
	})
}

func TestParseOfHostileInput(t *testing.T) {
	good := render(t, stubOf())
	rows := map[string][]byte{
		"empty":                   nil,
		"empty slice":             {},
		"white space":             []byte(" \n\t"),
		"not JSON":                []byte("x"),
		"a list":                  []byte("[]"),
		"null":                    []byte("null"),
		"a string":                []byte(`"x"`),
		"a number":                []byte("1"),
		"an empty object":         []byte("{}"),
		"a trailing object":       append(bytes.Clone(good), []byte("{}")...),
		"trailing text":           append(bytes.Clone(good), []byte(" x")...),
		"a byte order mark":       append([]byte{0xef, 0xbb, 0xbf}, good...),
		"a NUL":                   append(bytes.Clone(good), 0),
		"invalid UTF-8":           bytes.Replace(good, []byte("example-key-holder"), []byte("example-\xff-holder"), 1),
		"a repeated describe_key": bytes.Replace(good, []byte(`"get_public_key"`), []byte(`"describe_key":{},"get_public_key"`), 1),
		"a repeated Arn":          bytes.Replace(good, []byte(`"KeyId":"1111`), []byte(`"Arn":"x","KeyId":"1111`), 1),
		"a repeated PolicyName":   bytes.Replace(good, []byte(`"Policy":`), []byte(`"PolicyName":"default","Policy":`), 1),
		"a float":                 bytes.Replace(good, []byte(`"MultiRegion":false`), []byte(`"MultiRegion":false,"X":1.5`), 1),
		"deep nesting":            []byte(`{"describe_key":` + strings.Repeat("[", 20000) + strings.Repeat("]", 20000) + `}`),
	}
	for name, data := range rows {
		t.Run(name, func(t *testing.T) {
			_ = wantRefused(t, data)
		})
	}
	// The twin: the stub itself.
	mustParse(t, good)
}

func TestParseSizeLimit(t *testing.T) {
	m := stubOf()
	base := render(t, m)
	pad := func(n int) []byte { return append(bytes.Clone(base), bytes.Repeat([]byte{' '}, n-len(base))...) }
	mustParse(t, pad(256<<10))
	_ = wantRefused(t, pad(256<<10+1))
	_ = wantRefused(t, pad(1<<20))
	// A policy of 300 KiB inside the stub is over the limit of the file.
	m["get_key_policy"] = map[string]any{"PolicyName": "default", "Policy": strings.Repeat("x", 300<<10)}
	_ = wantRefused(t, render(t, m))
}

// The error of Parse holds fixed words: no byte of the input is repeated.
func TestParseErrorsDoNotRepeatTheInput(t *testing.T) {
	const marker = "SECRET-MARKER-31bd"
	for name, edit := range map[string]func(m map[string]any){
		"an unknown member":       func(m map[string]any) { m[marker] = 1 },
		"an unknown inner member": func(m map[string]any) { m["describe_key"].(map[string]any)["KeyMetadata"].(map[string]any)[marker] = 1 },
		"a bad error code":        func(m map[string]any) { m["describe_key"] = map[string]any{"error": marker + " x"} },
		"a bad role":              func(m map[string]any) { m["assume_role"] = map[string]any{"RoleArn": marker} },
		"a bad policy name":       func(m map[string]any) { m["get_key_policy"].(map[string]any)["PolicyName"] = marker },
		"a key id of another key": func(m map[string]any) { m["get_public_key"].(map[string]any)["KeyId"] = marker },
		"a value and an error":    func(m map[string]any) { m["get_key_policy"].(map[string]any)["error"] = marker },
		"a long error code":       func(m map[string]any) { m["describe_key"] = map[string]any{"error": marker + strings.Repeat("a", 200)} },
	} {
		t.Run(name, func(t *testing.T) {
			m := stubOf()
			edit(m)
			err := wantRefused(t, render(t, m))
			if strings.Contains(err.Error(), marker) {
				t.Fatalf("the error repeats the input: %v", err)
			}
			if len(err.Error()) > 300 {
				t.Fatalf("the error is %d bytes", len(err.Error()))
			}
		})
	}
	data := bytes.Replace(render(t, stubOf()), []byte("kms:Sign"), []byte(marker), 1)
	if _, err := kmsreplay.Parse(append(data, []byte(marker)...)); err == nil || strings.Contains(err.Error(), marker) {
		t.Fatalf("error %v", err)
	}
}

func TestParseCopiesTheInput(t *testing.T) {
	data := render(t, withRole(stubOf()))
	r := mustParse(t, data)
	for i := range data {
		data[i] = 'x'
	}
	api, err := r.Open(t.Context(), roleA)
	if err != nil {
		t.Fatal(err)
	}
	d, err := api.DescribeKey(t.Context(), arn)
	if err != nil || d.ARN != arn || d.KeyState != "Enabled" {
		t.Fatalf("%+v, %v", d, err)
	}
	p, err := api.GetKeyPolicy(t.Context(), arn, "default")
	if err != nil || p != policy {
		t.Fatalf("%q, %v", p, err)
	}
}

func TestTheAnswersOfAStub(t *testing.T) {
	r := mustParse(t, render(t, stubOf()))
	api, err := r.Open(t.Context(), "")
	if err != nil {
		t.Fatal(err)
	}
	d, err := api.DescribeKey(t.Context(), arn)
	if err != nil {
		t.Fatal(err)
	}
	want := &kms.KeyDescription{
		ARN: arn, KeyID: "11111111-2222-3333-4444-555555555555", KeySpec: "ECC_NIST_P384", KeyUsage: "SIGN_VERIFY",
		KeyState: "Enabled", Origin: "AWS_KMS", KeyManager: "CUSTOMER", SigningAlgorithms: []string{"ECDSA_SHA_384"},
	}
	if !reflect.DeepEqual(d, want) {
		t.Fatalf("description %+v, want %+v", d, want)
	}
	pk, err := api.GetPublicKey(t.Context(), arn)
	if err != nil {
		t.Fatal(err)
	}
	if pk.KeyID != arn || pk.KeySpec != "ECC_NIST_P384" || string(pk.PublicKey) != "der bytes" {
		t.Fatalf("public key answer %+v", pk)
	}
	p, err := api.GetKeyPolicy(t.Context(), arn, "default")
	if err != nil || p != policy {
		t.Fatalf("%q, %v", p, err)
	}
	if want := []string{"open:-", "DescribeKey", "GetPublicKey", "GetKeyPolicy:default"}; !reflect.DeepEqual(r.Calls(), want) {
		t.Fatalf("calls %v, want %v", r.Calls(), want)
	}
	// A multi-Region key is a boolean in the file.
	m := stubOf()
	m["describe_key"].(map[string]any)["KeyMetadata"].(map[string]any)["MultiRegion"] = true
	api, _ = mustParse(t, render(t, m)).Open(t.Context(), "")
	if d, _ := api.DescribeKey(t.Context(), arn); !d.MultiRegion {
		t.Fatal("MultiRegion is lost")
	}
}

func TestTheRoleRules(t *testing.T) {
	denied := func(t *testing.T, err error) {
		t.Helper()
		var ae *kms.APIError
		if !errors.As(err, &ae) || ae.Code != "AccessDenied" {
			t.Fatalf("error %v, want an APIError with the code AccessDenied", err)
		}
	}
	t.Run("a stub with a role, the role given", func(t *testing.T) {
		r := mustParse(t, render(t, withRole(stubOf())))
		api, err := r.Open(t.Context(), roleA)
		if err != nil || api == nil {
			t.Fatalf("%v", err)
		}
		if want := []string{"open:" + roleA}; !reflect.DeepEqual(r.Calls(), want) {
			t.Fatalf("calls %v", r.Calls())
		}
	})
	t.Run("a stub with a role, no role given", func(t *testing.T) {
		r := mustParse(t, render(t, withRole(stubOf())))
		api, err := r.Open(t.Context(), "")
		denied(t, err)
		if api != nil {
			t.Fatal("an API beside an error")
		}
		if want := []string{"open:-"}; !reflect.DeepEqual(r.Calls(), want) {
			t.Fatalf("calls %v", r.Calls())
		}
	})
	t.Run("a stub with a role, another role given", func(t *testing.T) {
		r := mustParse(t, render(t, withRole(stubOf())))
		api, err := r.Open(t.Context(), roleB)
		denied(t, err)
		if api != nil {
			t.Fatal("an API beside an error")
		}
		if want := []string{"open:" + roleB}; !reflect.DeepEqual(r.Calls(), want) {
			t.Fatalf("calls %v", r.Calls())
		}
	})
	t.Run("a role that differs in one character", func(t *testing.T) {
		r := mustParse(t, render(t, withRole(stubOf())))
		for _, given := range []string{roleA + "x", strings.ToUpper(roleA), roleA[:len(roleA)-1], " " + roleA} {
			_, err := r.Open(t.Context(), given)
			denied(t, err)
		}
	})
	t.Run("a stub without a role, none given", func(t *testing.T) {
		r := mustParse(t, render(t, stubOf()))
		if api, err := r.Open(t.Context(), ""); err != nil || api == nil {
			t.Fatalf("%v", err)
		}
	})
	t.Run("a stub without a role, a role given", func(t *testing.T) {
		r := mustParse(t, render(t, stubOf()))
		api, err := r.Open(t.Context(), roleA)
		denied(t, err)
		if api != nil {
			t.Fatal("an API beside an error")
		}
		if want := []string{"open:" + roleA}; !reflect.DeepEqual(r.Calls(), want) {
			t.Fatalf("calls %v", r.Calls())
		}
	})
}

func TestACallForAnotherKeyIsNotFound(t *testing.T) {
	notFound := func(t *testing.T, err error) {
		t.Helper()
		var ae *kms.APIError
		if !errors.As(err, &ae) || ae.Code != "NotFoundException" {
			t.Fatalf("error %v, want NotFoundException", err)
		}
	}
	r := mustParse(t, render(t, stubOf()))
	api, _ := r.Open(t.Context(), "")
	for _, k := range []string{other, "", strings.ToUpper(arn), arn + " ", "alias/x", "11111111-2222-3333-4444-555555555555"} {
		d, err := api.DescribeKey(t.Context(), k)
		notFound(t, err)
		if d != nil {
			t.Fatal("an answer beside an error")
		}
		pk, err := api.GetPublicKey(t.Context(), k)
		notFound(t, err)
		if pk != nil {
			t.Fatal("an answer beside an error")
		}
		p, err := api.GetKeyPolicy(t.Context(), k, "default")
		notFound(t, err)
		if p != "" {
			t.Fatal("a policy beside an error")
		}
	}
	// The twin: the key of the file is answered.
	if _, err := api.DescribeKey(t.Context(), arn); err != nil {
		t.Fatal(err)
	}
	// The calls are in the log, also those that were not found.
	if got := r.Calls(); len(got) != 1+3*6+1 {
		t.Fatalf("%d calls in the log: %v", len(got), got)
	}
}

func TestAPolicyNameOtherThanDefaultIsNotFound(t *testing.T) {
	r := mustParse(t, render(t, stubOf()))
	api, _ := r.Open(t.Context(), "")
	for _, name := range []string{"other", "Default", "", "default ", "default\n"} {
		p, err := api.GetKeyPolicy(t.Context(), arn, name)
		var ae *kms.APIError
		if !errors.As(err, &ae) || ae.Code != "NotFoundException" || p != "" {
			t.Fatalf("name %q: %q, %v", name, p, err)
		}
	}
	if p, err := api.GetKeyPolicy(t.Context(), arn, "default"); err != nil || p != policy {
		t.Fatalf("%q, %v", p, err)
	}
	if want := "GetKeyPolicy:other"; r.Calls()[1] != want {
		t.Fatalf("the log holds %q, want %q", r.Calls()[1], want)
	}
}

func TestAnErrorAnswerIsTheErrorOfTheCode(t *testing.T) {
	for _, member := range []string{"describe_key", "get_public_key", "get_key_policy"} {
		t.Run(member, func(t *testing.T) {
			m := stubOf()
			m[member] = map[string]any{"error": "AccessDeniedException"}
			r := mustParse(t, render(t, m))
			api, _ := r.Open(t.Context(), "")
			var errs []error
			_, e1 := api.DescribeKey(t.Context(), arn)
			_, e2 := api.GetPublicKey(t.Context(), arn)
			_, e3 := api.GetKeyPolicy(t.Context(), arn, "default")
			errs = append(errs, e1, e2, e3)
			idx := map[string]int{"describe_key": 0, "get_public_key": 1, "get_key_policy": 2}[member]
			for i, err := range errs {
				if i == idx {
					var ae *kms.APIError
					if !errors.As(err, &ae) || ae.Code != "AccessDeniedException" {
						t.Fatalf("call %d: %v", i, err)
					}
				} else if err != nil {
					t.Fatalf("call %d: %v", i, err)
				}
			}
		})
	}
}

// When every answer is an error, every key gets its error; when some answer is a value, the other keys are
// not found.
func TestAFileOfErrorsAnswersEveryKey(t *testing.T) {
	r := mustParse(t, render(t, map[string]any{
		"describe_key": map[string]any{"error": "AccessDeniedException"}, "get_public_key": map[string]any{"error": "AccessDeniedException"},
		"get_key_policy": map[string]any{"error": "AccessDeniedException"},
	}))
	api, err := r.Open(t.Context(), "")
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{arn, other, "x"} {
		_, err := api.DescribeKey(t.Context(), k)
		var ae *kms.APIError
		if !errors.As(err, &ae) || ae.Code != "AccessDeniedException" {
			t.Fatalf("key %q: %v", k, err)
		}
		_, err = api.GetKeyPolicy(t.Context(), k, "default")
		if !errors.As(err, &ae) || ae.Code != "AccessDeniedException" {
			t.Fatalf("key %q: %v", k, err)
		}
	}
	// A file whose description is an error and whose public key is a value knows the key of the value.
	m := stubOf()
	m["describe_key"] = map[string]any{"error": "AccessDeniedException"}
	r = mustParse(t, render(t, m))
	api, _ = r.Open(t.Context(), "")
	_, err = api.DescribeKey(t.Context(), other)
	var ae *kms.APIError
	if !errors.As(err, &ae) || ae.Code != "NotFoundException" {
		t.Fatalf("another key: %v", err)
	}
	_, err = api.DescribeKey(t.Context(), arn)
	if !errors.As(err, &ae) || ae.Code != "AccessDeniedException" {
		t.Fatalf("the key of the public answer: %v", err)
	}
}

func TestACancelledContextIsReturnedByEveryCallAndNotLogged(t *testing.T) {
	r := mustParse(t, render(t, stubOf()))
	api, err := r.Open(t.Context(), "")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := r.Open(ctx, ""); !errors.Is(err, context.Canceled) {
		t.Fatalf("Open: %v", err)
	}
	if _, err := api.DescribeKey(ctx, arn); !errors.Is(err, context.Canceled) {
		t.Fatalf("DescribeKey: %v", err)
	}
	if _, err := api.GetPublicKey(ctx, arn); !errors.Is(err, context.Canceled) {
		t.Fatalf("GetPublicKey: %v", err)
	}
	if _, err := api.GetKeyPolicy(ctx, arn, "default"); !errors.Is(err, context.Canceled) {
		t.Fatalf("GetKeyPolicy: %v", err)
	}
	if want := []string{"open:-"}; !reflect.DeepEqual(r.Calls(), want) {
		t.Fatalf("calls %v: a call that ended is not logged as answered", r.Calls())
	}
}

func TestACallWithNoContextIsAnErrorAndNeverAPanic(t *testing.T) {
	r := mustParse(t, render(t, stubOf()))
	api, _ := r.Open(t.Context(), "")
	var nilCtx context.Context
	if _, err := r.Open(nilCtx, ""); err == nil { //nolint:staticcheck // a nil context is the case under test
		t.Fatal("Open with no context")
	}
	if _, err := api.DescribeKey(nilCtx, arn); err == nil { //nolint:staticcheck // as above
		t.Fatal("DescribeKey with no context")
	}
	if _, err := api.GetPublicKey(nilCtx, arn); err == nil { //nolint:staticcheck // as above
		t.Fatal("GetPublicKey with no context")
	}
	if _, err := api.GetKeyPolicy(nilCtx, arn, "default"); err == nil { //nolint:staticcheck // as above
		t.Fatal("GetKeyPolicy with no context")
	}
	var none *kmsreplay.Replay
	if _, err := none.Open(t.Context(), ""); err == nil {
		t.Fatal("Open of a nil replay")
	}
}

func TestCallsIsACopy(t *testing.T) {
	r := mustParse(t, render(t, stubOf()))
	api, _ := r.Open(t.Context(), "")
	_, _ = api.DescribeKey(t.Context(), arn)
	got := r.Calls()
	if len(got) != 2 {
		t.Fatalf("calls %v", got)
	}
	got[0] = "changed"
	got = append(got, "extra")
	_ = got
	again := r.Calls()
	if !reflect.DeepEqual(again, []string{"open:-", "DescribeKey"}) {
		t.Fatalf("calls %v after a change of the copy", again)
	}
	var fresh []string
	if len(mustParse(t, render(t, stubOf())).Calls()) != len(fresh) {
		t.Fatal("a new replay has calls")
	}
}

func TestTheAnswersShareNothingWithTheReplay(t *testing.T) {
	r := mustParse(t, render(t, stubOf()))
	api, _ := r.Open(t.Context(), "")
	d, _ := api.DescribeKey(t.Context(), arn)
	d.SigningAlgorithms[0] = "changed"
	d.ARN = "changed"
	d.KeyState = "Disabled"
	pk, _ := api.GetPublicKey(t.Context(), arn)
	pk.PublicKey[0] = 'X'
	pk.KeyID = "changed"
	d2, _ := api.DescribeKey(t.Context(), arn)
	pk2, _ := api.GetPublicKey(t.Context(), arn)
	if d2.SigningAlgorithms[0] != "ECDSA_SHA_384" || d2.ARN != arn || d2.KeyState != "Enabled" {
		t.Fatalf("description %+v", d2)
	}
	if string(pk2.PublicKey) != "der bytes" || pk2.KeyID != arn {
		t.Fatalf("public key answer %+v", pk2)
	}
}

// Eight goroutines each open and make the three calls: the answers are the same and the log has all the
// calls, with no timing involved.
func TestConcurrentCalls(t *testing.T) {
	const n = 8
	r := mustParse(t, render(t, withRole(stubOf())))
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			api, err := r.Open(context.Background(), roleA)
			if err != nil {
				errs <- err
				return
			}
			d, err := api.DescribeKey(context.Background(), arn)
			if err != nil || d.ARN != arn {
				errs <- fmt.Errorf("describe: %+v, %w", d, err)
				return
			}
			pk, err := api.GetPublicKey(context.Background(), arn)
			if err != nil || string(pk.PublicKey) != "der bytes" {
				errs <- fmt.Errorf("public key: %+v, %w", pk, err)
				return
			}
			p, err := api.GetKeyPolicy(context.Background(), arn, "default")
			if err != nil || p != policy {
				errs <- fmt.Errorf("policy: %q, %w", p, err)
				return
			}
			_ = r.Calls()
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	calls := r.Calls()
	if len(calls) != 4*n {
		t.Fatalf("%d calls in the log, want %d", len(calls), 4*n)
	}
	count := map[string]int{}
	for _, c := range calls {
		count[c]++
	}
	var keys []string
	for k := range count {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	want := map[string]int{"open:" + roleA: n, "DescribeKey": n, "GetPublicKey": n, "GetKeyPolicy:default": n}
	if !reflect.DeepEqual(count, want) {
		t.Fatalf("log %v", count)
	}
}

func FuzzParse(f *testing.F) {
	good := render(f, withRole(stubOf()))
	f.Add(good)
	f.Add(render(f, stubOf()))
	f.Add([]byte(`{"describe_key":{"error":"AccessDeniedException"},"get_public_key":{"error":"AccessDeniedException"},"get_key_policy":{"error":"AccessDeniedException"}}`))
	f.Add([]byte(""))
	f.Add([]byte("{}"))
	f.Add([]byte(`{"describe_key":[[[[[[[[`))
	f.Add(bytes.Replace(good, []byte(`"default"`), []byte(`"\u0000"`), 1))
	f.Fuzz(func(t *testing.T, data []byte) {
		r, err := kmsreplay.Parse(data)
		if err != nil {
			if r != nil {
				t.Fatal("a replay beside an error")
			}
			if !strings.HasPrefix(err.Error(), "kmsreplay:") || len(err.Error()) > 300 {
				t.Fatalf("error %q", err)
			}
			return
		}
		if len(data) > 256<<10 {
			t.Fatalf("accepted a file of %d bytes", len(data))
		}
		// An accepted stub answers every call without a panic, and a second read of the same bytes agrees.
		for _, role := range []string{"", roleA} {
			api, err := r.Open(context.Background(), role)
			if err != nil {
				continue
			}
			for _, k := range []string{arn, other, ""} {
				_, _ = api.DescribeKey(context.Background(), k)
				_, _ = api.GetPublicKey(context.Background(), k)
				_, _ = api.GetKeyPolicy(context.Background(), k, "default")
			}
		}
		if r2, err := kmsreplay.Parse(data); err != nil || r2 == nil {
			t.Fatalf("a second read: %v", err)
		}
	})
}
