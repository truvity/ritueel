package handoff_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/handoff"
)

// ReadProof is the reader of the proof file that the requester uses on its own request. It is the reader of the
// certifier: a file that it refuses is a file that the certifier refuses with malformed or version-unsupported,
// with the same words.

func TestReadProofReadsTheProofOfEveryVectorRequestAsTheCertifierDoes(t *testing.T) {
	m, cases := allRequestCases(t)
	roots := rootsOfManifest(t, m)
	read := 0
	for _, c := range cases {
		t.Run(c.ID, func(t *testing.T) {
			r := loadCase(t, c)
			proof := r.Files[handoff.FileProof]
			p, perr := handoff.ReadProof(proof)
			v, err := checkerOfCase(t, m, c, roots, testNow).Check(t.Context(), r)
			if err != nil && !errors.Is(err, handoff.ErrTypeNotBuilt) && !errors.Is(err, handoff.ErrNoVerifier) {
				t.Fatalf("Check: %v", err)
			}
			if perr != nil {
				if p != nil {
					t.Error("ReadProof returns a proof with an error")
				}
				if !errors.Is(perr, handoff.ErrProofShape) {
					t.Errorf("the error %v does not wrap ErrProofShape", perr)
				}
				switch {
				case v.Code == handoff.CodeVersionUnsupported && v.Checks[0].Status == handoff.StatusFailed:
				case v.Code == handoff.CodeMalformed && (v.Checks[1].Status == handoff.StatusFailed):
					if !strings.Contains(perr.Error(), v.Detail) {
						t.Errorf("ReadProof says %q, the certifier says %q", perr, v.Detail)
					}
				default:
					t.Errorf("ReadProof refuses a proof that the certifier takes past check 2: %v; code %q", perr, v.Code)
				}
				return
			}
			read++
			if p == nil || string(p.Type) != c.Type {
				t.Fatalf("ReadProof returns %+v for a case of type %s", p, c.Type)
			}
			var raw struct {
				RequestSHA256 string `json:"request_sha256"`
			}
			if err := json.Unmarshal(proof, &raw); err != nil || raw.RequestSHA256 != p.RequestSHA256 {
				t.Errorf("request_sha256 %q, the file says %q", p.RequestSHA256, raw.RequestSHA256)
			}
			if p.Handoff != 1 {
				t.Errorf("Handoff %d", p.Handoff)
			}
		})
	}
	if read < 20 {
		t.Errorf("only %d proofs were read", read)
	}
}

func allRequestCases(t testing.TB) (vectorManifest, []vectorCase) {
	t.Helper()
	m := readManifest(t)
	return m, m.Cases
}

func TestReadProofRefusesWhatTheCertifierRefusesAtChecksOneAndTwoWithTheSameWords(t *testing.T) {
	f := newFixture(t, handoff.StorePIV, csrSpec{})
	chk := newChecker(t)
	good := f.request().Files[handoff.FileProof]
	if _, err := handoff.ReadProof(good); err != nil {
		t.Fatalf("a good proof: %v", err)
	}
	set := func(change func(m map[string]any)) []byte { return proofWith(t, f, change) }
	longList := func(n int) []string {
		var l []string
		for i := 0; i < n; i++ {
			l = append(l, strings.Repeat("a", 40))
		}
		return l
	}
	for _, c := range []struct {
		name  string
		proof []byte
		code  handoff.Code
	}{
		{"an empty file", nil, handoff.CodeMalformed},
		{"text", []byte("proof"), handoff.CodeMalformed},
		{"an array", []byte("[]"), handoff.CodeMalformed},
		{"a byte order mark", append([]byte("\xef\xbb\xbf"), good...), handoff.CodeMalformed},
		{"a file over 256 KiB", bytes.Repeat([]byte(" "), handoff.MaxFileSize+1), handoff.CodeMalformed},
		{"version 2", set(func(m map[string]any) { m["handoff"] = 2 }), handoff.CodeVersionUnsupported},
		{"version 0", set(func(m map[string]any) { m["handoff"] = 0 }), handoff.CodeVersionUnsupported},
		{"the version as a string", set(func(m map[string]any) { m["handoff"] = "1" }), handoff.CodeMalformed},
		{"no version", set(func(m map[string]any) { delete(m, "handoff") }), handoff.CodeMalformed},
		{"the version twice", bytes.Replace(good, []byte(`"handoff":1`), []byte(`"handoff":1,"handoff":1`), 1), handoff.CodeMalformed},
		{"an unknown member", set(func(m map[string]any) { m["x"] = 1 }), handoff.CodeMalformed},
		{"a null member", set(func(m map[string]any) { m["store"] = nil }), handoff.CodeMalformed},
		{"a type that is unknown", set(func(m map[string]any) { m["type"] = "x509" }), handoff.CodeMalformed},
		{"a store that is unknown", set(func(m map[string]any) { m["store"] = "tpm" }), handoff.CodeMalformed},
		{"a digest in capitals", set(func(m map[string]any) { m["request_sha256"] = strings.ToUpper(m["request_sha256"].(string)) }), handoff.CodeMalformed},
		{"a digest of 63 digits", set(func(m map[string]any) { m["request_sha256"] = m["request_sha256"].(string)[:63] }), handoff.CodeMalformed},
		{"no evidence for a PIV key", set(func(m map[string]any) { delete(m, "evidence") }), handoff.CodeMalformed},
		{"primaries in an X.509 proof", set(func(m map[string]any) { m["primaries"] = longList(2) }), handoff.CodeMalformed},
		{"capabilities in an X.509 proof", set(func(m map[string]any) { m["capabilities"] = []string{"sign"} }), handoff.CodeMalformed},
		{"a use in an X.509 proof", set(func(m map[string]any) { m["use"] = "user" }), handoff.CodeMalformed},
		{"nine certificates of attestation", set(func(m map[string]any) {
			m["evidence"] = map[string]any{"attestation": []string{b64("a"), b64("a"), b64("a"), b64("a"), b64("a"), b64("a"), b64("a"), b64("a"), b64("a")}}
		}), handoff.CodeMalformed},
		{"an attestation that is not Base64", set(func(m map[string]any) { m["evidence"] = map[string]any{"attestation": []string{"!", "!"}} }), handoff.CodeMalformed},
		{"a nest of 100000 levels", bytes.Replace(good, []byte(`"handoff":1`), []byte(`"handoff":1,"x":`+strings.Repeat("[", 100000)+strings.Repeat("]", 100000)), 1), handoff.CodeMalformed},
	} {
		t.Run(c.name, func(t *testing.T) {
			p, perr := handoff.ReadProof(c.proof)
			if perr == nil || p != nil {
				t.Fatalf("ReadProof = %v, %v", p, perr)
			}
			if !errors.Is(perr, handoff.ErrProofShape) {
				t.Errorf("the error does not wrap ErrProofShape: %v", perr)
			}
			v, err := chk.Check(t.Context(), withProofBytes(f, c.proof))
			if err != nil {
				t.Fatal(err)
			}
			if v.Code != c.code {
				t.Fatalf("the certifier says %q (%s), want %q", v.Code, v.Detail, c.code)
			}
			if c.code == handoff.CodeMalformed && v.Checks[1].Status == handoff.StatusFailed && !strings.Contains(perr.Error(), v.Detail) {
				t.Errorf("ReadProof says %q, the certifier says %q", perr, v.Detail)
			}
		})
	}
	t.Run("an OpenPGP proof with one more primary than the bound", func(t *testing.T) {
		pf := newPGPFixture(t, 2, handoff.StoreSoftware)
		pf.edit(func(m map[string]any) { m["primaries"] = fingerprints(handoff.MaxPrimaries + 1) })
		p, err := handoff.ReadProof(pf.request().Files[handoff.FileProof])
		if err == nil || p != nil {
			t.Fatalf("ReadProof = %v, %v", p, err)
		}
		if want := fmt.Sprintf("primaries holds more than %d fingerprints", handoff.MaxPrimaries); !strings.Contains(err.Error(), want) {
			t.Errorf("the error is %q, want it to say %q", err, want)
		}
	})
}

func TestReadProofGivesTheMembersOfTheTypeAndNothingThatSharesTheFile(t *testing.T) {
	pf := newPGPFixture(t, 2, handoff.StoreKMS)
	r := pf.request()
	file := bytes.Clone(r.Files[handoff.FileProof])
	p, err := handoff.ReadProof(file)
	if err != nil {
		t.Fatal(err)
	}
	if p.Type != handoff.TypeOpenPGP || p.Store != handoff.StoreKMS || !slices.Equal(p.Primaries, pf.fingerprints()) || !slices.Equal(p.Capabilities, []string{"sign"}) || p.Use != "" {
		t.Errorf("proof %+v", p)
	}
	if len(p.Evidence) == 0 {
		t.Fatal("no evidence")
	}
	wantEvidence := bytes.Clone(p.Evidence)
	for i := range file {
		file[i] = 'x'
	}
	if !bytes.Equal(p.Evidence, wantEvidence) || !slices.Equal(p.Primaries, pf.fingerprints()) {
		t.Error("the proof shares its bytes with the file that was read")
	}
	again, err := handoff.ReadProof(r.Files[handoff.FileProof])
	if err != nil {
		t.Fatal(err)
	}
	again.Primaries[0] = "changed"
	third, _ := handoff.ReadProof(r.Files[handoff.FileProof])
	if third.Primaries[0] == "changed" {
		t.Error("two proofs share their lists")
	}
	if !slices.Equal(strictjsonKeys(t, wantEvidence), []string{"key_arn", "public_key"}) {
		t.Errorf("the evidence is %s", wantEvidence)
	}
}

func strictjsonKeys(t testing.TB, raw []byte) []string {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	var keys []string
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// The proof of a software key has no evidence, and the one of an SSH CA key has a use.
func TestReadProofReadsTheSoftwareAndTheSSHProofsOfTheVectors(t *testing.T) {
	m := readManifest(t)
	seen := map[string]bool{}
	for _, c := range m.Cases {
		if c.Expect != "accept" {
			continue
		}
		r := loadCase(t, c)
		p, err := handoff.ReadProof(r.Files[handoff.FileProof])
		if err != nil {
			t.Fatalf("%s: %v", c.ID, err)
		}
		seen[string(p.Type)+"/"+string(p.Store)] = true
		switch p.Type {
		case handoff.TypeSSH:
			if p.Use != "user" && p.Use != "host" {
				t.Errorf("%s: use %q", c.ID, p.Use)
			}
		case handoff.TypeOpenPGP:
			if len(p.Primaries) != 2 || len(p.Capabilities) != 1 {
				t.Errorf("%s: %+v", c.ID, p)
			}
		}
	}
	for _, want := range []string{"x509-intermediate/software", "openpgp-subkey/software", "ssh-ca-key/software", "x509-intermediate/piv", "x509-intermediate/aws-kms"} {
		if !seen[want] {
			t.Errorf("no accepted vector of %s", want)
		}
	}
}

func FuzzReadProof(f *testing.F) {
	for _, set := range seedRequests(f) {
		f.Add(set[0])
	}
	f.Add([]byte(`{"handoff":1}`))
	f.Add([]byte(`{"handoff":2}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := handoff.ReadProof(data)
		if err != nil {
			if p != nil {
				t.Fatal("a proof comes with an error")
			}
			if !errors.Is(err, handoff.ErrProofShape) {
				t.Fatalf("an error that is not of the shape of the proof: %v", err)
			}
			return
		}
		if len(data) > handoff.MaxFileSize {
			t.Fatal("a file over the limit is read")
		}
		switch p.Type {
		case handoff.TypeX509, handoff.TypeOpenPGP, handoff.TypeSSH:
		default:
			t.Fatalf("the type %q", p.Type)
		}
		if len(p.RequestSHA256) != 64 || p.Handoff != 1 {
			t.Fatalf("proof %+v", p)
		}
		if len(p.Primaries) > handoff.MaxPrimaries {
			t.Fatalf("%d primaries", len(p.Primaries))
		}
	})
}

// "A receiver that does not know the version refuses the message with version-unsupported and reads nothing
// else in it" (the contract, "Versioning"). ReadProof says the same of a proof file: a file of another version is
// refused before the rest of it is read, so the error names the version and not a fault of what follows.
func TestReadProofReadsNothingElseOfAFileOfAnotherVersion(t *testing.T) {
	_, plain := handoff.ReadProof([]byte(`{"handoff":2}`))
	if plain == nil {
		t.Fatal("version 2 is read")
	}
	for _, rest := range []string{`,"zzz":1`, `,"zzz":null`, `,"type":"x509-intermediate"`, `,"type":"nothing","store":"nothing"`, `,"evidence":[1,2,3]`, `,"request_sha256":"x"`} {
		_, err := handoff.ReadProof([]byte(`{"handoff":2` + rest + `}`))
		if err == nil || !errors.Is(err, handoff.ErrProofShape) {
			t.Fatalf("%s: %v", rest, err)
		}
		if err.Error() != plain.Error() {
			t.Errorf("a file of version 2 with %s is refused for something else than its version: %q, and without the rest: %q", rest, err, plain)
		}
	}
}

// A proof of another version is refused with the words that the certifier uses for the same bytes (check 1), and
// whatever follows the version is not read: the same bytes with the rest of a good proof, with a rest that is
// not a proof, and with a rest that is long give the same words.
func TestReadProofSaysTheVersionInTheWordsOfTheCertifier(t *testing.T) {
	f := newFixture(t, handoff.StorePIV, csrSpec{})
	chk := newChecker(t)
	good := f.request().Files[handoff.FileProof]
	for _, version := range []string{"0", "-1", "2", "3", "10", "100", "9007199254740991", "-9007199254740991"} {
		wantText := "the contract version is " + version + ", and only 1 is known"
		bodies := map[string][]byte{
			"the version alone":    []byte(`{"handoff":` + version + `}`),
			"a good proof":         bytes.Replace(good, []byte(`"handoff":1`), []byte(`"handoff":`+version), 1),
			"an unknown member":    []byte(`{"handoff":` + version + `,"zzz":1}`),
			"a null":               []byte(`{"handoff":` + version + `,"type":null}`),
			"the member last":      []byte(`{"type":"nothing","handoff":` + version + `}`),
			"a rest of many words": []byte(`{"handoff":` + version + `,"x":"` + strings.Repeat("word ", 40000) + `"}`),
			"spaces and new lines": []byte("\n {\n \"handoff\" :\t" + version + " \n}\n"),
		}
		for name, file := range bodies {
			t.Run(version+" "+name, func(t *testing.T) {
				p, err := handoff.ReadProof(file)
				if err == nil || p != nil || !errors.Is(err, handoff.ErrProofShape) {
					t.Fatalf("ReadProof = %v, %v", p, err)
				}
				if !strings.HasSuffix(err.Error(), ": "+wantText) {
					t.Errorf("the error is %q, want the words %q at its end", err, wantText)
				}
				v, cerr := chk.Check(t.Context(), withProofBytes(f, file))
				if cerr != nil {
					t.Fatal(cerr)
				}
				if v.Code != handoff.CodeVersionUnsupported || v.Detail != wantText {
					t.Fatalf("the certifier says %q (%q)", v.Code, v.Detail)
				}
			})
		}
	}
	t.Run("a rest that is too deep for the reader is judged by the one reader, here and at the certifier", func(t *testing.T) {
		// The version is found by a scan that holds the same depth limit as the reader of the whole file, so a
		// nest is a fault of form for both, with the same words, and not a version.
		file := []byte(`{"handoff":2,"x":` + strings.Repeat("[", 100000) + strings.Repeat("]", 100000) + `}`)
		_, err := handoff.ReadProof(file)
		if err == nil || !errors.Is(err, handoff.ErrProofShape) {
			t.Fatalf("%v", err)
		}
		v, cerr := chk.Check(t.Context(), withProofBytes(f, file))
		if cerr != nil {
			t.Fatal(cerr)
		}
		if v.Code != handoff.CodeMalformed || !strings.Contains(err.Error(), v.Detail) {
			t.Fatalf("ReadProof says %q, the certifier says %q (%s)", err, v.Detail, v.Code)
		}
	})
	t.Run("a version that is not an integer is a fault of form, as it is for the certifier", func(t *testing.T) {
		for _, v := range []string{`"1"`, `1.0`, `1e0`, `2.5`, `null`, `true`, `[1]`, `9007199254740993`, `-0`, `01`} {
			file := []byte(`{"handoff":` + v + `}`)
			_, err := handoff.ReadProof(file)
			if err == nil || !errors.Is(err, handoff.ErrProofShape) {
				t.Fatalf("%s: %v", v, err)
			}
			vd, cerr := chk.Check(t.Context(), withProofBytes(f, file))
			if cerr != nil {
				t.Fatal(cerr)
			}
			switch vd.Code {
			case handoff.CodeMalformed:
				if !strings.Contains(err.Error(), vd.Detail) {
					t.Errorf("%s: ReadProof says %q, the certifier says %q", v, err, vd.Detail)
				}
			case handoff.CodeVersionUnsupported:
				if !strings.Contains(err.Error(), vd.Detail) {
					t.Errorf("%s: ReadProof says %q, the certifier says %q", v, err, vd.Detail)
				}
			default:
				t.Errorf("%s: the certifier says %q", v, vd.Code)
			}
		}
	})
	t.Run("version 1 is read", func(t *testing.T) {
		if p, err := handoff.ReadProof(good); err != nil || p == nil || p.Handoff != 1 {
			t.Fatalf("%v %v", p, err)
		}
	})
}
