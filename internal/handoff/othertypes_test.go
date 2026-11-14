package handoff_test

import (
	"errors"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/handoff"
)

// The OpenPGP subkey and the SSH CA key requests run the checks 1 to 3 and then stop, because the rest
// of their checks is not built. The bytes of their files are not read here: only their names, their
// size and the digest.

var (
	subkeyBytes  = []byte("\x98\x00 a public subkey packet, as far as these checks look")
	sshPubBytes  = []byte("ecdsa-sha2-nistp384 AAAAE2VjZHNhLXNoYTItbmlzdHAzODQ example\n")
	sshSigBytes  = []byte("-----BEGIN SSH SIGNATURE-----\nAAAA\n-----END SSH SIGNATURE-----\n")
	fingerprintA = strings.Repeat("ab", 20)
	fingerprintB = strings.Repeat("0123456789", 4)
)

func pgpRequest(change func(m map[string]any)) *handoff.Request {
	m := map[string]any{
		"handoff":        1,
		"type":           "openpgp-subkey",
		"request_sha256": digestHex(subkeyBytes),
		"store":          "software",
		"primaries":      []string{fingerprintA, fingerprintB},
		"capabilities":   []string{"sign"},
	}
	if change != nil {
		change(m)
	}
	b, err := jsonOf(m)
	if err != nil {
		panic(err)
	}
	return &handoff.Request{Stem: testStem, Files: map[string][]byte{
		handoff.FileProof:  b,
		handoff.FileSubkey: append([]byte(nil), subkeyBytes...),
	}}
}

func sshRequest(change func(m map[string]any)) *handoff.Request {
	m := map[string]any{
		"handoff":        1,
		"type":           "ssh-ca-key",
		"request_sha256": digestHex(sshPubBytes),
		"store":          "software",
		"use":            "user",
	}
	if change != nil {
		change(m)
	}
	b, err := jsonOf(m)
	if err != nil {
		panic(err)
	}
	return &handoff.Request{Stem: testStem, Files: map[string][]byte{
		handoff.FileProof:  b,
		handoff.FileSSHKey: append([]byte(nil), sshPubBytes...),
		handoff.FileSSHSig: append([]byte(nil), sshSigBytes...),
	}}
}

func TestAnOpenPGPRequestThatIsWellFormedRunsChecksOneToThreeAndStopsAsNotBuilt(t *testing.T) {
	v, err := newChecker(t).Check(t.Context(), pgpRequest(nil))
	if !errors.Is(err, handoff.ErrTypeNotBuilt) {
		t.Fatalf("error %v, want ErrTypeNotBuilt", err)
	}
	if v.Refused() || v.Complete() {
		t.Fatalf("code %q, complete %v: a request whose checks are not built is neither refused nor accepted", v.Code, v.Complete())
	}
	// Check 3 for OpenPGP is the digest and then the primaries against the signed root list. The list is
	// not read, so check 3 did not fully run and is not passed.
	if got := statuses(v); got != "ppnnnnnnn" {
		t.Fatalf("statuses %s, want ppnnnnnnn", got)
	}
	if got := v.Checks[2].NotRun; len(got) != 1 || got[0] != "primaries" {
		t.Errorf("check 3 names %v as not run, want [primaries]", got)
	}
}

func TestAnSSHRequestThatIsWellFormedRunsChecksOneToThreeAndStopsAsNotBuilt(t *testing.T) {
	for _, use := range []string{"user", "host"} {
		v, err := newChecker(t).Check(t.Context(), sshRequest(func(m map[string]any) { m["use"] = use }))
		if !errors.Is(err, handoff.ErrTypeNotBuilt) {
			t.Fatalf("%s: error %v, want ErrTypeNotBuilt", use, err)
		}
		if v.Refused() || v.Complete() {
			t.Fatalf("%s: code %q, complete %v", use, v.Code, v.Complete())
		}
		if got := statuses(v); got != "pppnnnnnn" {
			t.Fatalf("%s: statuses %s, want pppnnnnnn", use, got)
		}
		if len(v.Checks[2].NotRun) != 0 {
			t.Errorf("check 3 for SSH is the digest alone: %v", v.Checks[2].NotRun)
		}
	}
}

func TestAnOpenPGPProofIsMalformedWhenItIsNotOfTheFormOfThePage(t *testing.T) {
	set := func(k string, v any) func(m map[string]any) {
		return func(m map[string]any) { m[k] = v }
	}
	del := func(k string) func(m map[string]any) {
		return func(m map[string]any) { delete(m, k) }
	}
	cases := map[string]func(m map[string]any){
		"no primaries":                   del("primaries"),
		"an empty list of primaries":     set("primaries", []string{}),
		"a primary of 39 digits":         set("primaries", []string{fingerprintA[1:]}),
		"a primary of 41 digits":         set("primaries", []string{fingerprintA + "0"}),
		"a primary in upper case":        set("primaries", []string{strings.ToUpper(fingerprintA)}),
		"a primary that is not hex":      set("primaries", []string{strings.Repeat("zz", 20)}),
		"one good primary and a bad one": set("primaries", []string{fingerprintA, "1234"}),
		"a primary that is a number":     set("primaries", []any{1}),
		"primaries that is a string":     set("primaries", fingerprintA),
		"no capabilities":                del("capabilities"),
		"two capabilities":               set("capabilities", []string{"sign", "authenticate"}),
		"the encrypt capability":         set("capabilities", []string{"encrypt"}),
		"the certify capability":         set("capabilities", []string{"certify"}),
		"an empty list of capabilities":  set("capabilities", []string{}),
		"capabilities as a string":       set("capabilities", "sign"),
		"a capability in upper case":     set("capabilities", []string{"Sign"}),
		"the same capability twice":      set("capabilities", []string{"sign", "sign"}),
		"a use member":                   set("use", "user"),
		"an empty use member":            set("use", ""),
		"the store piv with no evidence": set("store", "piv"),
		"evidence on a software key":     set("evidence", evidenceFor(handoff.StorePIV)),
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			v, err := newChecker(t).Check(t.Context(), pgpRequest(change))
			wantRefusal(t, v, err, handoff.CodeMalformed, 2)
		})
	}
	for _, capability := range []string{"sign", "authenticate"} {
		v, err := newChecker(t).Check(t.Context(), pgpRequest(func(m map[string]any) { m["capabilities"] = []string{capability} }))
		if !errors.Is(err, handoff.ErrTypeNotBuilt) || v.Refused() {
			t.Errorf("%s: a good capability gives code %q, error %v", capability, v.Code, err)
		}
	}
}

func TestAnSSHProofIsMalformedWhenItIsNotOfTheFormOfThePage(t *testing.T) {
	set := func(k string, v any) func(m map[string]any) {
		return func(m map[string]any) { m[k] = v }
	}
	cases := map[string]func(m map[string]any){
		"no use":                 func(m map[string]any) { delete(m, "use") },
		"use both":               set("use", "both"),
		"an empty use":           set("use", ""),
		"use in upper case":      set("use", "User"),
		"use that is a list":     set("use", []string{"user"}),
		"use that is a number":   set("use", 1),
		"primaries":              set("primaries", []string{fingerprintA}),
		"an empty primaries":     set("primaries", []string{}),
		"capabilities":           set("capabilities", []string{"sign"}),
		"an empty capabilities":  set("capabilities", []string{}),
		"an unknown member":      set("unknown", 1),
		"evidence for software":  set("evidence", map[string]any{}),
		"the store of no kind":   set("store", "tpm"),
		"no digest":              func(m map[string]any) { delete(m, "request_sha256") },
		"a digest in upper case": set("request_sha256", strings.ToUpper(digestHex(sshPubBytes))),
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			v, err := newChecker(t).Check(t.Context(), sshRequest(change))
			wantRefusal(t, v, err, handoff.CodeMalformed, 2)
		})
	}
}

func TestTheFilesOfAnOpenPGPAndAnSSHRequestMustBeThere(t *testing.T) {
	r := pgpRequest(nil)
	delete(r.Files, handoff.FileSubkey)
	v, err := newChecker(t).Check(t.Context(), r)
	wantRefusal(t, v, err, handoff.CodeMalformed, 2)

	for _, missing := range []string{handoff.FileSSHKey, handoff.FileSSHSig} {
		r := sshRequest(nil)
		delete(r.Files, missing)
		v, err := newChecker(t).Check(t.Context(), r)
		wantRefusal(t, v, err, handoff.CodeMalformed, 2)
	}

	// A request of one type with the file of another in its place has no file of its own.
	r = pgpRequest(nil)
	delete(r.Files, handoff.FileSubkey)
	r.Files[handoff.FileCSR] = subkeyBytes
	v, err = newChecker(t).Check(t.Context(), r)
	wantRefusal(t, v, err, handoff.CodeMalformed, 2)
}

func TestTheFilesOfAnOpenPGPAndAnSSHRequestAreHeldToTheSizeLimit(t *testing.T) {
	big := make([]byte, handoff.MaxFileSize+1)
	r := pgpRequest(nil)
	r.Files[handoff.FileSubkey] = big
	v, err := newChecker(t).Check(t.Context(), r)
	wantRefusal(t, v, err, handoff.CodeMalformed, 2)

	for _, name := range []string{handoff.FileSSHKey, handoff.FileSSHSig} {
		r := sshRequest(nil)
		r.Files[name] = big
		v, err := newChecker(t).Check(t.Context(), r)
		wantRefusal(t, v, err, handoff.CodeMalformed, 2)
	}

	// A file of exactly the limit is not too large: the check goes on to the digest.
	r = pgpRequest(nil)
	exact := make([]byte, handoff.MaxFileSize)
	r.Files[handoff.FileSubkey] = exact
	r.Files[handoff.FileProof] = pgpRequest(func(m map[string]any) { m["request_sha256"] = digestHex(exact) }).Files[handoff.FileProof]
	if _, err := newChecker(t).Check(t.Context(), r); !errors.Is(err, handoff.ErrTypeNotBuilt) {
		t.Errorf("a subkey file of exactly 256 KiB: error %v", err)
	}
}

func TestTheDigestOfAnOpenPGPRequestIsOfTheSubkeyFile(t *testing.T) {
	r := pgpRequest(func(m map[string]any) { m["request_sha256"] = digestHex([]byte("something else")) })
	v, err := newChecker(t).Check(t.Context(), r)
	wantRefusal(t, v, err, handoff.CodeRequestMismatch, 3)

	// One byte of the file changes after the proof was made.
	r = pgpRequest(nil)
	r.Files[handoff.FileSubkey][3] ^= 1
	v, err = newChecker(t).Check(t.Context(), r)
	wantRefusal(t, v, err, handoff.CodeRequestMismatch, 3)
}

func TestTheDigestOfAnSSHRequestIsOfTheKeyFileAndNotOfTheSignature(t *testing.T) {
	r := sshRequest(func(m map[string]any) { m["request_sha256"] = digestHex(sshSigBytes) })
	v, err := newChecker(t).Check(t.Context(), r)
	wantRefusal(t, v, err, handoff.CodeRequestMismatch, 3)

	r = sshRequest(nil)
	r.Files[handoff.FileSSHKey][5] ^= 1
	v, err = newChecker(t).Check(t.Context(), r)
	wantRefusal(t, v, err, handoff.CodeRequestMismatch, 3)

	// The signature file is not part of the digest: changing it does not make a mismatch.
	r = sshRequest(nil)
	r.Files[handoff.FileSSHSig][5] ^= 1
	if _, err := newChecker(t).Check(t.Context(), r); !errors.Is(err, handoff.ErrTypeNotBuilt) {
		t.Errorf("error %v", err)
	}
}

func TestThePrimariesOfAnOpenPGPRequestAreNeverTakenForKnown(t *testing.T) {
	// The root list is not read, so a request with any primaries is neither accepted nor given a reason that
	// needs the list: it is not decided.
	for _, ps := range [][]string{{fingerprintA}, {fingerprintB, fingerprintA}, {strings.Repeat("0", 40)}} {
		v, err := newChecker(t).Check(t.Context(), pgpRequest(func(m map[string]any) { m["primaries"] = ps }))
		if !errors.Is(err, handoff.ErrTypeNotBuilt) || v.Complete() || v.Code == handoff.CodeUnknownPrimary {
			t.Errorf("primaries %v: code %q, error %v, complete %v", ps, v.Code, err, v.Complete())
		}
	}
}

func TestACheckOfAnUnbuiltTypeNeverReadsAsAcceptedWhateverTheStore(t *testing.T) {
	for _, store := range []string{"software", "piv", "openpgp-card", "aws-kms"} {
		for name, mk := range map[string]func(func(m map[string]any)) *handoff.Request{"openpgp": pgpRequest, "ssh": sshRequest} {
			r := mk(func(m map[string]any) {
				m["store"] = store
				if ev := evidenceFor(handoff.Store(store)); ev != nil {
					m["evidence"] = ev
				} else {
					delete(m, "evidence")
				}
			})
			chk := newChecker(t)
			v, err := chk.Check(t.Context(), r)
			if !errors.Is(err, handoff.ErrTypeNotBuilt) {
				t.Errorf("%s %s: error %v", name, store, err)
			}
			if v.Complete() || v.Refused() {
				t.Errorf("%s %s: complete %v, code %q", name, store, v.Complete(), v.Code)
			}
		}
	}
}
