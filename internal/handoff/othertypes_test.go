package handoff_test

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/handoff"
)

// An SSH CA key request runs the checks 1 to 3 and then stops, because the rest of its checks is not built;
// the bytes of its files are not read here, only their names, their size and the digest. An OpenPGP subkey
// request has all nine checks (see openpgp_test.go); the tests of its proof file and its files that the page
// states in the same terms as the other types are here.

var (
	sshPubBytes  = []byte("ecdsa-sha2-nistp384 AAAAE2VjZHNhLXNoYTItbmlzdHAzODQ example\n")
	sshSigBytes  = []byte("-----BEGIN SSH SIGNATURE-----\nAAAA\n-----END SSH SIGNATURE-----\n")
	fingerprintA = strings.Repeat("ab", 20)
)

// pgpCase is a good request of type openpgp-subkey for two primaries, with a software key, after the change
// of the members of its proof, and a checker that holds the same two primaries.
func pgpCase(t testing.TB, change func(m map[string]any)) (*handoff.Request, *handoff.Checker) {
	t.Helper()
	f := newPGPFixture(t, 2, handoff.StoreSoftware).edit(change)
	return f.request(), f.checker(nil)
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
			r, chk := pgpCase(t, change)
			v, err := chk.Check(t.Context(), r)
			wantRefusal(t, v, err, handoff.CodeMalformed, 2)
		})
	}
	// The two capabilities of the page are read, and the one that the delegation holds is accepted.
	for _, capability := range []string{"sign", "authenticate"} {
		f := newPGPFixture(t, 2, handoff.StoreSoftware).edit(func(m map[string]any) { m["capabilities"] = []string{capability} })
		v, err := f.checker(func(c *handoff.Config) { c.Delegation.Capability = capability }).Check(t.Context(), f.request())
		wantAccepted(t, v, err)
		if v.Subkey == nil || v.Subkey.Capability != capability {
			t.Errorf("%s: the subkey of the verdict is %+v", capability, v.Subkey)
		}
	}
}

func TestTheFilesOfAnOpenPGPAndAnSSHRequestMustBeThere(t *testing.T) {
	r, chk := pgpCase(t, nil)
	delete(r.Files, handoff.FileSubkey)
	v, err := chk.Check(t.Context(), r)
	wantRefusal(t, v, err, handoff.CodeMalformed, 2)

	for _, missing := range []string{handoff.FileSSHKey, handoff.FileSSHSig} {
		r := sshRequest(nil)
		delete(r.Files, missing)
		v, err := newChecker(t).Check(t.Context(), r)
		wantRefusal(t, v, err, handoff.CodeMalformed, 2)
	}

	// A request of one type with the file of another in its place has no file of its own.
	r, chk = pgpCase(t, nil)
	r.Files[handoff.FileCSR] = r.Files[handoff.FileSubkey]
	delete(r.Files, handoff.FileSubkey)
	v, err = chk.Check(t.Context(), r)
	wantRefusal(t, v, err, handoff.CodeMalformed, 2)
}

func TestTheFilesOfAnOpenPGPAndAnSSHRequestAreHeldToTheSizeLimit(t *testing.T) {
	big := make([]byte, handoff.MaxFileSize+1)
	f := newPGPFixture(t, 2, handoff.StoreSoftware)
	f.file = big
	v, err := f.checker(nil).Check(t.Context(), f.request())
	wantRefusal(t, v, err, handoff.CodeMalformed, 2)

	for _, name := range []string{handoff.FileSSHKey, handoff.FileSSHSig} {
		r := sshRequest(nil)
		r.Files[name] = big
		v, err := newChecker(t).Check(t.Context(), r)
		wantRefusal(t, v, err, handoff.CodeMalformed, 2)
	}

	// A subkey file of exactly the limit is not too large: it is whole packets (the subkey and one packet
	// of padding), so the checks go on, and the one that refuses is check 5, which finds the packet after
	// the subkey is no back-signature.
	g := newPGPFixture(t, 1, handoff.StoreSoftware)
	pad := make([]byte, handoff.MaxFileSize-len(g.subPacket)-6)
	g.file = append(slices.Clone(g.subPacket), pgpPacket(pgpTagUserID, pad)...)
	if len(g.file) != handoff.MaxFileSize {
		t.Fatalf("test setup: the file is %d bytes", len(g.file))
	}
	v, err = g.checker(nil).Check(t.Context(), g.request())
	wantRefusal(t, v, err, handoff.CodePossessionInvalid, 5)
}

func TestTheDigestOfAnOpenPGPRequestIsOfTheSubkeyFile(t *testing.T) {
	f := newPGPFixture(t, 2, handoff.StoreSoftware)
	f.digest = digestHex([]byte("something else"))
	v, err := f.checker(nil).Check(t.Context(), f.request())
	wantRefusal(t, v, err, handoff.CodeRequestMismatch, 3)

	// One byte of the file changes after the proof was made.
	g := newPGPFixture(t, 2, handoff.StoreSoftware)
	r := g.request()
	r.Files[handoff.FileSubkey][len(r.Files[handoff.FileSubkey])-1] ^= 1
	v, err = g.checker(nil).Check(t.Context(), r)
	wantRefusal(t, v, err, handoff.CodeRequestMismatch, 3)

	// The digest is of the bytes of the file, not of the subkey packet alone: the digest of the first packet
	// is not the digest of the file.
	h := newPGPFixture(t, 2, handoff.StoreSoftware)
	h.digest = digestHex(h.subPacket)
	v, err = h.checker(nil).Check(t.Context(), h.request())
	wantRefusal(t, v, err, handoff.CodeRequestMismatch, 3)
}

func TestAnSSHRequestIsTheOnlyTypeThatStopsAsNotBuiltWhateverTheStore(t *testing.T) {
	for _, store := range []string{"software", "piv", "openpgp-card", "aws-kms"} {
		r := sshRequest(func(m map[string]any) {
			m["store"] = store
			if ev := evidenceFor(handoff.Store(store)); ev != nil {
				m["evidence"] = ev
			} else {
				delete(m, "evidence")
			}
		})
		v, err := newChecker(t).Check(t.Context(), r)
		if !errors.Is(err, handoff.ErrTypeNotBuilt) {
			t.Errorf("ssh %s: error %v", store, err)
		}
		if v.Complete() || v.Refused() || v.Accepted() {
			t.Errorf("ssh %s: complete %v, code %q, accepted %v", store, v.Complete(), v.Code, v.Accepted())
		}
		// An OpenPGP request of the same store never gets that error.
		f := newPGPFixture(t, 2, handoff.Store(store))
		_, oerr := f.checker(nil).Check(t.Context(), f.request())
		if errors.Is(oerr, handoff.ErrTypeNotBuilt) {
			t.Errorf("openpgp %s: the error is ErrTypeNotBuilt", store)
		}
	}
}
