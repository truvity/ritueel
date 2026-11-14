package handoff_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/fsx"
	"ritueel.id/ritueel/internal/handoff"
	"ritueel.id/ritueel/internal/openpgp"
)

// pgpFuzzVerifier is the evidence verifier of the OpenPGP fuzz target: it reads the key of the subkey from the
// subkey file with the reader of package openpgp, and never reads csr.pem (an OpenPGP request has none). It
// reports a recent firmware, an allowed PIN policy and one principal, so that checks 8 and 9 are reached.
type pgpFuzzVerifier struct{}

func (pgpFuzzVerifier) Verify(_ context.Context, r *handoff.Request, _ *handoff.Proof, _ time.Time) (*handoff.Evidence, error) {
	if _, ok := r.Files[handoff.FileCSR]; ok {
		return nil, &handoff.CodeError{Code: handoff.CodeProofInvalid, Detail: "a request file of another type"}
	}
	first, _, err := openpgp.SplitSubkeyFile(r.Files[handoff.FileSubkey], handoff.MaxPrimaries)
	if err != nil {
		return nil, &handoff.CodeError{Code: handoff.CodeProofInvalid, Detail: "no subkey"}
	}
	sub, err := openpgp.ReadSubkey(first)
	if err != nil {
		return nil, &handoff.CodeError{Code: handoff.CodeProofInvalid, Detail: "no key"}
	}
	return &handoff.Evidence{
		Key: sub.PublicKey(), Firmware: "5.8.0", PINPolicy: handoff.PINOnce,
		SignPrincipals: []handoff.Principal{{ARN: "arn:aws:iam::123456789012:role/example-holder", Kind: handoff.PrincipalRole}},
	}, nil
}

// FuzzCheckOpenPGP runs the nine checks of an openpgp-subkey request on the proof and subkey files of the
// vectors and their mutations. Whatever the bytes, the laws of every verdict hold, a refused verdict (and any
// verdict beside an error) holds no key, no evidence and no subkey, and an accepted verdict holds all three, with
// the subkey that package openpgp reads from the first packet of the file.
func FuzzCheckOpenPGP(f *testing.F) {
	for _, s := range seedRequests(f) {
		f.Add(s[0], s[2])
	}
	f.Add([]byte(`{"handoff":1,"type":"openpgp-subkey"}`), []byte(nil))
	f.Add([]byte(`{}`), []byte{0xCE, 0x00})
	m := readManifest(f)
	cfg := configOfCase(f, m, vectorCase{ID: "fuzz", Type: "openpgp-subkey", Config: "development"}, rootsOfManifest(f, m), testNow)
	v := pgpFuzzVerifier{}
	cfg.Evidence = map[handoff.Store]handoff.EvidenceVerifier{handoff.StorePIV: v, handoff.StoreKMS: v, handoff.StoreOpenPGPCard: v}
	chk := mustNew(f, cfg)
	f.Fuzz(func(t *testing.T, proof, subkey []byte) {
		r := &handoff.Request{Stem: "fuzz", Files: map[string][]byte{handoff.FileProof: proof}}
		if subkey != nil {
			r.Files[handoff.FileSubkey] = subkey
		}
		before := copyOfRequest(r)
		verdict, err := chk.Check(t.Context(), r)
		checkVerdictLaws(t, r, verdict, err)
		if !sameRequest(before, r) {
			t.Fatal("the request of the caller was changed")
		}
		if verdict.Accepted() {
			if verdict.Subkey == nil || verdict.Key == nil || verdict.Evidence == nil {
				t.Fatalf("an acceptance without a subkey, a key or evidence: %+v", verdict)
			}
			first, _, serr := openpgp.SplitSubkeyFile(subkey, handoff.MaxPrimaries)
			if serr != nil {
				t.Fatalf("a subkey file that cannot be split was accepted: %v", serr)
			}
			sub, rerr := openpgp.ReadSubkey(first)
			if rerr != nil {
				t.Fatalf("a subkey that cannot be read was accepted: %v", rerr)
			}
			if verdict.Subkey.Fingerprint != sub.Fingerprint() || !verdict.Subkey.Created.Equal(sub.Created()) || !verdict.Key.Equal(sub.PublicKey()) {
				t.Fatalf("the subkey of the verdict is not the one of the file: %+v", verdict.Subkey)
			}
			if verdict.Subkey.Capability != "sign" {
				t.Fatalf("capability %q", verdict.Subkey.Capability)
			}
		} else if verdict.Subkey != nil || verdict.Key != nil || verdict.Evidence != nil {
			t.Fatalf("a verdict that is not accepted holds a subkey, a key or evidence: %+v", verdict)
		}
		again, err2 := chk.Check(t.Context(), r)
		if again.Code != verdict.Code || statuses(again) != statuses(verdict) || (err == nil) != (err2 == nil) {
			t.Fatalf("two runs differ: %q %s %v, and %q %s %v", verdict.Code, statuses(verdict), err, again.Code, statuses(again), err2)
		}
	})
}

// The subkey file is read through the loader, which follows no link: a link, a pipe or a folder where the
// file belongs is an error of the loader, and the checks never see it.
func TestALinkAPipeOrAFolderInPlaceOfTheSubkeyFileIsRefusedByTheLoader(t *testing.T) {
	f := newPGPFixture(t, 2, handoff.StoreSoftware)
	for name, put := range map[string]func(t *testing.T, dir, secret string){
		"a link to a file": func(t *testing.T, dir, secret string) {
			if err := os.Symlink(secret, filepath.Join(dir, "x.subkey.pgp")); err != nil {
				t.Skip(err)
			}
		},
		"a pipe": func(t *testing.T, dir, _ string) {
			if err := syscall.Mkfifo(filepath.Join(dir, "x.subkey.pgp"), 0o600); err != nil {
				t.Skip(err)
			}
		},
		"a folder": func(t *testing.T, dir, _ string) {
			if err := os.Mkdir(filepath.Join(dir, "x.subkey.pgp"), 0o700); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			base := t.TempDir()
			dir := filepath.Join(base, "requests", "x")
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			req := f.request()
			secret := filepath.Join(base, "secret")
			if err := os.WriteFile(secret, req.Files[handoff.FileSubkey], 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "x.proof.json"), req.Files[handoff.FileProof], 0o600); err != nil {
				t.Fatal(err)
			}
			put(t, dir, secret)
			root, err := fsx.OpenFS(base)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = root.Close() })
			r, err := loadWithin(t, root, "requests/x", "x")
			wantLoadError(t, r, err)
		})
	}
	// The control: the same files as plain files load and are accepted.
	base := t.TempDir()
	dir := filepath.Join(base, "requests", "x")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	req := f.request()
	for suffix, data := range req.Files {
		if err := os.WriteFile(filepath.Join(dir, "x."+suffix), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	root, err := fsx.OpenFS(base)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	r, err := loadWithin(t, root, "requests/x", "x")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(r.Files[handoff.FileSubkey], req.Files[handoff.FileSubkey]) {
		t.Fatal("the loader changed the subkey file")
	}
	v, err := f.checker(nil).Check(t.Context(), r)
	wantAccepted(t, v, err)
}
