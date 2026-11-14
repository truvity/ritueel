package handoff_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/x509/pkix"
	"strings"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/handoff"
)

// plain reports whether the text is printable ASCII, the form in which a refusal may be shown.
func plain(s string) bool {
	for _, r := range s {
		if r < 0x20 || r >= 0x7f {
			return false
		}
	}
	return true
}

func TestTheSizeOfAFileIsRefusedBeforeItIsReadAndTheDetailSaysSo(t *testing.T) {
	f := newFixture(t, handoff.StoreSoftware, csrSpec{})
	over := append(bytes.Clone(f.csr), bytes.Repeat([]byte("\n"), handoff.MaxFileSize+1-len(f.csr))...)
	if len(over) != handoff.MaxFileSize+1 {
		t.Fatalf("test setup: %d bytes", len(over))
	}
	v, err := newChecker(t).Check(t.Context(), withCSR(f, over))
	wantRefusal(t, v, err, handoff.CodeMalformed, 2)
	if !strings.Contains(v.Detail, "longer than") || !strings.Contains(v.Detail, handoff.FileCSR) {
		t.Errorf("the detail of a file one byte over the limit is %q", v.Detail)
	}
	// The proof file of exactly one byte over the limit says so too, and a request with no proof file says that.
	r := f.request()
	r.Files[handoff.FileProof] = make([]byte, handoff.MaxFileSize+1)
	v, err = newChecker(t).Check(t.Context(), r)
	wantUnreadableVersion(t, v, err)
	if !strings.Contains(v.Detail, "longer than") || !strings.Contains(v.Detail, "proof file") {
		t.Errorf("the detail of a proof file one byte over the limit is %q", v.Detail)
	}
	delete(r.Files, handoff.FileProof)
	v, err = newChecker(t).Check(t.Context(), r)
	wantUnreadableVersion(t, v, err)
	if !strings.Contains(v.Detail, "no proof file") {
		t.Errorf("the detail of a request with no proof file is %q", v.Detail)
	}
	for name, mk := range map[string]func() *handoff.Request{
		"subkey": func() *handoff.Request {
			r := pgpRequest(nil)
			r.Files[handoff.FileSubkey] = make([]byte, handoff.MaxFileSize+1)
			return r
		},
		"ssh key": func() *handoff.Request {
			r := sshRequest(nil)
			r.Files[handoff.FileSSHKey] = make([]byte, handoff.MaxFileSize+1)
			return r
		},
	} {
		v, err := newChecker(t).Check(t.Context(), mk())
		wantRefusal(t, v, err, handoff.CodeMalformed, 2)
		if !strings.Contains(v.Detail, "longer than") {
			t.Errorf("%s: the detail of a file one byte over the limit is %q", name, v.Detail)
		}
	}
}

func TestTheDetailOfEveryRefusalIsPlainTextWhateverTheRequestHolds(t *testing.T) {
	hostile := "\x1b[2J\u202e\u00e4"
	host := uriName("ex\x1bample.org")
	good := goodExtensions(uriName("example.org"))
	// A subject whose value is not printable, written by hand into a request that is otherwise good.
	for name, spec := range map[string]csrSpec{
		"a subject with a control character":  {subject: &pkix.Name{CommonName: "a\x1b[2Jb"}},
		"a subject with a right-to-left mark": {subject: &pkix.Name{CommonName: "a\u202eb"}},
		"a country that is not a country":     {subject: &pkix.Name{Country: []string{hostile}}},
		"a host with a control character":     {exts: goodExtensions(host)},
		"a DNS name with a control character": {exts: goodExtensions(dnsName("ex\x1bample.org"))},
		"a host that is not UTF-8":            {exts: goodExtensions(uriName("ex\xffample.org"))},
		"an extension that is not known":      {exts: append(good[:len(good):len(good)], pkix.Extension{Id: oidSubjectAltName, Value: []byte(hostile)})},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, handoff.StoreSoftware, spec)
			v, err := newChecker(t).Check(t.Context(), f.request())
			if err != nil {
				t.Fatal(err)
			}
			if !v.Refused() {
				t.Fatalf("accepted")
			}
			if !plain(v.Detail) {
				t.Errorf("the detail is not plain text: %q", v.Detail)
			}
		})
	}
	// The same for the proof file: a value that the proof holds is never repeated in the detail raw.
	f := newFixture(t, handoff.StoreSoftware, csrSpec{})
	for _, proof := range []string{
		"{\"handoff\":1,\"type\":\"\x1b[2J\",\"store\":\"\xff\"}",
		"{\"handoff\":1,\"\x1b\":1}",
		"{\"\u202e\":1}",
		"{\"handoff\":\"\x1b\"}",
	} {
		v, err := newChecker(t).Check(t.Context(), withProofBytes(f, []byte(proof)))
		if err != nil || !v.Refused() || !plain(v.Detail) {
			t.Errorf("%q: code %q, detail %q, error %v", proof, v.Code, v.Detail, err)
		}
	}
}

func TestAnEvidenceThatIsMarkedUnprotectedStillHasItsKeyComparedWhenItHasOne(t *testing.T) {
	// Only a software key has nothing to compare. A verifier of a store that gives a key and also says
	// the key is unprotected has its key compared like any other.
	f := newFixture(t, handoff.StorePIV, csrSpec{})
	ev := f.goodEvidence(handoff.StorePIV)
	ev.Unprotected = true
	ev.Key = &newP384(t).PublicKey
	v, err := checkerWith(t, handoff.StorePIV, returning(ev)).Check(t.Context(), f.request())
	wantRefusal(t, v, err, handoff.CodeKeyMismatch, 8)
}

func TestWhatTheCallerDoesToItsFilesWhileTheVerifierRunsHasNoEffectOnTheChecksThatFollow(t *testing.T) {
	// A caller that reuses its buffers while a slow verifier waits: the request was copied at the top of
	// the call, so the later checks read the file as it was.
	f := newFixture(t, handoff.StorePIV, csrSpec{})
	req := f.request()
	sv := &stub{fn: func(context.Context, *handoff.Request, *handoff.Proof, time.Time) (*handoff.Evidence, error) {
		for i := range req.Files[handoff.FileCSR] {
			req.Files[handoff.FileCSR][i] = '!'
		}
		clear(req.Files[handoff.FileProof])
		return f.goodEvidence(handoff.StorePIV), nil
	}}
	v, err := checkerWith(t, handoff.StorePIV, sv).Check(t.Context(), req)
	wantAccepted(t, v, err)
}

func TestARootThatHoldsATypedNilKeyIsAConfigurationFault(t *testing.T) {
	good := newRoot(t, "Example Test Root")
	cfg := defaultConfig(t)
	cfg.Roots = []handoff.RootRef{good.ref(), {Subject: good.subject, Key: (*ecdsa.PublicKey)(nil)}}
	wantConfigError(t, cfg)
}
