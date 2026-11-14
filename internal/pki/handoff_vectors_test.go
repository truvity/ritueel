package pki_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"slices"
	"sort"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/pki"
	"ritueel.id/ritueel/internal/testrepo"
)

// The requests of the hand-off vectors that are X.509 intermediates, read through the manifest. The manifest says, for every request,
// whether the whole hand-off accepts it, and for a refusal the reason code (the contract's list). What the builder does with the
// bytes of a request is a smaller question than what the hand-off does: the builder reads the request, and the proof, the store, the
// policy of the configuration and the clock are others'. The test therefore asks the manifest, not a list of ids:
//
//   - a request that the manifest accepts is read by ParseRequestFile and by IntermediateTBS, a body is issued, and what is issued
//     is verified by both verifiers; the extended key usage issued is the request's, in its order;
//   - a request that the manifest refuses with the code algorithm-unsupported or possession-invalid is a fact about the bytes
//     (the key, the algorithm, the signature), so the builder alone must see it, and CheckOf must give the manifest's code;
//   - a request that the manifest refuses with the code malformed or policy is either a fact about the bytes, and then the builder
//     refuses it and CheckOf gives the manifest's code, or it is a fact about something else (the proof file, the configuration of the
//     requester), and then the builder accepts the bytes. The second kind is every row where the builder accepts, and each is
//     in the table cannotJudge below with the reason, so a new row of this kind fails the test until it is explained;
//   - a request that the manifest refuses with any other code (proof-invalid, store-not-allowed, declined, key-mismatch, request-mismatch,
//     version-unsupported) is a question that the bytes of the request do not answer, and the builder must accept the bytes.
//
// What the builder refuses is always checked against the manifest: a refusal with another code than the manifest's is a failure, in
// both directions.

// handOffRequest is a row of the manifest that is an X.509 intermediate.
type handOffRequest struct {
	ID     string   `json:"id"`
	Type   string   `json:"type"`
	Expect string   `json:"expect"`
	Reason string   `json:"reason"`
	Files  []string `json:"files"`
}

func handOffX509Requests(t *testing.T) []handOffRequest {
	t.Helper()
	var m struct {
		Requests []handOffRequest `json:"requests"`
	}
	if err := json.Unmarshal(testrepo.Read(t, "testdata", "hand-off", "v1", "manifest.json"), &m); err != nil {
		t.Fatal(err)
	}
	var out []handOffRequest
	for _, r := range m.Requests {
		if r.Type == "x509-intermediate" {
			out = append(out, r)
		}
	}
	return out
}

// cannotJudge are the requests that the manifest refuses with the code malformed or policy and the builder accepts, with the reason.
// The reason is read from the manifest and from the files of the row: the request is a good request in every one of them.
var cannotJudge = map[string]string{
	"x509-unknown-member":          "the fault is a member of the proof file that the contract does not know: the request is the request of the valid software row",
	"x509-piv-pin-never":           "the fault is in the attestation of the proof (the PIN policy of the card); the request is an ordinary request",
	"x509-piv-old-firmware":        "the fault is in the attestation of the proof (the firmware of the card); the request is an ordinary request",
	"x509-name-constraint-outside": "the permitted URI host is outside the subtrees that the policy of the requester lists: that list is in the configuration, not in the request",
	"x509-kms-two-actors":          "the fault is in the proof (the same actor as requester and approver): the request is an ordinary request",
}

// builderCodes are the reason codes that name a check that this package makes.
var builderCodes = map[string]bool{"malformed": true, "algorithm-unsupported": true, "possession-invalid": true, "policy": true}

// The roots of the vectors: the roots on the pinned root list of the manifest (A and B). The first is the issuer that a request is read
// against; all of them are the roots of the bundle, so that the rules that name a root (the key of the request is the key of a root, the
// subject of the request is the name of a root) can be seen by the builder for root B as well as for root A.
func vectorRoots(t *testing.T) []pki.RootRef {
	t.Helper()
	var m struct {
		Pinned struct {
			RootList struct {
				X509 []string `json:"x509"`
			} `json:"root_list"`
		} `json:"pinned"`
	}
	if err := json.Unmarshal(testrepo.Read(t, "testdata", "hand-off", "v1", "manifest.json"), &m); err != nil {
		t.Fatal(err)
	}
	if len(m.Pinned.RootList.X509) < 2 {
		t.Fatalf("the pinned root list has %d X.509 roots, want at least 2 (A and B)", len(m.Pinned.RootList.X509))
	}
	var out []pki.RootRef
	for _, f := range m.Pinned.RootList.X509 {
		cert, err := x509.ParseCertificate(pemBlock(t, testrepo.Read(t, "testdata", "hand-off", "v1", f), "CERTIFICATE"))
		if err != nil {
			t.Fatal(err)
		}
		k, ok := cert.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			t.Fatalf("the vector root %s has no ECDSA key", f)
		}
		out = append(out, pki.RootRef{Subject: cert.RawSubject, Key: k})
	}
	return out
}

func TestHandOffRequestsAreReadByTheBuilder(t *testing.T) {
	reqs := handOffX509Requests(t)
	if len(reqs) < 50 {
		t.Fatalf("the manifest has %d X.509 intermediate requests", len(reqs))
	}
	roots := vectorRoots(t)
	root := buildRoot(t, nil)
	byOutcome := map[string]int{}
	var unjudged []string
	for _, r := range reqs {
		t.Run(r.ID, func(t *testing.T) {
			if len(r.Files) == 0 || !strings.HasSuffix(r.Files[0], ".csr.pem") {
				t.Fatalf("the first file of %s is %v", r.ID, r.Files)
			}
			file := testrepo.Read(t, "testdata", "hand-off", "v1", r.Files[0])
			block, rest := pem.Decode(file)
			if block == nil || block.Type != "CERTIFICATE REQUEST" || len(bytes.TrimSpace(rest)) != 0 {
				// The file is not one block and nothing else: only the readers of a file judge it (the request inside is a good request).
				req, err := pki.ParseRequestFile(file)
				key, kerr := pki.RequestKeyFile(file)
				if r.Expect != "refuse" || r.Reason != "malformed" {
					t.Fatalf("the file of %s is not one block, and the manifest says %s %s", r.ID, r.Expect, r.Reason)
				}
				if req != nil || key != nil || pki.CheckOf(err) != pki.CheckMalformed || pki.CheckOf(kerr) != pki.CheckMalformed || err.Error() != kerr.Error() {
					t.Errorf("a file that is not one block: ParseRequestFile %v (%q), RequestKeyFile %v (%q)", err, pki.CheckOf(err), kerr, pki.CheckOf(kerr))
				}
				byOutcome["refused by the readers of a file, which are not one block (malformed)"]++
				return
			}
			der := block.Bytes
			params := pki.IntermediateParams{CSR: der, IssuerSubject: roots[0].Subject, IssuerKey: roots[0].Key, Roots: roots, CeremonyTime: ceremony, Serial: aSerial}

			// The three readers of the same bytes agree.
			reqFile, errFile := pki.ParseRequestFile(file)
			reqDER, errDER := pki.ParseRequest(der)
			key, keyErr := pki.RequestKey(der)
			fileKey, fileKeyErr := pki.RequestKeyFile(file)
			if (reqDER != nil) != (errDER == nil) || (reqFile != nil) != (errFile == nil) {
				t.Fatalf("a request with an error, or none without: %v / %v, %v / %v", reqDER != nil, errDER, reqFile != nil, errFile)
			}
			// RequestKey stops at checks 2, 4 and 5: it agrees with ParseRequest on those three, and gives the key when the content is all
			// that is wrong.
			switch c := pki.CheckOf(errDER); c {
			case pki.CheckNone, pki.CheckPolicy:
				if keyErr != nil || fileKeyErr != nil || key == nil || !key.Equal(fileKey) {
					t.Fatalf("RequestKey: %v, %v; RequestKeyFile: %v, %v", key, keyErr, fileKey, fileKeyErr)
				}
			default:
				if key != nil || fileKey != nil || pki.CheckOf(keyErr) != c || pki.CheckOf(fileKeyErr) != c {
					t.Fatalf("RequestKey: %v, %v (%q); RequestKeyFile: %v, %v; ParseRequest says %q", key, keyErr, pki.CheckOf(keyErr), fileKey, fileKeyErr, c)
				}
			}
			_, errTBS := pki.IntermediateTBS(params)
			if (errFile == nil) != (errDER == nil) || pki.CheckOf(errFile) != pki.CheckOf(errDER) {
				t.Fatalf("ParseRequestFile says %v and ParseRequest says %v", errFile, errDER)
			}
			// A request that ParseRequest reads can still be refused by IntermediateTBS, for the rules that name a root: the key of the request
			// is the key of the issuer or of a root of the bundle, the subject of the request is the name of one.
			if errDER == nil && errTBS != nil && !strings.Contains(errTBS.Error(), "of the issuer") && !strings.Contains(errTBS.Error(), "of a root of the bundle") {
				t.Fatalf("IntermediateTBS refuses a request that is read, for another reason than the issuer's: %v", errTBS)
			}
			builder := errDER
			if builder == nil {
				builder = errTBS
			}

			switch {
			case r.Expect == "accept":
				byOutcome["accepted"]++
				if errTBS != nil {
					t.Fatalf("IntermediateTBS refuses the request of an accepted row: %v", errTBS)
				}
				if reqFile.Subject() == nil || reqDER.Subject() == nil || string(reqFile.DER()) != string(der) {
					t.Error("the request that is read is not the request of the file")
				}
				if !key.Equal(reqDER.PublicKey()) {
					t.Error("RequestKey and the request that ParseRequest reads have two keys")
				}
				got := root.issue(t, &testCSR{Fixed: der}, nil)
				verifyEverywhere(t, root, got, true)
				// The request that is checked is the request that is issued: the subject and the extended key usage come out as they went in.
				if string(got.parsed.RawSubject) != string(reqDER.Subject()) {
					t.Error("the subject issued is not the subject of the request")
				}
				var asked []byte
				for _, e := range reqDER.Extensions() {
					if e.Id.Equal(oidExtKeyUsage) {
						asked = e.Value
						if e.Critical {
							t.Error("the request that was accepted has a critical extended key usage")
						}
					}
				}
				issuedEKU := extensionOf(got.parsed, oidExtKeyUsage)
				if asked == nil || issuedEKU == nil || issuedEKU.Critical || string(issuedEKU.Value) != string(asked) {
					t.Errorf("the extended key usage issued is %+v, the request's value is %x", issuedEKU, asked)
				}
			case builder == nil:
				// The builder accepts the bytes of a request that the manifest refuses.
				switch {
				case r.Reason == "algorithm-unsupported" || r.Reason == "possession-invalid":
					t.Errorf("the manifest refuses with %q, a fact about the bytes, and the builder accepts them", r.Reason)
				case builderCodes[r.Reason]:
					if _, known := cannotJudge[r.ID]; !known {
						t.Errorf("the builder accepts a request that the manifest refuses with %q, and the row is not in cannotJudge", r.Reason)
					}
					unjudged = append(unjudged, r.ID)
					byOutcome["refused for a fact that is not in the request ("+r.Reason+")"]++
				default:
					byOutcome["refused for a question of the bytes' neighbours ("+r.Reason+")"]++
				}
			default:
				// The builder refuses the bytes: it must be for the manifest's reason, with the manifest's code.
				refused(t, builder, pki.ErrRequest)
				if !builderCodes[r.Reason] {
					t.Errorf("the manifest refuses with %q, which is not a question of the bytes, and the builder refuses them: %v", r.Reason, builder)
				}
				if got := pki.CheckOf(builder).Code(); got != r.Reason {
					t.Errorf("CheckOf says %q, the manifest says %q: %v", got, r.Reason, builder)
				}
				if errDER == nil {
					byOutcome["refused by IntermediateTBS, for the issuer ("+r.Reason+")"]++
					return
				}
				byOutcome["refused by the builder ("+r.Reason+")"]++
				// No request comes with an error; a request refused for its content (policy) has its key from RequestKey, and any other check has
				// none (checked above).
				if r.Reason == "policy" {
					assertRefusedForContent(t, reqDER, der)
					assertRefusedForContent(t, reqFile, der)
				} else if reqDER != nil || reqFile != nil {
					t.Errorf("a request came with the %q refusal", r.Reason)
				}
				// The same bytes are refused by IntermediateTBS with the same code.
				refused(t, errTBS, pki.ErrRequest)
				if got := pki.CheckOf(errTBS); got != pki.CheckOf(errDER) {
					t.Errorf("IntermediateTBS says %q, ParseRequest says %q", got, pki.CheckOf(errDER))
				}
			}
		})
	}
	// Every row where the builder cannot judge is explained, and every explained row is still one that the builder cannot judge.
	sort.Strings(unjudged)
	var table []string
	for id := range cannotJudge {
		table = append(table, id)
	}
	sort.Strings(table)
	if !slices.Equal(unjudged, table) {
		t.Errorf("the rows that the builder accepts and the manifest refuses with a builder code are %v, the table cannotJudge has %v", unjudged, table)
	}
	keys := make([]string, 0, len(byOutcome))
	for k := range byOutcome {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		t.Logf("%3d  %s", byOutcome[k], k)
	}
	if byOutcome["accepted"] < 10 {
		t.Errorf("only %d accepted rows", byOutcome["accepted"])
	}
	// Every row of the manifest fell in one of the outcomes, and every accepted row of the manifest is one of the accepted outcomes.
	total, wantAccepted := 0, 0
	for _, n := range byOutcome {
		total += n
	}
	for _, r := range reqs {
		if r.Expect == "accept" {
			wantAccepted++
		}
	}
	if total != len(reqs) || byOutcome["accepted"] != wantAccepted {
		t.Errorf("%d rows in the manifest, %d outcomes; %d rows accepted by the manifest, %d accepted by the builder", len(reqs), total, wantAccepted, byOutcome["accepted"])
	}
	if byOutcome["refused by the readers of a file, which are not one block (malformed)"] < 2 {
		t.Errorf("the manifest has fewer than two files that are not one block (the block twice, text after the block)")
	}
}

// Every code that the manifest names for a request is a code of the contract's list, and every code that the builder can give is
// in the manifest at least once: the vectors cover the four checks.
func TestTheVectorsCoverEveryCheckTheBuilderMakes(t *testing.T) {
	seen := map[string]int{}
	for _, r := range handOffX509Requests(t) {
		if r.Expect == "refuse" {
			seen[r.Reason]++
		}
	}
	for code := range builderCodes {
		if seen[code] == 0 {
			t.Errorf("no vector refuses with %q", code)
		}
	}
	for _, c := range []pki.Check{pki.CheckMalformed, pki.CheckAlgorithm, pki.CheckPossession, pki.CheckPolicy} {
		if !builderCodes[c.Code()] {
			t.Errorf("the check %v has the code %q, which is not a reason code of the manifest", int(c), c.Code())
		}
	}
	t.Log(fmt.Sprint(seen))
}
