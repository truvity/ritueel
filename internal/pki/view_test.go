package pki_test

import (
	"bytes"
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"

	"ritueel.id/ritueel/internal/pki"
)

// The view of a request: ParseRequest reads everything about a request that needs no issuer, so what it shows is what is
// issued. The comparison with the body, for every valid request of the tests, is intermediateTBS in helpers_test.go; these
// are the shapes of the view, its copies, the order of the refusals, and the name constraints that are required.

func TestTheViewShowsTheSubjectAndTheNameConstraintsRead(t *testing.T) {
	ou := mustOID(asn1.ObjectIdentifier{2, 5, 4, 11})
	oidOU := asn1.ObjectIdentifier{2, 5, 4, 11}
	subject := nameOf(
		rdn(atv(oidAttrO, str(tUTF8, "acme"))),
		rdn(atv(ou, str(tUTF8, "ops"))),
		rdn(atv(ou, str(tPrintable, "build team"))),
		rdn(atv(oidAttrCN, str(tUTF8, "acme example ca")), atv(oidAttrC, str(tPrintable, "NL"))),
	)
	uri := func(s string) []byte { return tlv(0x86, []byte(s)) }
	v4, v6 := ipSub(8), ipSub(32)
	rows := []struct {
		name       string
		value      []byte
		dns, uris  []string
		excludesIP bool
	}{
		{"one DNS name", ncValue([][]byte{ncSub(dns("example.org"))}, nil), []string{"example.org"}, nil, false},
		{"one URI host", ncValue([][]byte{ncSub(uri("host.example.org"))}, nil), nil, []string{"host.example.org"}, false},
		{"one URI domain", ncValue([][]byte{ncSub(uri(".example.org"))}, nil), nil, []string{".example.org"}, false},
		{"all three, in the order of the request", ncValue([][]byte{ncSub(uri(".b.example")), ncSub(dns("z.example")), ncSub(dns("a.example")), ncSub(uri("h.example"))}, nil),
			[]string{"z.example", "a.example"}, []string{".b.example", "h.example"}, false},
		{"both ranges, IPv4 first", ncValue([][]byte{ncSub(dns("example.org"))}, [][]byte{v4, v6}), []string{"example.org"}, nil, true},
		{"both ranges, IPv6 first", ncValue([][]byte{ncSub(dns("example.org"))}, [][]byte{v6, v4}), []string{"example.org"}, nil, true},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			csr := withExtensions(t, extBasicConstraints(), extKeyUsage(kuKeyCertSign, kuCRLSign), pkix.Extension{Id: oidNameConstraints, Critical: true, Value: r.value})
			csr.RawSubject = subject
			req, err := pki.ParseRequest(csr.DER())
			if err != nil {
				t.Fatal(err)
			}
			nc := req.NameConstraints()
			if !equalStrings(nc.PermittedDNS, r.dns) || !equalStrings(nc.PermittedURI, r.uris) || nc.ExcludesAllIP != r.excludesIP {
				t.Errorf("NameConstraints = %+v, want DNS %v, URI %v, excludes %v", nc, r.dns, r.uris, r.excludesIP)
			}
			want := [][]pki.NameAttribute{
				{{Type: asn1.ObjectIdentifier{2, 5, 4, 10}, Value: "acme"}},
				{{Type: oidOU, Value: "ops"}},
				{{Type: oidOU, Value: "build team"}},
			}
			got := req.SubjectName()
			if len(got) != 4 {
				t.Fatalf("%d relative names, want 4: %+v", len(got), got)
			}
			for i := 0; i < 3; i++ {
				if len(got[i]) != 1 || !got[i][0].Type.Equal(want[i][0].Type) || got[i][0].Value != want[i][0].Value {
					t.Errorf("relative name %d = %+v, want %+v", i, got[i], want[i])
				}
			}
			// The last relative name has two attributes, in DER order (the shorter encoding first): the country (2.5.4.6) and the
			// common name (2.5.4.3).
			if len(got[3]) != 2 || !got[3][0].Type.Equal(asn1.ObjectIdentifier{2, 5, 4, 6}) || got[3][0].Value != "NL" ||
				!got[3][1].Type.Equal(asn1.ObjectIdentifier{2, 5, 4, 3}) || got[3][1].Value != "acme example ca" {
				t.Errorf("the last relative name = %+v", got[3])
			}
			if !bytes.Equal(req.Subject(), subject) {
				t.Error("the subject DER is not the one of the request")
			}
		})
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Every method of the view returns a copy: a caller that changes what it got does not change the view.
func TestTheViewReturnsCopiesOfEverything(t *testing.T) {
	csr := goodRequest(t)
	req, err := pki.ParseRequest(csr.DER())
	if err != nil {
		t.Fatal(err)
	}
	der, subject, name, nc, exts := req.DER(), req.Subject(), req.SubjectName(), req.NameConstraints(), req.Extensions()
	for i := range der {
		der[i] ^= 0xff
	}
	for i := range subject {
		subject[i] ^= 0xff
	}
	name[0][0].Value = "changed"
	name[0][0].Type[0] = 99
	name[0] = append(name[0], pki.NameAttribute{Value: "more"})
	nc.PermittedDNS[0] = "changed.example"
	nc.PermittedDNS = append(nc.PermittedDNS, "more.example")
	for i := range exts {
		exts[i].Value[0] ^= 0xff
		exts[i].Id[0] = 99
	}
	if !bytes.Equal(req.Subject(), csr.RawSubject) {
		t.Error("the subject changed with a copy")
	}
	if got := req.SubjectName(); got[0][0].Value == "changed" || got[0][0].Type[0] == 99 || len(got[0]) != 1 {
		t.Errorf("the subject read changed with a copy: %+v", got)
	}
	if got := req.NameConstraints(); len(got.PermittedDNS) != 1 || got.PermittedDNS[0] != "example.org" {
		t.Errorf("the name constraints changed with a copy: %+v", got)
	}
	for i, e := range req.Extensions() {
		if e.Id[0] == 99 || !e.Id.Equal(csr.Extensions[i].Id) || !bytes.Equal(e.Value, csr.Extensions[i].Value) {
			t.Errorf("extension %d changed with a copy", i)
		}
	}
	if _, err := pki.ParseRequest(req.DER()); err != nil {
		t.Errorf("the request DER of the view does not read again: %v", err)
	}
	var none *pki.Request
	if none.SubjectName() != nil || none.NameConstraints().ExcludesAllIP || none.NameConstraints().PermittedDNS != nil {
		t.Error("the view of nothing is something")
	}
}

// The order of the refusals: a request that fails its own signature and its content is refused for the signature; one that is
// signed with another algorithm and has bad content, for the algorithm; and of two faults of content, the subject comes first.
func TestTheOrderOfTheRefusalsOfARequest(t *testing.T) {
	badSubject := cnName(tUTF8, "bad name") // a no-break space
	badNC := pkix.Extension{Id: oidNameConstraints, Critical: true, Value: ncValue([][]byte{ncSub(dns("Example.ORG"))}, nil)}
	mk := func(edit func(c *testCSR)) *testCSR {
		c := withExtensions(t, extBasicConstraints(), extKeyUsage(kuKeyCertSign), badNC)
		c.RawSubject = badSubject
		edit(c)
		return c
	}
	rows := []struct {
		name  string
		c     *testCSR
		words string
		check pki.Check
	}{
		{"a content fault only: the subject first", mk(func(*testCSR) {}), "outside printable ASCII", pki.CheckPolicy},
		{"a signature that does not verify, and bad content", mk(func(c *testCSR) {
			c.SignatureEdit = func(s []byte) []byte { s[len(s)-1] ^= 1; return s }
		}), "does not verify", pki.CheckPossession},
		{"a signature of another key, and bad content", mk(func(c *testCSR) {
			other := newKey(t)
			c.Digest = 0
			c.SignatureEdit = func([]byte) []byte { return rawSign(t, other, []byte("x")) }
		}), "does not verify", pki.CheckPossession},
		{"the algorithm of SHA-256, and bad content", mk(func(c *testCSR) { c.Algorithm = algDER(0x02) }), "ecdsa-with-SHA384", pki.CheckPossession},
		{"the version 1, and bad content", mk(func(c *testCSR) { c.Version = []byte{0x02, 0x01, 0x01} }), "version", pki.CheckMalformed},
		{"the subject, and then the extensions", mk(func(*testCSR) {}), "subject of the request", pki.CheckPolicy},
		{"a good subject and bad name constraints", func() *testCSR {
			c := mk(func(*testCSR) {})
			c.RawSubject = goodSubject()
			return c
		}(), "DNS name constraint", pki.CheckPolicy},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			_, err := pki.ParseRequest(r.c.DER())
			refusedSaying(t, err, pki.ErrRequest, r.words)
			if got := pki.CheckOf(err); got != r.check {
				t.Errorf("check %q, want %q", got, r.check)
			}
		})
	}
}

// Name constraints are required: absent, only excluded, and permitted present.
func TestNameConstraintsAreRequired(t *testing.T) {
	v4, v6 := ipSub(8), ipSub(32)
	rows := []struct {
		name  string
		exts  []pkix.Extension
		ok    bool
		words string
	}{
		{"absent", []pkix.Extension{extBasicConstraints(), extKeyUsage(kuKeyCertSign, kuCRLSign)}, false, "no name constraints"},
		{"absent, with an extended key usage", []pkix.Extension{extBasicConstraints(), extKeyUsage(kuKeyCertSign), extExtKeyUsage(false, oidServerAuth)}, false, "no name constraints"},
		{"only both excluded ranges", []pkix.Extension{extBasicConstraints(), extKeyUsage(kuKeyCertSign), {Id: oidNameConstraints, Critical: true, Value: ncValue(nil, [][]byte{v4, v6})}}, false, "no permitted subtree"},
		{"only one excluded range", []pkix.Extension{extBasicConstraints(), extKeyUsage(kuKeyCertSign), {Id: oidNameConstraints, Critical: true, Value: ncValue(nil, [][]byte{v4})}}, false, "no permitted subtree"},
		{"an empty permitted list", []pkix.Extension{extBasicConstraints(), extKeyUsage(kuKeyCertSign), {Id: oidNameConstraints, Critical: true, Value: ncValue([][]byte{}, nil)}}, false, "empty"},
		{"permitted present", []pkix.Extension{extBasicConstraints(), extKeyUsage(kuKeyCertSign), extNameConstraints("example.org")}, true, ""},
		{"permitted and both excluded", []pkix.Extension{extBasicConstraints(), extKeyUsage(kuKeyCertSign), {Id: oidNameConstraints, Critical: true, Value: ncValue([][]byte{ncSub(dns("example.org"))}, [][]byte{v4, v6})}}, true, ""},
		{"present but not critical", []pkix.Extension{extBasicConstraints(), extKeyUsage(kuKeyCertSign), {Id: oidNameConstraints, Critical: false, Value: ncValue([][]byte{ncSub(dns("example.org"))}, nil)}}, false, "not critical"},
	}
	root := buildRoot(t, nil)
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			csr := withExtensions(t, r.exts...)
			der := csr.DER()
			req, err := pki.ParseRequest(der)
			tbs, ierr := intermediateTBS(t, root.interParams(csr))
			if r.ok {
				if err != nil || ierr != nil {
					t.Fatalf("refused: %v, %v", err, ierr)
				}
				if req == nil || tbs == nil {
					t.Error("nothing came")
				}
				return
			}
			refusedSaying(t, err, pki.ErrRequest, r.words)
			refusedSaying(t, ierr, pki.ErrRequest, r.words)
			if got := pki.CheckOf(err); got != pki.CheckPolicy {
				t.Errorf("check %q, want policy", got)
			}
			assertRefusedForContent(t, req, der)
			if tbs != nil {
				t.Error("a body came with the error")
			}
		})
	}
}
