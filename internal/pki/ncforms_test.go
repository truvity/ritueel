package pki_test

import (
	"bytes"
	"encoding/asn1"
	"net"
	"testing"
)

func ipSub(n int) []byte { return ncSub(tlv(0x87, make([]byte, n))) }

// Every form of a name constraint that the builder issues, verified by Go and by OpenSSL (strict), and the value in
// the body is the value of the request.
func TestEveryAcceptedFormOfAConstraintIsVerifiedByBoth(t *testing.T) {
	root := buildRoot(t, nil)
	uri := func(s string) []byte { return tlv(0x86, []byte(s)) }
	v4, v6 := ipSub(8), ipSub(32)
	forms := []struct {
		name  string
		value []byte
	}{
		{"one DNS name", ncValue([][]byte{ncSub(dns("example.org"))}, nil)},
		{"a DNS name of one label", ncValue([][]byte{ncSub(dns("internal"))}, nil)},
		{"a URI host", ncValue([][]byte{ncSub(uri("host.example.org"))}, nil)},
		{"a URI domain", ncValue([][]byte{ncSub(uri(".example.org"))}, nil)},
		{"two DNS names", ncValue([][]byte{ncSub(dns("example.org")), ncSub(dns("example.com"))}, nil)},
		{"a DNS name, a URI host and a URI domain", ncValue([][]byte{ncSub(dns("example.org")), ncSub(uri("host.example.net")), ncSub(uri(".example.com"))}, nil)},
		{"the same name twice", ncValue([][]byte{ncSub(dns("example.org")), ncSub(dns("example.org"))}, nil)},
		{"a DNS name with every IP address excluded, IPv4 first", ncValue([][]byte{ncSub(dns("example.org"))}, [][]byte{v4, v6})},
		{"a DNS name with every IP address excluded, IPv6 first", ncValue([][]byte{ncSub(dns("example.org"))}, [][]byte{v6, v4})},
		{"a URI domain with every IP address excluded", ncValue([][]byte{ncSub(uri(".example.org"))}, [][]byte{v4, v6})},
		{"a label of 63 characters", ncValue([][]byte{ncSub(dns(labelOf('a', 63) + ".example.org"))}, nil)},
		{"a name of 253 characters", ncValue([][]byte{ncSub(dns(longName(253)))}, nil)},
		{"a URI domain of 253 characters", ncValue([][]byte{ncSub(uri("." + longName(253)))}, nil)},
		{"a label that starts with a digit", ncValue([][]byte{ncSub(dns("1password.example.org"))}, nil)},
		{"a label with hyphens inside", ncValue([][]byte{ncSub(dns("a-b--c.example.org"))}, nil)},
		{"an internationalised label in its ASCII form", ncValue([][]byte{ncSub(dns("xn--bcher-kva.example"))}, nil)},
		{"fifty DNS names", func() []byte {
			var subs [][]byte
			for i := 0; i < 50; i++ {
				subs = append(subs, ncSub(dns(string(rune('a'+i%26))+string(rune('a'+i/26))+".example.org")))
			}
			return ncValue(subs, nil)
		}()},
	}
	for _, f := range forms {
		t.Run(f.name, func(t *testing.T) {
			csr := ncRequest(t, f.value)
			got := root.issue(t, csr, nil)
			if e := extensionOf(got.parsed, oidNameConstraints); e == nil || !e.Critical || !bytes.Equal(e.Value, f.value) {
				t.Errorf("the name constraints in the body are not the request's, critical")
			}
			verifyEverywhere(t, root, got, true)
		})
	}
}

// The length of the value, of each field and of each subtree crosses the edges of the DER length forms (127 and
// 128, 255 and 256) as the name grows; every size from one to 253 characters is issued, and those at the edges are
// verified by both.
func TestNameConstraintsAtTheEdgesOfTheDERLengthForms(t *testing.T) {
	root := buildRoot(t, nil)
	edges := map[int]bool{127: true, 128: true, 255: true, 256: true}
	hit := map[int]bool{}
	for n := 1; n <= 253; n++ {
		name := longName(n)
		if len(name) != n {
			t.Fatalf("longName(%d) has %d characters", n, len(name))
		}
		value := ncValue([][]byte{ncSub(dns(name))}, nil)
		var outer, field, sub asn1.RawValue
		if _, err := asn1.Unmarshal(value, &outer); err != nil {
			t.Fatal(err)
		}
		if _, err := asn1.Unmarshal(outer.Bytes, &field); err != nil {
			t.Fatal(err)
		}
		if _, err := asn1.Unmarshal(field.Bytes, &sub); err != nil {
			t.Fatal(err)
		}
		atEdge := false
		for _, l := range []int{len(outer.Bytes), len(field.Bytes), len(sub.Bytes), n} {
			if edges[l] {
				atEdge = true
				hit[l] = true
			}
		}
		csr := ncRequest(t, value)
		tbs, err := intermediateTBS(t, root.interParams(csr))
		if err != nil {
			t.Fatalf("a name of %d characters (value of %d octets): %v", n, len(value), err)
		}
		if e := extensionOf(parseBodyOf(t, tbs), oidNameConstraints); e == nil || !bytes.Equal(e.Value, value) {
			t.Fatalf("a name of %d characters: the value in the body is not the request's", n)
		}
		if atEdge {
			verifyEverywhere(t, root, root.issue(t, csr, nil), true)
		}
	}
	if len(hit) != 4 {
		t.Errorf("the sweep reached the edges %v, want 127, 128, 255 and 256", hit)
	}
}

// Excluded subtrees: what the two verifiers do with a leaf that has an address, with and without the exclusion. This
// is why the contract excludes both address spaces: a constraint that names only DNS leaves every address allowed.
func TestExcludedAddressSpacesBindLeavesWithAddresses(t *testing.T) {
	root := buildRoot(t, nil)
	dnsOnly := ncValue([][]byte{ncSub(dns("example.org"))}, nil)
	excluded := ncValue([][]byte{ncSub(dns("example.org"))}, [][]byte{ipSub(8), ipSub(32)})
	for _, ip := range []string{"192.0.2.1", "10.0.0.1", "0.0.0.0", "255.255.255.255", "::1", "2001:db8::1", "::"} {
		t.Run(ip, func(t *testing.T) {
			addr := net.ParseIP(ip)
			if v := leafBelow(t, root, dnsOnly, []string{"www.example.org"}, nil, addr); !v.goOK || !v.sslOK {
				t.Errorf("with no exclusion, Go %v and OpenSSL %v, want both to accept: an address is not constrained", v.goOK, v.sslOK)
			}
			if v := leafBelow(t, root, excluded, []string{"www.example.org"}, nil, addr); v.goOK || v.sslOK {
				t.Errorf("with every address excluded, Go %v and OpenSSL %v, want both to refuse", v.goOK, v.sslOK)
			}
		})
	}
	t.Run("a leaf with no address is not affected", func(t *testing.T) {
		if v := leafBelow(t, root, excluded, []string{"www.example.org"}, nil); !v.goOK || !v.sslOK {
			t.Errorf("Go %v and OpenSSL %v", v.goOK, v.sslOK)
		}
	})
}
