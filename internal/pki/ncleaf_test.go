package pki_test

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/url"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/verifier"
)

// verdicts of the two verifiers on a leaf below an intermediate that has a name constraint.
type leafVerdict struct{ goOK, sslOK bool }

// leafBelow issues an intermediate with the constraint value and a leaf with the given names below it, and returns
// what Go and OpenSSL (strict) say about the chain.
func leafBelow(t *testing.T, root *testRoot, value []byte, dnsNames []string, uris []string, ips ...net.IP) leafVerdict {
	t.Helper()
	csr := ncRequest(t, value)
	inter := root.issue(t, csr, nil)
	at := ceremony.Add(24 * time.Hour)
	var u []*url.URL
	for _, s := range uris {
		p, err := url.Parse(s)
		if err != nil {
			t.Fatal(err)
		}
		u = append(u, p)
	}
	lkey := newKey(t)
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(91), Subject: pkix.Name{CommonName: "leaf"}, DNSNames: dnsNames, URIs: u, IPAddresses: ips,
		NotBefore: ceremony.Add(time.Hour), NotAfter: ceremony.Add(48 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
	}, inter.parsed, &lkey.PublicKey, csr.Key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots, inters := x509.NewCertPool(), x509.NewCertPool()
	roots.AddCert(root.parsed)
	inters.AddCert(inter.parsed)
	_, gerr := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inters, CurrentTime: at, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	serr := verifier.OpenSSLVerify(t, append(pemOf(root.cert), pemOf(inter.cert)...), der, at)
	if gerr != nil {
		t.Logf("   go: %v", gerr)
	}
	if serr != nil {
		t.Logf("   ssl: %.200v", serr)
	}
	return leafVerdict{gerr == nil, serr == nil}
}

// The leaves below a constraint, by the RFC and by the two verifiers. The column rfc is the reading of RFC 5280,
// 4.2.1.10: a DNS constraint holds the name and every name with labels added on its left; a URI constraint without a
// period "specifies a host" (the host itself), a URI constraint with a period holds the hosts that have labels
// added on the left of the domain, and not the domain itself; a URI with an address as its host is never inside; a
// host is compared without regard to case (RFC 3986, 3.2.2).
type leafRow struct {
	name       string
	uri        string
	dns        string
	rfc        bool
	goOK       bool
	sslOK      bool
	difference string
}

func TestLeavesInsideAndOutsideOfEachFormOfAConstraint(t *testing.T) {
	root := buildRoot(t, nil)
	host := ncValue([][]byte{ncSub(tlv(0x86, []byte("host.example.org")))}, nil)
	dom := ncValue([][]byte{ncSub(tlv(0x86, []byte(".example.org")))}, nil)
	dnsc := ncValue([][]byte{ncSub(dns("example.org"))}, nil)
	const goAdmitsSubdomains = "Go reads a URI host constraint as a domain too (it admits the subdomains of the host); RFC 5280 and OpenSSL: only the host"
	groups := []struct {
		form  string
		value []byte
		rows  []leafRow
	}{
		{"a URI host constraint host.example.org", host, []leafRow{
			{"the host", "https://host.example.org/", "", true, true, true, ""},
			{"the host with a port", "https://host.example.org:8443/x", "", true, true, true, ""},
			{"the host with a user", "https://user@host.example.org/", "", true, true, true, ""},
			{"the host in capitals", "https://HOST.EXAMPLE.ORG/", "", true, true, true, ""},
			{"a subdomain of the host", "https://a.host.example.org/", "", false, true, false, goAdmitsSubdomains},
			{"a subdomain of two labels", "https://b.a.host.example.org/", "", false, true, false, goAdmitsSubdomains},
			{"the domain above", "https://example.org/", "", false, false, false, ""},
			{"a host that ends the same, without the period", "https://xhost.example.org/", "", false, false, false, ""},
			{"a sibling", "https://other.example.org/", "", false, false, false, ""},
			{"another domain", "https://other.example.com/", "", false, false, false, ""},
			{"the host and then another domain", "https://host.example.org.evil.com/", "", false, false, false, ""},
			{"an IPv4 address", "https://10.0.0.1/", "", false, false, false, ""},
			{"an IPv6 address", "https://[::1]/", "", false, false, false, ""},
		}},
		{"a URI domain constraint .example.org", dom, []leafRow{
			{"a host below", "https://host.example.org/", "", true, true, true, ""},
			{"a host two labels below", "https://a.host.example.org/", "", true, true, true, ""},
			{"a host that ends the same, without the period", "https://xhost.example.org/", "", true, true, true, ""},
			{"a host below, with a port", "https://host.example.org:8443/x", "", true, true, true, ""},
			{"a host below, in capitals", "https://HOST.EXAMPLE.ORG/", "", true, true, true, ""},
			{"the domain itself", "https://example.org/", "", false, false, false, ""},
			{"a name that ends the same, without the period", "https://notexample.org/", "", false, false, false, ""},
			{"another domain", "https://other.example.com/", "", false, false, false, ""},
			{"the domain and then another domain", "https://host.example.org.evil.com/", "", false, false, false, ""},
			{"an IPv4 address", "https://10.0.0.1/", "", false, false, false, ""},
			{"an IPv6 address", "https://[::1]/", "", false, false, false, ""},
		}},
		{"a DNS constraint example.org, URI names are not its", dnsc, []leafRow{
			{"a URI name of any host", "https://other.example.com/", "", true, true, true, ""},
			{"an IP address as a URI host", "https://10.0.0.1/", "", true, false, true, "Go refuses a URI whose host is an address whenever the issuer has any name constraints (its message: URI with IP cannot be matched against constraints); RFC 5280 constrains only the forms that a constraint names, and OpenSSL agrees"},
		}},
		{"a DNS constraint example.org, DNS names", dnsc, []leafRow{
			{"the name", "", "example.org", true, true, true, ""},
			{"a name below", "", "www.example.org", true, true, true, ""},
			{"a name two labels below", "", "a.b.example.org", true, true, true, ""},
			{"a name that ends the same, without the period", "", "notexample.org", false, false, false, ""},
			{"another domain", "", "example.com", false, false, false, ""},
			{"the domain and then another domain", "", "example.org.evil.com", false, false, false, ""},
			{"the top label alone", "", "org", false, false, false, ""},
		}},
		{"a URI host constraint, DNS names are not its", host, []leafRow{
			{"a DNS name of any domain", "", "other.example.com", true, true, true, ""},
		}},
	}
	differences := 0
	for _, g := range groups {
		for _, r := range g.rows {
			t.Run(g.form+": "+r.name, func(t *testing.T) {
				var names, uris []string
				if r.dns != "" {
					names = []string{r.dns}
				}
				if r.uri != "" {
					uris = []string{r.uri}
				}
				v := leafBelow(t, root, g.value, names, uris)
				if v.goOK != r.goOK || v.sslOK != r.sslOK {
					t.Errorf("Go says %v and OpenSSL says %v, the table has %v and %v", v.goOK, v.sslOK, r.goOK, r.sslOK)
				}
				if (r.goOK != r.rfc || r.sslOK != r.rfc) != (r.difference != "") {
					t.Errorf("rfc=%v go=%v openssl=%v note=%q", r.rfc, r.goOK, r.sslOK, r.difference)
				}
			})
			if r.difference != "" {
				differences++
			}
		}
	}
	if differences != 3 {
		t.Errorf("%d rows where a verifier differs from the RFC, want 3 (Go and a subdomain of a URI host, two rows; Go and an address as a URI host)", differences)
	}
}
