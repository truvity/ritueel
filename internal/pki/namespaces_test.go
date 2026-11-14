package pki_test

import (
	"encoding/asn1"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/pki"
)

// Spaces in a value of the subject: none at the start, none at the end, never two in a row. Only the ASCII space
// is a space that a subject may hold: the other spaces of Unicode (category Zs) and a tab are outside printable ASCII, which is
// the rule of the characters, so they are refused with the words of that rule.
func TestSpacesInAValueOfTheSubject(t *testing.T) {
	root := buildRoot(t, nil)
	nbsp, ideographic := " ", "　"
	type row struct {
		text  string
		tag   byte
		oid   []byte
		ok    bool
		words string
	}
	rows := []row{
		{"acme root", tUTF8, oidAttrCN, true, ""},
		{"a b c d e f", tUTF8, oidAttrCN, true, ""},
		{"a", tUTF8, oidAttrCN, true, ""},
		{" acme", tUTF8, oidAttrCN, false, "space at its start"},
		{"acme ", tUTF8, oidAttrCN, false, "space at its start or its end"},
		{" ", tUTF8, oidAttrCN, false, "space at its start"},
		{"  ", tUTF8, oidAttrCN, false, "space"},
		{"acme  root", tUTF8, oidAttrCN, false, "two spaces in a row"},
		{"acme   root", tUTF8, oidAttrCN, false, "two spaces in a row"},
		{"a  ", tUTF8, oidAttrCN, false, "space"},
		{"  a", tUTF8, oidAttrCN, false, "space"},
		{"a b  c", tUTF8, oidAttrCN, false, "two spaces in a row"},
		{"a b c  ", tUTF8, oidAttrCN, false, "space"},
		{"acme" + nbsp + "root", tUTF8, oidAttrCN, false, "outside printable ASCII"},
		{"acme " + nbsp + "root", tUTF8, oidAttrCN, false, "outside printable ASCII"},
		{"acme" + nbsp + " root", tUTF8, oidAttrCN, false, "outside printable ASCII"},
		{nbsp + "acme", tUTF8, oidAttrCN, false, "outside printable ASCII"},
		{"acme" + nbsp, tUTF8, oidAttrCN, false, "outside printable ASCII"},
		{ideographic + "acme" + ideographic, tUTF8, oidAttrCN, false, "outside printable ASCII"},
		{"acme" + ideographic + ideographic + "root", tUTF8, oidAttrCN, false, "outside printable ASCII"},
		{"acme\troot", tUTF8, oidAttrCN, false, "outside printable ASCII"},
		{" acme", tPrintable, oidAttrCN, false, "space"},
		{"acme ", tPrintable, oidAttrCN, false, "space"},
		{"acme  root", tPrintable, oidAttrCN, false, "two spaces"},
		{"acme root", tPrintable, oidAttrCN, true, ""},
		{" acme", tUTF8, oidAttrO, false, "space"},
		{"acme ", tUTF8, oidAttrO, false, "space"},
		{"acme  corp", tUTF8, oidAttrO, false, "two spaces"},
		{"acme corp", tUTF8, oidAttrO, true, ""},
		{"ex ample", tIA5, oidAttrDC, true, ""},
		{" example", tIA5, oidAttrDC, false, "space"},
		{"example ", tIA5, oidAttrDC, false, "space"},
		{"ex  ample", tIA5, oidAttrDC, false, "two spaces"},
		{" N", tPrintable, oidAttrC, false, "space"},
		{"N ", tPrintable, oidAttrC, false, "space"},
	}
	for _, r := range rows {
		t.Run(r.text+"|"+string(rune('0'+r.tag%10))+"|"+oidName(r.oid), func(t *testing.T) {
			// The attribute alone, and the attribute beside a common name.
			cn := atv(oidAttrCN, str(tUTF8, "ca"))
			subjects := [][]byte{nameOf(rdn(atv(r.oid, str(r.tag, r.text))))}
			if string(r.oid) != string(oidAttrCN) {
				subjects = append(subjects, nameOf(rdn(atv(r.oid, str(r.tag, r.text))), rdn(cn)))
			}
			for _, subject := range subjects {
				csr := copyCSR(withExtensions(t, goodExtensions()...))
				csr.RawSubject = subject
				tbs, err := intermediateTBS(t, root.interParams(csr))
				if r.ok {
					if err != nil {
						// A value that is outside the SIZE of its type is another rule: C has two characters.
						if string(r.oid) == string(oidAttrC) {
							return
						}
						t.Fatalf("refused: %v", err)
					}
					return
				}
				refused(t, err, pki.ErrRequest)
				if tbs != nil {
					t.Error("a body came with the error")
				}
				if err != nil && !strings.Contains(err.Error(), r.words) && !strings.Contains(err.Error(), "SIZE") {
					t.Errorf("the text does not say %q: %q", r.words, err.Error())
				}
			}
		})
	}
	// The issuer is held to the same text rule as the subject (a root's name is ASCII with single spaces), so the spaces
	// that a subject may not hold are refused in it too, as a parameter of the caller, with no check of the contract.
	for _, c := range []struct{ name, text, words string }{
		{"an issuer with spaces at both ends and two in a row", " acme  root ", "space at its start or its end"},
		{"an issuer with two spaces in a row", "acme  root", "two spaces in a row"},
		{"an issuer with a space at its end", "acme root ", "space at its start or its end"},
		{"an issuer with a control character and a mark that changes the direction of text", "acme\u202eroot\x01", "outside printable ASCII"},
		{"an issuer with a no-break space", "acme\u00a0root", "outside printable ASCII"},
	} {
		t.Run(c.name, func(t *testing.T) {
			p := root.interParams(withExtensions(t, goodExtensions()...))
			p.IssuerSubject = cnName(tUTF8, c.text)
			_, err := intermediateTBS(t, p)
			refusedSaying(t, err, pki.ErrParams, c.words)
			if got := pki.CheckOf(err); got != pki.CheckNone {
				t.Errorf("check %q, want none", got)
			}
		})
	}
}

func oidName(oid []byte) string {
	var o asn1.ObjectIdentifier
	if _, err := asn1.Unmarshal(oid, &o); err != nil {
		return "?"
	}
	return o.String()
}

// An attribute type stands once in a subject, except the organisational unit and the domain component. Every type of
// RFC 5280, Appendix A.1, and one that is not in it, twice in the same relative name and in two relative names, and
// three times where it may repeat.
func TestRepeatedAttributeTypesInTheSubject(t *testing.T) {
	root := buildRoot(t, nil)
	o := func(ints ...int) []byte { return mustOID(asn1.ObjectIdentifier(ints)) }
	types := []struct {
		name   string
		oid    []byte
		tag    byte
		a, b   string
		repeat bool
	}{
		{"commonName", o(2, 5, 4, 3), tUTF8, "one", "two", false},
		{"surname", o(2, 5, 4, 4), tUTF8, "one", "two", false},
		{"serialNumber", o(2, 5, 4, 5), tPrintable, "one", "two", false},
		{"countryName", o(2, 5, 4, 6), tPrintable, "NL", "DE", false},
		{"localityName", o(2, 5, 4, 7), tUTF8, "one", "two", false},
		{"stateOrProvinceName", o(2, 5, 4, 8), tUTF8, "one", "two", false},
		{"streetAddress", o(2, 5, 4, 9), tUTF8, "one", "two", false},
		{"organizationName", o(2, 5, 4, 10), tUTF8, "one", "two", false},
		{"organizationalUnitName", o(2, 5, 4, 11), tUTF8, "one", "two", true},
		{"title", o(2, 5, 4, 12), tUTF8, "one", "two", false},
		{"name", o(2, 5, 4, 41), tUTF8, "one", "two", false},
		{"givenName", o(2, 5, 4, 42), tUTF8, "one", "two", false},
		{"initials", o(2, 5, 4, 43), tUTF8, "one", "two", false},
		{"generationQualifier", o(2, 5, 4, 44), tUTF8, "one", "two", false},
		{"dnQualifier", o(2, 5, 4, 46), tPrintable, "one", "two", false},
		{"pseudonym", o(2, 5, 4, 65), tUTF8, "one", "two", false},
		{"domainComponent", o(0, 9, 2342, 19200300, 100, 1, 25), tIA5, "one", "two", true},
		{"emailAddress", o(1, 2, 840, 113549, 1, 9, 1), tIA5, "a@example.org", "b@example.org", false},
		{"an attribute that RFC 5280 does not list", o(1, 3, 6, 1, 4, 1, 99999, 5), tUTF8, "one", "two", false},
	}
	cn := rdn(atv(oidAttrCN, str(tUTF8, "ca")))
	for _, ty := range types {
		a := atv(ty.oid, str(ty.tag, ty.a))
		b := atv(ty.oid, str(ty.tag, ty.b))
		cases := []struct {
			where string
			name  []byte
			twice bool // the type is there twice
			one   bool // in one relative name: X.501 asks for distinct types there, for every type
		}{
			{"once", nameOf(rdn(a), cn), false, false},
			{"twice in two relative names", nameOf(rdn(a), rdn(b), cn), true, false},
			{"twice in one relative name", nameOf(rdn(a, b), cn), true, true},
			{"the same value twice in one relative name", nameOf(rdn(a, a), cn), true, true},
			{"twice, with the common name between", nameOf(rdn(a), cn, rdn(b)), true, false},
			{"the same value twice", nameOf(rdn(a), rdn(a), cn), true, false},
			{"three times in three relative names", nameOf(rdn(a), rdn(b), rdn(a), cn), true, false},
			{"twice in one relative name and once more in another", nameOf(rdn(a, b), rdn(a), cn), true, true},
		}
		for _, c := range cases {
			if string(ty.oid) == string(oidAttrCN) && c.where != "once" {
				// The common name is in the name already: it is in the table twice below.
				c.name = nameOf(rdn(atv(oidAttrCN, str(tUTF8, "one"))), rdn(atv(oidAttrCN, str(tUTF8, "two"))))
				if c.one {
					c.name = nameOf(rdn(atv(oidAttrCN, str(tUTF8, "one")), atv(oidAttrCN, str(tUTF8, "two"))))
				}
			}
			if string(ty.oid) == string(oidAttrCN) && c.where == "once" {
				c.name = nameOf(cn)
			}
			t.Run(ty.name+" "+c.where, func(t *testing.T) {
				csr := copyCSR(withExtensions(t, goodExtensions()...))
				csr.RawSubject = c.name
				tbs, err := intermediateTBS(t, root.interParams(csr))
				want := !c.twice || (ty.repeat && !c.one)
				if want {
					if err != nil {
						t.Fatalf("refused: %v", err)
					}
					return
				}
				refused(t, err, pki.ErrRequest)
				if tbs != nil {
					t.Error("a body came with the error")
				}
				words := "more than once"
				if c.one {
					words = "in one relative name"
				}
				if err != nil && !strings.Contains(err.Error(), words) {
					t.Errorf("the text does not say %q: %q", words, err.Error())
				}
			})
		}
	}
	// Three of the types that repeat, and the two that repeat together.
	t.Run("many domain components", func(t *testing.T) {
		var rdns [][]byte
		for _, l := range []string{"org", "example", "corp", "eu", "a", "b"} {
			rdns = append(rdns, rdn(atv(oidAttrDC, str(tIA5, l))))
		}
		csr := copyCSR(withExtensions(t, goodExtensions()...))
		csr.RawSubject = nameOf(append(rdns, cn)...)
		if _, err := intermediateTBS(t, root.interParams(csr)); err != nil {
			t.Error(err)
		}
	})
	t.Run("units and components together", func(t *testing.T) {
		ou := o(2, 5, 4, 11)
		csr := copyCSR(withExtensions(t, goodExtensions()...))
		csr.RawSubject = nameOf(rdn(atv(oidAttrDC, str(tIA5, "org"))), rdn(atv(oidAttrDC, str(tIA5, "example"))), rdn(atv(ou, str(tUTF8, "x"))), rdn(atv(ou, str(tUTF8, "y"))), cn)
		if _, err := intermediateTBS(t, root.interParams(csr)); err != nil {
			t.Error(err)
		}
	})
	t.Run("a unit and a repeated common name", func(t *testing.T) {
		ou := o(2, 5, 4, 11)
		csr := copyCSR(withExtensions(t, goodExtensions()...))
		csr.RawSubject = nameOf(rdn(atv(ou, str(tUTF8, "x"))), cn, cn)
		_, err := intermediateTBS(t, root.interParams(csr))
		refused(t, err, pki.ErrRequest)
	})
}
