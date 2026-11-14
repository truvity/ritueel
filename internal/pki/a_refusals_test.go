package pki_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/pki"
)

// Every refusal of a request has a check of the contract, and a new refusal cannot be added without one. How the test knows:
//
//  1. The source is walked with go/parser. Every call of failRequest and of nameFail in the files of the package (not the tests)
//     is read: its check must be one of the four constants (never CheckNone) and its format must be in refusalChecks below, with
//     the same check. A refusal that is added with a check that is not in the table, or without a row, fails here. No call of
//     fail or of failWith with the kind ErrRequest may stand anywhere (it would make an ErrRequest that carries no check), except
//     the one that says it is a fault of the package (the second reading of a body, which no input reaches). No composite literal
//     of requestError may stand outside check.go.
//  2. The table is written from the contract's order of the checks (docs/reference/hand-off-contract.md, "What the certifier
//     checks": 2 the form, 4 the key, 5 the signature, 9 the policy), and not read from the source: the codes of the table are the
//     ones that the contract's check gives, and the walk finds a refusal whose check in the source is another.
//  3. While the whole package is tested, every error of kind ErrRequest that a test sees (they pass through kindOf) is recorded with
//     its text and its check. At the end, every recorded text must be matched by a row of the table with the check of the row, and
//     every row of the table (every refusal of the source) must have been reached by some test with the check that the table says.
//     That step runs only when no -run filter is given, because it needs the other tests to have run first.
//
// The test is the last of the package by its file name (zz_).

// refusalChecks maps the format of every refusal of a request in the source to the check that the contract gives it.
var refusalChecks = map[string]pki.Check{
	// check 2: an algorithm element that is not well formed is a fault of the form (the contract: "an algorithm element that is not
	// well-formed is malformed"); another algorithm that is well formed is check 5.
	"the signature algorithm of the request is not an AlgorithmIdentifier (RFC 2986, section 4.2)": pki.CheckMalformed,
	// check 9: a key or a name equal to that of any root key of the bundle.
	"the key of the request is the key of a root of the bundle":                                 pki.CheckPolicy,
	"the subject of the request is the name of a root of the bundle, as OpenSSL compares names": pki.CheckPolicy,
	// check 2, the form of the request (reason code malformed).
	"the request is longer than %d octets":                                                                         pki.CheckMalformed,
	"the request is not one DER sequence with nothing after it (RFC 2986, section 4.2)":                            pki.CheckMalformed,
	"the request is not a certification request info, an algorithm and a signature (RFC 2986, section 4.2)":        pki.CheckMalformed,
	"the request has an element after its signature (RFC 2986, section 4.2)":                                       pki.CheckMalformed,
	"the certification request info is not a sequence (RFC 2986, section 4.1)":                                     pki.CheckMalformed,
	"the certification request info is not a version, a subject, a key and the attributes (RFC 2986, section 4.1)": pki.CheckMalformed,
	"the certification request info has an element after its attributes (RFC 2986, section 4.1)":                   pki.CheckMalformed,
	"the version of the request is not 0 (RFC 2986, section 4.1)":                                                  pki.CheckMalformed,
	"the subject of the request is not a sequence (RFC 2986, section 4.1)":                                         pki.CheckMalformed,
	"the signature of the request is not a bit string of whole octets (RFC 2986, section 4.2)":                     pki.CheckMalformed,
	"the request file is longer than %d octets":                                                                    pki.CheckMalformed,
	"the request file does not start with a PEM block":                                                             pki.CheckMalformed,
	"the request file is not a PEM block":                                                                          pki.CheckMalformed,
	"the PEM block of the request file does not have the label CERTIFICATE REQUEST":                                pki.CheckMalformed,
	"the PEM block of the request file has headers":                                                                pki.CheckMalformed,
	"the request file has something after its PEM block":                                                           pki.CheckMalformed,
	"the first line of the request file is not followed by a line end of LF or CRLF":                               pki.CheckMalformed,
	"a line of the base64 text of the request file is empty or longer than %d characters":                          pki.CheckMalformed,
	"the base64 text of the request file is not the standard base64 of one request":                                pki.CheckMalformed,
	"the key of the request is not a SubjectPublicKeyInfo (RFC 5280, section 4.1)":                                 pki.CheckMalformed,
	"the key of the request is not in the canonical form":                                                          pki.CheckMalformed,
	"the attributes of the request are not [0] in the constructed form (RFC 2986, section 4.1)":                    pki.CheckMalformed,
	"the request has no attribute: it must have the extension request (RFC 2985, section 5.4.2)":                   pki.CheckMalformed,
	"the request has more than one attribute: it may have only the extension request":                              pki.CheckMalformed,
	"the attribute of the request is not the extension request (RFC 2985, section 5.4.2)":                          pki.CheckMalformed,
	"the values of the extension request are not one set with nothing after it (RFC 2985, section 5.4.2)":          pki.CheckMalformed,
	"the extension request has no value that is the extensions (RFC 2985, section 5.4.2)":                          pki.CheckMalformed,
	"the extension request has more than one value: it may have only one":                                          pki.CheckMalformed,
	"the extensions of the request are an empty sequence (RFC 5280, section 4.1: SIZE (1..MAX))":                   pki.CheckMalformed,
	"an extension of the request is not a DER sequence (RFC 5280, section 4.1)":                                    pki.CheckMalformed,
	"an extension of the request does not start with an object identifier (RFC 5280, section 4.1)":                 pki.CheckMalformed,
	"an extension of the request has no value (RFC 5280, section 4.1)":                                             pki.CheckMalformed,
	"an extension of the request has a critical flag that is not TRUE: DER leaves FALSE out (X.690, 11.5)":         pki.CheckMalformed,
	"an extension of the request has a value that is not an octet string (RFC 5280, section 4.1)":                  pki.CheckMalformed,
	"an extension of the request has an element after its value (RFC 5280, section 4.1)":                           pki.CheckMalformed,
	"%s is not a name: one DER sequence (RFC 5280, 4.1.2.4)":                                                       pki.CheckMalformed,
	"%s has bytes after the name":                                                                                  pki.CheckMalformed,
	"%s is empty (RFC 5280, 4.1.2.4)":                                                                              pki.CheckMalformed,
	"%s has a relative name that is not a DER set (RFC 5280, 4.1.2.4)":                                             pki.CheckMalformed,
	"%s has an empty relative name (RFC 5280, 4.1.2.4: SIZE (1..MAX))":                                             pki.CheckMalformed,
	"%s has an attribute that is not DER (RFC 5280, 4.1.2.4)":                                                      pki.CheckMalformed,
	"%s has a relative name whose attributes are not in DER order (X.690, 11.6)":                                   pki.CheckMalformed,
	"%s has an attribute that is not a sequence (RFC 5280, 4.1.2.4)":                                               pki.CheckMalformed,
	"%s has an attribute that does not start with an object identifier (RFC 5280, 4.1.2.4)":                        pki.CheckMalformed,
	"%s has an attribute with no value that is DER (RFC 5280, 4.1.2.4)":                                            pki.CheckMalformed,
	"%s has an attribute with an element after its value (RFC 5280, 4.1.2.4)":                                      pki.CheckMalformed,
	"%s has an attribute whose value is not a string (RFC 5280, 4.1.2.4)":                                          pki.CheckMalformed,
	// check 4, the key (algorithm-unsupported).
	"the key of the request is not ECDSA on P-384": pki.CheckAlgorithm,
	// check 5, the signature and its algorithm (possession-invalid).
	"the request is not signed with ecdsa-with-SHA384, as the hand-off contract says": pki.CheckPossession,
	"the signature of the request is not one DER ECDSA value":                         pki.CheckPossession,
	"the request does not verify with its own key":                                    pki.CheckPossession,
	// check 9, the content: the strings and the text of the subject, the extensions, the name constraints, the issuer (policy).
	"the key of the request is the key of the issuer":                                 pki.CheckPolicy,
	"the subject of the request is the name of the issuer, as OpenSSL compares names": pki.CheckPolicy,
	"the request has the extension %s twice":                                          pki.CheckPolicy,
	"the basic constraints are not critical, cA true, path length 0":                  pki.CheckPolicy,
	"the key usage is not critical":                                                   pki.CheckPolicy,
	"the name constraints are not critical":                                           pki.CheckPolicy,
	"the extended key usage is critical: the contract's request has it not critical":  pki.CheckPolicy,
	"the request has an extension outside the profile: %s":                            pki.CheckPolicy,
	"the request has no basic constraints":                                            pki.CheckPolicy,
	"the request has no key usage":                                                    pki.CheckPolicy,
	"the request has no extended key usage: the hand-off contract's request has it, not critical, with serverAuth, clientAuth or both": pki.CheckPolicy,
	"the request has no name constraints: the hand-off contract's request has them, with at least one permitted subtree":               pki.CheckPolicy,
	"the key usage is not one DER bit string":                                                                                                    pki.CheckPolicy,
	"the key usage has the bit %d, which is not keyCertSign, cRLSign or digitalSignature":                                                        pki.CheckPolicy,
	"the key usage has no keyCertSign":                                                                                                           pki.CheckPolicy,
	"the key usage is not in the named-bit DER form":                                                                                             pki.CheckPolicy,
	"the extended key usage is not a non-empty list of object identifiers":                                                                       pki.CheckPolicy,
	"the extended key usage is not in the DER form":                                                                                              pki.CheckPolicy,
	"the extended key usage names a purpose other than serverAuth and clientAuth":                                                                pki.CheckPolicy,
	"the extended key usage names a purpose twice":                                                                                               pki.CheckPolicy,
	"the name constraints are not one DER sequence (RFC 5280, 4.2.1.10)":                                                                         pki.CheckPolicy,
	"the name constraints have a field that is not DER (RFC 5280, 4.2.1.10)":                                                                     pki.CheckPolicy,
	"the name constraints have a field other than permittedSubtrees [0] and excludedSubtrees [1], in this order, once each (RFC 5280, 4.2.1.10)": pki.CheckPolicy,
	"the name constraints are an empty sequence (RFC 5280, 4.2.1.10)":                                                                            pki.CheckPolicy,
	"the name constraints have no permitted subtree (hand-off contract, the request: at least one permitted subtree)":                            pki.CheckPolicy,
	"a list of subtrees is empty (RFC 5280, 4.2.1.10: SIZE (1..MAX))":                                                                            pki.CheckPolicy,
	"a subtree is not a DER sequence (RFC 5280, 4.2.1.10)":                                                                                       pki.CheckPolicy,
	"a subtree has no base that is DER (RFC 5280, 4.2.1.10)":                                                                                     pki.CheckPolicy,
	"the base of a subtree is not a general name, tags 0 to 8 in the form of the CHOICE (RFC 5280, 4.2.1.6)":                                     pki.CheckPolicy,
	"a subtree has more than its base: the minimum must be zero and the maximum absent, and a subtree has one base (RFC 5280, 4.2.1.10)":         pki.CheckPolicy,
	"a permitted subtree is a DNS name or a URI host: this version issues no other name form (hand-off contract, the reference policy)":          pki.CheckPolicy,
	"the excluded subtrees are not none or exactly 0.0.0.0/0 and ::/0 (hand-off contract, the request)":                                          pki.CheckPolicy,
	"%s has an attribute whose value is an empty string (RFC 5280, 4.1.2.4: SIZE (1..MAX))":                                                      pki.CheckPolicy,
	"%s has a domainComponent or e-mail attribute that is not an IA5String (RFC 5280, Appendix A.1)":                                             pki.CheckPolicy,
	"%s has a country, serial number or distinguished name qualifier attribute that is not a PrintableString (RFC 5280, Appendix A.1)":           pki.CheckPolicy,
	"%s has an attribute whose value is not a PrintableString or a UTF8String (RFC 5280, 4.1.2.4)":                                               pki.CheckPolicy,
	"%s has a value that is not valid UTF-8":                                                                                                     pki.CheckPolicy,
	"%s has a PrintableString with a character outside its character set (X.680)":                                                                pki.CheckPolicy,
	"%s has an IA5String with a character outside ASCII (X.680)":                                                                                 pki.CheckPolicy,
	"%s has an attribute whose value is outside the SIZE constraint of its attribute type in RFC 5280, Appendix A.1":                             pki.CheckPolicy,
	"%s has an attribute type that stands more than once in one relative name (X.501)":                                                           pki.CheckPolicy,
	"%s has a value with %s": pki.CheckPolicy,
	"%s has an attribute type that stands more than once, other than the organisational unit and the domain component": pki.CheckPolicy,
}

// faultTexts are the texts that failRequest and nameFail get through "%s" from a function: a refusal of a host name, and of the text of a
// value. Each is a refusal of the check 9.
var faultTexts = []string{
	"is a name whose last label is all digits, so it reads as a dotted address and not as a name (RFC 1123, section 2.1)",
	"is not a name of lower-case labels of letters, digits and hyphens joined by periods, with no wildcard and no period at its start or its end (RFC 5280, 4.2.1.6 and 4.2.1.10)",
	"a value with a character outside printable ASCII (U+0020 to U+007E)",
	"a value with a space at its start or its end",
	"a value with two spaces in a row",
}

type sourceRefusal struct {
	file, format string
	check        string // the name of the constant
}

// walkTheSource reads the non-test files of the package.
func walkTheSource(t *testing.T) (found []sourceRefusal) {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.CompositeLit:
				if id, ok := n.Type.(*ast.Ident); ok && id.Name == "requestError" && name != "check.go" {
					t.Errorf("%s: a requestError is made outside check.go: the check is given by failRequest and nameFail", fset.Position(n.Pos()))
				}
			case *ast.CallExpr:
				id, ok := n.Fun.(*ast.Ident)
				if !ok {
					return true
				}
				pos := fset.Position(n.Pos())
				switch id.Name {
				case "failRequest", "nameFail":
					ci, fi := 0, 1
					if id.Name == "nameFail" {
						ci, fi = 1, 2
						if name == "check.go" {
							return true // the definition's own call of failRequest
						}
					}
					if name == "check.go" {
						return true
					}
					if len(n.Args) <= fi {
						t.Errorf("%s: %s has too few arguments", pos, id.Name)
						return true
					}
					var check string
					switch c := n.Args[ci].(type) {
					case *ast.Ident:
						check = c.Name
					default:
						t.Errorf("%s: the check of %s is not one of the four constants", pos, id.Name)
						return true
					}
					lit, ok := n.Args[fi].(*ast.BasicLit)
					if !ok || lit.Kind != token.STRING {
						t.Errorf("%s: the format of %s is not a string literal", pos, id.Name)
						return true
					}
					format, err := strconv.Unquote(lit.Value)
					if err != nil {
						t.Fatal(err)
					}
					found = append(found, sourceRefusal{name, format, check})
				case "fail", "failWith":
					if len(n.Args) == 0 {
						return true
					}
					if k, ok := n.Args[0].(*ast.Ident); ok && k.Name == "ErrRequest" {
						text := ""
						if len(n.Args) > 1 {
							if lit, ok := n.Args[1].(*ast.BasicLit); ok {
								text = lit.Value
							}
						}
						if id.Name == "failWith" && strings.Contains(text, "a fault of this package") {
							return true // the second reading of a body: reached by no input
						}
						t.Errorf("%s: %s(ErrRequest, ...) makes a refusal of a request that carries no check: use failRequest", pos, id.Name)
					}
				}
			}
			return true
		})
	}
	return found
}

var checkConstants = map[string]pki.Check{
	"CheckMalformed": pki.CheckMalformed, "CheckAlgorithm": pki.CheckAlgorithm, "CheckPossession": pki.CheckPossession, "CheckPolicy": pki.CheckPolicy,
}

func TestEveryRefusalOfTheSourceHasItsCheckOfTheContract(t *testing.T) {
	found := walkTheSource(t)
	if len(found) < 90 {
		t.Fatalf("the walk found %d refusals, want at least 90", len(found))
	}
	inSource := map[string]bool{}
	for _, r := range found {
		code, ok := checkConstants[r.check]
		if !ok {
			t.Errorf("%s: the check %s is not one of the four of the contract", r.file, r.check)
			continue
		}
		if r.format == "%s" {
			if code != pki.CheckPolicy {
				t.Errorf("%s: a refusal by a function's text has the check %s, want CheckPolicy", r.file, r.check)
			}
			continue
		}
		inSource[r.format] = true
		want, ok := refusalChecks[r.format]
		if !ok {
			t.Errorf("%s: the refusal %q is not in the table of the contract's checks: add it, with the check that the contract gives it", r.file, r.format)
			continue
		}
		if want != code {
			t.Errorf("%s: the refusal %q has the check %s, the contract gives %s (%s)", r.file, r.format, r.check, want, want.Code())
		}
	}
	for format := range refusalChecks {
		if !inSource[format] {
			t.Errorf("the table has the refusal %q, which the source does not have any more: take it out", format)
		}
	}
}
