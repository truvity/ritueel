package pki

import (
	"bytes"
	"encoding/asn1"
	"errors"
	"slices"
	"sort"
	"strings"
	"unicode/utf8"
)

// The universal tags of the string types that a name of this package may hold (UTF8String is in
// der.go).
const (
	tagPrintableString = 0x13
	tagIA5String       = 0x16
)

// attrSyntax is the syntax that RFC 5280, Appendix A.1 gives the value of an attribute type: the
// string types it may have and its size in characters, as the SIZE constraint of the ASN.1 module
// states it. A maximum of 0 means the module gives no upper bound.
type attrSyntax struct {
	tags     []byte
	min, max int
}

// The syntaxes of Appendix A.1. A DirectoryString is a PrintableString or a UTF8String here (see
// readName); the three attribute types that the module defines as a PrintableString, and the
// two that it defines as an IA5String, are not a DirectoryString.
var (
	directoryString = []byte{tagPrintableString, tagUTF8String}
	printableOnly   = []byte{tagPrintableString}
	ia5Only         = []byte{tagIA5String}
)

// The attribute types that this package names. The first two may stand more than once in a subject.
var (
	oidOrganizationalUnit = asn1.ObjectIdentifier{2, 5, 4, 11}
	oidDomainComponent    = asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 25}
)

// attributeSyntaxes holds the attribute types that Appendix A.1 defines, by object identifier. The
// upper bounds are those of the module ("Upper Bounds", ub-name 32768, ub-common-name 64, and so
// on); the module's own comment says "specifications of Upper Bounds MUST be regarded as
// mandatory". An attribute type that the module does not define ("This specification does not
// restrict the set of attribute types that may appear in names") is read as a DirectoryString with
// no upper bound, because the RFC gives it none.
var attributeSyntaxes = map[string]attrSyntax{
	"2.5.4.41":                   {directoryString, 1, 32768}, // name
	"2.5.4.4":                    {directoryString, 1, 32768}, // surname
	"2.5.4.42":                   {directoryString, 1, 32768}, // givenName
	"2.5.4.43":                   {directoryString, 1, 32768}, // initials
	"2.5.4.44":                   {directoryString, 1, 32768}, // generationQualifier
	"2.5.4.3":                    {directoryString, 1, 64},    // commonName, ub-common-name
	"2.5.4.7":                    {directoryString, 1, 128},   // localityName, ub-locality-name
	"2.5.4.8":                    {directoryString, 1, 128},   // stateOrProvinceName, ub-state-name
	"2.5.4.10":                   {directoryString, 1, 64},    // organizationName, ub-organization-name
	"2.5.4.11":                   {directoryString, 1, 64},    // organizationalUnitName, ub-organizational-unit-name
	"2.5.4.12":                   {directoryString, 1, 64},    // title, ub-title
	"2.5.4.65":                   {directoryString, 1, 128},   // pseudonym, ub-pseudonym
	"2.5.4.46":                   {printableOnly, 1, 0},       // dnQualifier: PrintableString (the module gives no lower bound; an empty one is refused)
	"2.5.4.6":                    {printableOnly, 2, 2},       // countryName: PrintableString (SIZE (2))
	"2.5.4.5":                    {printableOnly, 1, 64},      // serialNumber: PrintableString (SIZE (1..ub-serial-number))
	"0.9.2342.19200300.100.1.25": {ia5Only, 1, 0},             // domainComponent: IA5String (the module gives no lower bound; an empty one is refused)
	"1.2.840.113549.1.9.1":       {ia5Only, 1, 255},           // emailAddress: IA5String (SIZE (1..ub-emailaddress-length))
}

// defaultSyntax is the syntax of an attribute type that Appendix A.1 does not define.
var defaultSyntax = attrSyntax{directoryString, 1, 0}

// printableChar tells whether a byte is in the character set of a PrintableString (X.680, 41.4):
// the letters A to Z and a to z, the digits, the space, and ' ( ) + , - . / : = ?.
func printableChar(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	}
	return c != 0 && strings.IndexByte(" '()+,-./:=?", c) >= 0
}

// A name as read: its relative names in order, each with its attributes in order.
type (
	attribute struct {
		typ   asn1.ObjectIdentifier
		tag   int    // the tag of the string
		value []byte // the content octets of the string
	}
	rdn  []attribute
	name []rdn
)

// readName reads the structure of a name by RFC 5280, section 4.1.2.4 (the issuer) and 4.1.2.6
// (the subject, "Implementation requirements for this field are those defined for the issuer
// field"), and refuses what the RFC does not allow. The bytes are read, never changed.
//
//	Name ::= CHOICE { rdnSequence RDNSequence }
//	RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
//	RelativeDistinguishedName ::= SET SIZE (1..MAX) OF AttributeTypeAndValue
//	AttributeTypeAndValue ::= SEQUENCE { type AttributeType, value AttributeValue }
//
// The input is one DER SEQUENCE with nothing after it, and it is not empty ("The issuer field MUST
// contain a non-empty distinguished name"; the subject of a CA "MUST be populated with a non-empty
// distinguished name"). Each relative name is a SET of at least one attribute, and in DER the
// elements of a SET OF are in ascending order of their encodings (X.690, 11.6). An attribute is a
// SEQUENCE of exactly an object identifier and one value, and nothing after it. The value is a
// string that is not empty: "CAs conforming to this profile MUST use either the PrintableString or
// UTF8String encoding of DirectoryString" (the exceptions are for a CA that has issued with another
// encoding before, which is not this CA), and the two attribute types of Appendix A that are not a
// DirectoryString, domainComponent and the e-mail address, are an IA5String. Any other type of
// value is refused. Appendix A.1 gives some attribute types another syntax and a size in
// characters, and these are read too: the country is a PrintableString of 2 characters, the serial
// number and the distinguished name qualifier are PrintableStrings, the domain component and the
// e-mail address are IA5Strings, and the upper bounds of the module apply ("specifications of
// Upper Bounds MUST be regarded as mandatory"); see attributeSyntaxes. A PrintableString holds only
// the characters of its type, an IA5String only ASCII, and a UTF8String valid UTF-8. These are
// everything that the standard library's reading of a name demands of the text of a string (its
// parser refuses an invalid PrintableString, IA5String or UTF8String and nothing else of a string
// of these three types; ours is stricter for a PrintableString, which refuses * and &), so a name
// that passes here is one that the second reading of a finished body cannot refuse, and an issuer
// that fails is refused as the caller's parameter and not as a fault of the request. The subject of a
// request is read to its end before it is judged: a fault of form anywhere in it is returned in
// preference to a fault of content that stands earlier (check 2 comes before check 9), and only when
// the form is good is the first fault of content returned. The rules
// about what a string says (see checkNameText) are not applied here: a request's subject and an
// issuer are held to them by their callers, and [SameName] reads names without them.
func readName(what string, raw []byte, kind error) (name, error) {
	var outer asn1.RawValue
	rest, err := asn1.Unmarshal(raw, &outer)
	switch {
	case err != nil || outer.Class != asn1.ClassUniversal || outer.Tag != asn1.TagSequence || !outer.IsCompound:
		return nil, nameFail(kind, CheckMalformed, "%s is not a name: one DER sequence (RFC 5280, 4.1.2.4)", what)
	case len(rest) != 0:
		return nil, nameFail(kind, CheckMalformed, "%s has bytes after the name", what)
	case len(outer.Bytes) == 0:
		return nil, nameFail(kind, CheckMalformed, "%s is empty (RFC 5280, 4.1.2.4)", what)
	}
	var out name
	var content error // the first fault of content (of a request's subject), kept while the form is read to the end
	for body := outer.Bytes; len(body) > 0; {
		var set asn1.RawValue
		if body, err = asn1.Unmarshal(body, &set); err != nil || set.Class != asn1.ClassUniversal || set.Tag != asn1.TagSet || !set.IsCompound {
			return nil, nameFail(kind, CheckMalformed, "%s has a relative name that is not a DER set (RFC 5280, 4.1.2.4)", what)
		}
		if len(set.Bytes) == 0 {
			return nil, nameFail(kind, CheckMalformed, "%s has an empty relative name (RFC 5280, 4.1.2.4: SIZE (1..MAX))", what)
		}
		var previous []byte
		var one rdn
		for attrs := set.Bytes; len(attrs) > 0; {
			var attr asn1.RawValue
			if attrs, err = asn1.Unmarshal(attrs, &attr); err != nil {
				return nil, nameFail(kind, CheckMalformed, "%s has an attribute that is not DER (RFC 5280, 4.1.2.4)", what)
			}
			if previous != nil && bytes.Compare(previous, attr.FullBytes) > 0 {
				return nil, nameFail(kind, CheckMalformed, "%s has a relative name whose attributes are not in DER order (X.690, 11.6)", what)
			}
			previous = attr.FullBytes
			a, err := readAttribute(what, attr, kind)
			if err != nil {
				if errors.Is(kind, ErrRequest) && CheckOf(err) == CheckPolicy {
					if content == nil {
						content = err
					}
					continue
				}
				return nil, err
			}
			one = append(one, a)
		}
		out = append(out, one)
	}
	if content != nil {
		return nil, content
	}
	return out, nil
}

// readAttribute reads one AttributeTypeAndValue: a SEQUENCE of an object identifier and one
// string, nothing after it.
func readAttribute(what string, attr asn1.RawValue, kind error) (attribute, error) {
	var none attribute
	if attr.Class != asn1.ClassUniversal || attr.Tag != asn1.TagSequence || !attr.IsCompound {
		return none, nameFail(kind, CheckMalformed, "%s has an attribute that is not a sequence (RFC 5280, 4.1.2.4)", what)
	}
	var typ asn1.ObjectIdentifier
	rest, err := asn1.Unmarshal(attr.Bytes, &typ)
	if err != nil {
		return none, nameFail(kind, CheckMalformed, "%s has an attribute that does not start with an object identifier (RFC 5280, 4.1.2.4)", what)
	}
	var value asn1.RawValue
	rest, err = asn1.Unmarshal(rest, &value)
	switch {
	case err != nil:
		return none, nameFail(kind, CheckMalformed, "%s has an attribute with no value that is DER (RFC 5280, 4.1.2.4)", what)
	case len(rest) != 0:
		return none, nameFail(kind, CheckMalformed, "%s has an attribute with an element after its value (RFC 5280, 4.1.2.4)", what)
	case value.Class != asn1.ClassUniversal || value.IsCompound:
		return none, nameFail(kind, CheckMalformed, "%s has an attribute whose value is not a string (RFC 5280, 4.1.2.4)", what)
	}
	syntax, ok := attributeSyntaxes[typ.String()]
	if !ok {
		syntax = defaultSyntax
	}
	if len(value.Bytes) == 0 && syntax.min >= 1 {
		return none, nameFail(kind, CheckPolicy, "%s has an attribute whose value is an empty string (RFC 5280, 4.1.2.4: SIZE (1..MAX))", what)
	}
	if !slices.Contains(syntax.tags, byte(value.Tag)) {
		switch {
		case slices.Equal(syntax.tags, ia5Only):
			return none, nameFail(kind, CheckPolicy, "%s has a domainComponent or e-mail attribute that is not an IA5String (RFC 5280, Appendix A.1)", what)
		case slices.Equal(syntax.tags, printableOnly):
			return none, nameFail(kind, CheckPolicy, "%s has a country, serial number or distinguished name qualifier attribute that is not a PrintableString (RFC 5280, Appendix A.1)", what)
		}
		return none, nameFail(kind, CheckPolicy, "%s has an attribute whose value is not a PrintableString or a UTF8String (RFC 5280, 4.1.2.4)", what)
	}
	size := len(value.Bytes)
	switch value.Tag {
	case tagUTF8String:
		// The standard library refuses a UTF8String that is not valid UTF-8, and it would be the
		// second reading of a body that found it; so it is refused here, for an issuer, a subject and a
		// name of SameName alike, in the kind of the caller.
		if !utf8.Valid(value.Bytes) {
			return none, nameFail(kind, CheckPolicy, "%s has a value that is not valid UTF-8", what)
		}
		size = utf8.RuneCount(value.Bytes)
	case tagPrintableString:
		for _, c := range value.Bytes {
			if !printableChar(c) {
				return none, nameFail(kind, CheckPolicy, "%s has a PrintableString with a character outside its character set (X.680)", what)
			}
		}
	case tagIA5String:
		for _, c := range value.Bytes {
			if c >= 0x80 {
				return none, nameFail(kind, CheckPolicy, "%s has an IA5String with a character outside ASCII (X.680)", what)
			}
		}
	}
	if size < syntax.min || (syntax.max != 0 && size > syntax.max) {
		return none, nameFail(kind, CheckPolicy, "%s has an attribute whose value is outside the SIZE constraint of its attribute type in RFC 5280, Appendix A.1", what)
	}
	return attribute{typ: typ, tag: value.Tag, value: value.Bytes}, nil
}

// checkNameText holds the text of the subject of a request to the contract's rule for version 1 of
// the subject, and nothing wider (hand-off contract, "The request"): the subject is printable ASCII,
// the characters U+0020 to U+007E, in every string type. The rule is one function, subjectTextFault.
// There is no other rule by kind of character, and no Unicode normal form to ask for: with ASCII only,
// no look-alike letter, no invisible or direction character and no second form of one text exist. A
// subject in another script needs a later version of the contract.
//
// Also:
//   - An attribute type stands once in one relative name (X.501: the attributes of a relative name have
//     different types), and once in a subject, except the organisational unit and the domain
//     component, which a name repeats by custom in different relative names (an organisation has units,
//     and a domain is written one label to a component).
//
// The text rule is for the subject of a request and for an issuer, which is always the name of a root
// that this package's root builder writes: "<name> Root <label>", and for a test root the same with
// " (TEST ONLY)" at its end, one common name whose text is ASCII with single spaces, which this rule
// accepts (see [RootCommonName]); the issuer is held to it in [IntermediateTBS] and in the reader of a
// body. The strings and sizes of a name are read by readName.
func checkNameText(what string, n name, kind error) error {
	seen := map[string]int{}
	for _, set := range n {
		inSet := map[string]bool{}
		for _, a := range set {
			typ := a.typ.String()
			if inSet[typ] {
				return nameFail(kind, CheckPolicy, "%s has an attribute type that stands more than once in one relative name (X.501)", what)
			}
			inSet[typ] = true
			seen[typ]++
			if fault := subjectTextFault(a.value); fault != "" {
				return nameFail(kind, CheckPolicy, "%s has a value with %s", what, fault)
			}
		}
	}
	for typ, count := range seen {
		if count > 1 && typ != oidOrganizationalUnit.String() && typ != oidDomainComponent.String() {
			return nameFail(kind, CheckPolicy, "%s has an attribute type that stands more than once, other than the organisational unit and the domain component", what)
		}
	}
	return nil
}

// subjectTextFault is the rule for the text of a value of a subject in version 1 of the contract: the
// characters U+0020 to U+007E only (the letters, the digits, the space and the punctuation of ASCII),
// no space at the start or the end, and no two spaces in a row. It returns "" for a text that holds
// the rule, and otherwise the words of the first fault. It is the one place of this rule. The text is
// the content octets of the string: a UTF8String with a non-ASCII character fails here, and a
// PrintableString and an IA5String also keep their own narrower sets (see readAttribute).
func subjectTextFault(text []byte) string {
	for _, c := range text {
		if c < 0x20 || c > 0x7e {
			return "a character outside printable ASCII (U+0020 to U+007E)"
		}
	}
	switch {
	case len(text) > 0 && (text[0] == ' ' || text[len(text)-1] == ' '):
		return "a space at its start or its end"
	case bytes.Contains(text, []byte("  ")):
		return "two spaces in a row"
	}
	return ""
}

// SameName tells whether two names, each the DER of a Name (a root's subject, for example), are the
// same name to OpenSSL. This is how OpenSSL decides that an issuer name matches a subject name when
// it builds a chain (X509_NAME_cmp compares the canonical encoding of the names, and the name hash
// of a certificate folder is made from the same encoding), and it was checked against the issuer
// hash of OpenSSL 3.6 on 7,750 pairs of names with no difference. The whole rule is:
//
//   - the names have the same relative names, in the same order;
//   - the attributes of one relative name are a set: their order does not count;
//   - two attributes are the same when they have the same type (object identifier) and the same
//     text after this canonical form: the string is read as UTF-8 text whatever its type (a
//     PrintableString, a UTF8String and an IA5String with the same text are the same); the white
//     space at its start and its end is dropped; a run of white space inside is one space; the
//     ASCII letters A to Z are turned to a to z. White space is the space and the characters TAB,
//     LF, VT, FF and CR; a byte of 0x80 or above is left as it is.
//
// It is exactly what OpenSSL does and no more. It is not string preparation (RFC 4518, which RFC
// 5280, section 7.1 asks of a full comparison): it does not fold the case of a letter outside
// ASCII, it does not normalise the Unicode form (a composed and a decomposed letter are two
// names), and it does not treat the other spaces of Unicode (the no-break space, the ideographic
// space) as space. Two names that SameName calls different may be one name to a verifier that
// does more, and two that it calls the same are one name to OpenSSL. A caller that must keep two
// roots of a bundle apart (an OpenSSL folder of certificates holds one file for a name) compares
// the subjects of the roots with it.
//
// Each name is read for its structure by the rules that read an issuer (RFC 5280, section 4.1.2.4
// and the strings and sizes of Appendix A.1, see the package comment); a name that fails them is an
// error that wraps [ErrParams], and no comparison is made. The text rules of a subject are not
// applied. Both names are copied at the top of the call.
func SameName(a, b []byte) (bool, error) {
	a, err := copyBytes(a) // read more than once: copied first
	if err != nil {
		return false, err
	}
	if b, err = copyBytes(b); err != nil {
		return false, err
	}
	na, err := readName("the first name", a, ErrParams)
	if err != nil {
		return false, err
	}
	nb, err := readName("the second name", b, ErrParams)
	if err != nil {
		return false, err
	}
	return sameName(na, nb), nil
}

// canonicalName is a string that is the same for two names exactly when sameName says they are the
// same, for names of printable ASCII (the separators are control characters, so no text holds them).
func canonicalName(n name) string {
	var b strings.Builder
	for _, set := range n {
		for _, attr := range canonicalRDN(set) {
			b.WriteString(attr)
			b.WriteByte(1)
		}
		b.WriteByte(2)
	}
	return b.String()
}

// sameName is the comparison of [SameName] on names that are read.
func sameName(a, b name) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !slices.Equal(canonicalRDN(a[i]), canonicalRDN(b[i])) {
			return false
		}
	}
	return true
}

// canonicalRDN is the attributes of a relative name as strings, in order: the object identifier,
// a zero, and the text in canonical form.
func canonicalRDN(set rdn) []string {
	out := make([]string, len(set))
	for i, a := range set {
		out[i] = a.typ.String() + "\x00" + canonicalText(a.value)
	}
	sort.Strings(out)
	return out
}

// canonicalText is the text as OpenSSL canonicalises it (see sameName).
func canonicalText(v []byte) string {
	isSpace := func(c byte) bool { return c == ' ' || (c >= '\t' && c <= '\r') }
	start, end := 0, len(v)
	for start < end && v[start] < 0x80 && isSpace(v[start]) {
		start++
	}
	for end > start && v[end-1] < 0x80 && isSpace(v[end-1]) {
		end--
	}
	out := make([]byte, 0, end-start)
	for i := start; i < end; i++ {
		c := v[i]
		switch {
		case c >= 0x80:
			out = append(out, c)
		case isSpace(c):
			out = append(out, ' ')
			for i+1 < end && v[i+1] < 0x80 && isSpace(v[i+1]) {
				i++
			}
		case c >= 'A' && c <= 'Z':
			out = append(out, c+'a'-'A')
		default:
			out = append(out, c)
		}
	}
	return string(out)
}
