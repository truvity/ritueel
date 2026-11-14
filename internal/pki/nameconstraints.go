package pki

import (
	"bytes"
	"encoding/asn1"
	"strings"
)

// The name constraints of a request.
//
// What a request may constrain is what the hand-off contract says in version 1 ("Name constraints"
// in the table of the request, and the rule of the reference policy), decided with the strict form of
// each name: a permitted subtree is a DNS name or a URI host and nothing else, the excluded subtrees
// are none or the two IP ranges, and every name has the form that RFC 5280 gives its kind. E-mail
// names and the five rare kinds are refused, as is every other excluded subtree (the planned excluded
// DNS subtrees and other IP ranges are for a later version). Each rule is one named function of this
// file:
//
//   - permittedBase: a permitted subtree is a DNS name or a URI host (the contract refuses "an IP
//     range or an e-mail name as a permitted subtree", and its policy lists DNS zones and URI
//     hosts). There is at least one ("At least one permitted subtree").
//   - excludedSubtrees: none, or exactly 0.0.0.0/0 and ::/0, both, in either order ("so that an IP
//     address is not left unconstrained (RFC 5280)").
//   - hostName: the text of a DNS name and of a URI host.
//
// The structure is read by RFC 5280, section 4.2.1.10 and 4.2.1.6 (readNameConstraints), and the
// bytes of the value go into the certificate unchanged.

// The two excluded subtrees that the contract allows: every IPv4 address and every IPv6 address, as
// a GeneralSubtree of an iPAddress of the zero address and the zero mask (8 octets for IPv4 and 32
// for IPv6, RFC 5280, section 4.2.1.10).
var (
	allIPv4 = append([]byte{0x30, 0x0a, 0x87, 0x08}, make([]byte, 8)...)
	allIPv6 = append([]byte{0x30, 0x22, 0x87, 0x20}, make([]byte, 32)...)
)

// The tags of the two name forms that a permitted subtree may have (RFC 5280, section 4.2.1.6).
const (
	generalNameDNS = 2
	generalNameURI = 6
)

// NameConstraints are the name constraints of a request that [ParseRequest] has read and found to be
// of the form that this package issues (see the rules at the top of nameconstraints.go): the
// permitted DNS names and URI constraints, which are host names in lower case, and whether the
// excluded subtrees are the two that exclude every IP address. Nothing else can be in a request that
// is read: other name forms, other excluded subtrees and an empty list of permitted subtrees are
// refused. The values are copies.
type NameConstraints struct {
	// PermittedDNS are the permitted DNS names, in the order of the request: each a host name; every
	// name with these labels on its right is permitted (RFC 5280, 4.2.1.10).
	PermittedDNS []string
	// PermittedURI are the permitted URI constraints, in the order of the request: a host name, or a
	// period and a domain name (RFC 5280, 4.2.1.10).
	PermittedURI []string
	// ExcludesAllIP is true when the excluded subtrees are exactly 0.0.0.0/0 and ::/0, and false
	// when there are none.
	ExcludesAllIP bool
}

// subtree is one GeneralSubtree as read: its bytes and its base.
type subtree struct {
	full []byte
	base asn1.RawValue
}

// readNameConstraints reads a name constraints value by RFC 5280, section 4.2.1.10 and 4.2.1.6,
// and refuses what the RFC does not allow and what this package does not issue (see the top of
// this file). The value is read, never changed.
//
//	NameConstraints ::= SEQUENCE {
//	     permittedSubtrees [0] GeneralSubtrees OPTIONAL,
//	     excludedSubtrees  [1] GeneralSubtrees OPTIONAL }
//	GeneralSubtrees ::= SEQUENCE SIZE (1..MAX) OF GeneralSubtree
//	GeneralSubtree ::= SEQUENCE { base GeneralName, minimum [0] BaseDistance DEFAULT 0,
//	     maximum [1] BaseDistance OPTIONAL }
//
// The value is one DER SEQUENCE with nothing after it. It has the permitted subtrees, the
// excluded subtrees, or both in this order, each once, as a context tag [0] or [1] in the
// constructed form ("either the permittedSubtrees field or the excludedSubtrees MUST be present").
// Each holds at least one subtree. A subtree is a SEQUENCE of exactly one general name: "the
// minimum and maximum fields are not used with any name forms, thus, the minimum MUST be zero, and
// maximum MUST be absent" (zero is the DEFAULT, so in DER the minimum is absent too). The general
// name has a tag of the CHOICE of section 4.2.1.6, 0 to 8, in the form the CHOICE gives it: 0, 3,
// 4 and 5 constructed (a SEQUENCE, and the explicit Name of directoryName), 1, 2, 6, 7 and 8
// primitive. Then the rules of this package apply (permittedBase, excludedSubtrees).
func readNameConstraints(value []byte) (NameConstraints, error) {
	var none NameConstraints
	var outer asn1.RawValue
	rest, err := asn1.Unmarshal(value, &outer)
	if err != nil || len(rest) != 0 || outer.Class != asn1.ClassUniversal || outer.Tag != asn1.TagSequence || !outer.IsCompound {
		return none, failRequest(CheckPolicy, "the name constraints are not one DER sequence (RFC 5280, 4.2.1.10)")
	}
	var permitted, excluded []subtree
	body := outer.Bytes
	next := 0 // the context tag that the next field may have
	for len(body) > 0 {
		var field asn1.RawValue
		if body, err = asn1.Unmarshal(body, &field); err != nil {
			return none, failRequest(CheckPolicy, "the name constraints have a field that is not DER (RFC 5280, 4.2.1.10)")
		}
		if field.Class != asn1.ClassContextSpecific || !field.IsCompound || field.Tag < next || field.Tag > 1 {
			return none, failRequest(CheckPolicy, "the name constraints have a field other than permittedSubtrees [0] and excludedSubtrees [1], in this order, once each (RFC 5280, 4.2.1.10)")
		}
		next = field.Tag + 1
		subtrees, err := readSubtrees(field.Bytes)
		if err != nil {
			return none, err
		}
		if field.Tag == 0 {
			permitted = subtrees
		} else {
			excluded = subtrees
		}
	}
	if next == 0 {
		return none, failRequest(CheckPolicy, "the name constraints are an empty sequence (RFC 5280, 4.2.1.10)")
	}
	if len(permitted) == 0 {
		return none, failRequest(CheckPolicy, "the name constraints have no permitted subtree (hand-off contract, the request: at least one permitted subtree)")
	}
	var out NameConstraints
	for _, s := range permitted {
		if err := permittedBase(s.base); err != nil {
			return none, err
		}
		if s.base.Tag == generalNameDNS {
			out.PermittedDNS = append(out.PermittedDNS, string(s.base.Bytes))
		} else {
			out.PermittedURI = append(out.PermittedURI, string(s.base.Bytes))
		}
	}
	if err := excludedSubtrees(excluded); err != nil {
		return none, err
	}
	out.ExcludesAllIP = len(excluded) > 0
	return out, nil
}

// readSubtrees reads the content of GeneralSubtrees: one or more GeneralSubtree.
func readSubtrees(content []byte) ([]subtree, error) {
	if len(content) == 0 {
		return nil, failRequest(CheckPolicy, "a list of subtrees is empty (RFC 5280, 4.2.1.10: SIZE (1..MAX))")
	}
	var out []subtree
	for len(content) > 0 {
		var raw asn1.RawValue
		var err error
		if content, err = asn1.Unmarshal(content, &raw); err != nil || raw.Class != asn1.ClassUniversal || raw.Tag != asn1.TagSequence || !raw.IsCompound {
			return nil, failRequest(CheckPolicy, "a subtree is not a DER sequence (RFC 5280, 4.2.1.10)")
		}
		var base asn1.RawValue
		after, err := asn1.Unmarshal(raw.Bytes, &base)
		if err != nil {
			return nil, failRequest(CheckPolicy, "a subtree has no base that is DER (RFC 5280, 4.2.1.10)")
		}
		if !generalNameTag(base) {
			return nil, failRequest(CheckPolicy, "the base of a subtree is not a general name, tags 0 to 8 in the form of the CHOICE (RFC 5280, 4.2.1.6)")
		}
		if len(after) != 0 {
			return nil, failRequest(CheckPolicy, "a subtree has more than its base: the minimum must be zero and the maximum absent, and a subtree has one base (RFC 5280, 4.2.1.10)")
		}
		out = append(out, subtree{full: raw.FullBytes, base: base})
	}
	return out, nil
}

// generalNameTag tells whether the element has the tag and the form of a GeneralName (RFC 5280,
// section 4.2.1.6; the module is IMPLICIT TAGS, but directoryName holds a CHOICE and so is explicit).
func generalNameTag(v asn1.RawValue) bool {
	if v.Class != asn1.ClassContextSpecific {
		return false
	}
	switch v.Tag {
	case 0, 3, 4, 5: // otherName, x400Address, directoryName, ediPartyName
		return v.IsCompound
	case 1, 2, 6, 7, 8: // rfc822Name, dNSName, uniformResourceIdentifier, iPAddress, registeredID
		return !v.IsCompound
	}
	return false
}

// permittedBase is the rule for the base of a permitted subtree: a DNS name or a URI host, and
// nothing else. It is the contract's rule for version 1: the reference policy refuses "an IP range or
// an e-mail name as a permitted subtree", and the other forms (otherName, x400Address,
// directoryName, ediPartyName, registeredID) are not read by the standard library or OpenSSL in a
// chain. The text of the name is read by RFC 5280, section 4.2.1.10:
//
//   - a DNS name: "DNS name restrictions are expressed as host.example.com. Any DNS name that can
//     be constructed by simply adding zero or more labels to the left-hand side of the name
//     satisfies the name constraint", and the name is in the "preferred name syntax" of RFC 1034
//     section 3.5 as modified by RFC 1123 section 2.1 (section 4.2.1.6). See hostName.
//   - a URI: "the constraint applies to the host part of the name. The constraint MUST be
//     specified as a fully qualified domain name and MAY specify a host or a domain. Examples would
//     be "host.example.com" and ".example.com"." So a URI constraint is such a host name, or a
//     period and then such a name.
//
// A host form (without the period) is read in two ways: RFC 5280 says "When the constraint does
// not begin with a period, it specifies a host", and OpenSSL reads it so, while the standard
// library also admits the subdomains of the host. The contract's own rule for a URI host ("a URI
// host is inside only when it equals a listed host") is the stricter one. The contract's page names
// this one known difference.
func permittedBase(base asn1.RawValue) error {
	text := string(base.Bytes)
	switch base.Tag {
	case generalNameDNS:
		if !hostName(text) {
			return failRequest(CheckPolicy, "%s", hostNameFault("a DNS name constraint", text))
		}
	case generalNameURI:
		if host := strings.TrimPrefix(text, "."); !hostName(host) {
			return failRequest(CheckPolicy, "%s", hostNameFault("a URI constraint", host))
		}
	default:
		return failRequest(CheckPolicy, "a permitted subtree is a DNS name or a URI host: this version issues no other name form (hand-off contract, the reference policy)")
	}
	return nil
}

// hostNameFault is the text of a refusal of a host name that hostName refuses: the one fault that
// has a text of its own, a last label of digits only, or the shape in general.
func hostNameFault(what, name string) string {
	if shapeOfHostName(name) && numericTopLabel(name) {
		return what + " is a name whose last label is all digits, so it reads as a dotted address and not as a name (RFC 1123, section 2.1)"
	}
	return what + " is not a name of lower-case labels of letters, digits and hyphens joined by periods, with no wildcard and no period at its start or its end (RFC 5280, 4.2.1.6 and 4.2.1.10)"
}

// excludedSubtrees is the rule for the excluded subtrees: none, or exactly every IPv4 address and
// every IPv6 address, both, in either order (hand-off contract, the request and the reference
// policy). Any other excluded subtree, alone or beside these, is refused; the planned excluded DNS
// subtrees and other IP ranges are for a later version of the contract.
func excludedSubtrees(list []subtree) error {
	if len(list) == 0 {
		return nil
	}
	if len(list) == 2 {
		a, b := list[0].full, list[1].full
		if (bytes.Equal(a, allIPv4) && bytes.Equal(b, allIPv6)) || (bytes.Equal(a, allIPv6) && bytes.Equal(b, allIPv4)) {
			return nil
		}
	}
	return failRequest(CheckPolicy, "the excluded subtrees are not none or exactly 0.0.0.0/0 and ::/0 (hand-off contract, the request)")
}

// hostName tells whether the text is a host name of the shape that a name constraint may have: one
// or more labels joined by periods; a label has 1 to 63 characters, each a lower-case ASCII letter,
// a digit or a hyphen, and does not start or end with a hyphen (RFC 1034, section 3.5: "Labels must
// be 63 characters or less", "interior characters only letters, digits, and hyphen", a label ends
// with a letter or a digit; RFC 1123, section 2.1 allows a digit at the start); the name has at
// most 253 characters (255 octets on the wire, RFC 1034, section 3.1). The last label is not all
// digits: RFC 1123, section 2.1 says "a valid host name can never have the dotted-decimal form
// #.#.#.#, since at least the highest-level component label will be alphabetic", which is what lets
// a reader tell a name from an address, so 10.0.0.1 is no name. Upper case is refused so that
// a name has one form: "no significance is attached to the case" (RFC 5280, section 4.2.1.6), and a
// verifier that folds only some of the letters would read a name with capitals in another way. So
// there is no empty name, no empty label (a period at the start or the end, two in a row), no
// wildcard and no underscore. Whether a name is a name the requester owns is the policy's. This is
// the syntax that the contract's page names for a DNS name and for a URI constraint (the lengths, the
// hyphen at the edge of a label and the last label come from RFC 1034 and RFC 1123).
func hostName(s string) bool {
	return shapeOfHostName(s) && !numericTopLabel(s)
}

// ValidDNSName tells whether s is a DNS name in the form that a permitted DNS name of a request may have
// (the hand-off contract, "The request"): the form that [ParseRequest] holds a permitted DNS name to.
// A leading period is not part of the form.
func ValidDNSName(s string) bool {
	return hostName(s)
}

// ValidURIHost tells whether s is a URI host in the form that a permitted URI constraint of a request
// may have: a host name, or a period and then a host name. It is the form that [ParseRequest] holds a
// permitted URI constraint to. A host name that follows the period has the form of [ValidDNSName]; the
// period does not count in the length of the name.
func ValidURIHost(s string) bool {
	return hostName(strings.TrimPrefix(s, "."))
}

// shapeOfHostName is the shape of hostName without the rule for the last label.
func shapeOfHostName(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			if c := label[i]; (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return false
			}
		}
	}
	return true
}

// numericTopLabel tells whether the last label of a name of the shape above is all digits.
func numericTopLabel(s string) bool {
	last := s[strings.LastIndexByte(s, '.')+1:]
	return strings.Trim(last, "0123456789") == ""
}
