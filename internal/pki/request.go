package pki

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"slices"
)

// MaxRequestSize is the largest certificate request that [ParseRequest], [ParseRequestFile] and
// [IntermediateTBS] read: 256 KiB, for the DER and for a request file (so a file of that size holds a
// request of about three quarters of it). A larger one is refused before any of it is parsed or
// decoded. The number is the contract's limit for a JSON file ("no more than 256 KiB",
// docs/reference/hand-off-contract.md, "JSON files"), which the contract's rules for a request take
// over for version 1. The size of the request bounds the size of everything built from it: the
// subject, the key and the extension values are copied from it.
const MaxRequestSize = 256 * 1024

// The object identifier of the extensionRequest attribute (RFC 2985, section 5.4.2).
var oidExtensionRequest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 14}

// Request is a certificate request (PKCS #10, RFC 2986) that [ParseRequest] has read. It is read
// once, from its own bytes, and it cannot be changed: the fields are private and a method that
// returns bytes, a key or a list returns a copy. The request has the form that the hand-off contract
// gives ("The request", docs/reference/hand-off-contract.md), its signature has been verified with
// its own key, and everything that can be judged without the issuer has been judged: the subject,
// its text, the extensions with their values, the name constraints. So a Request is exactly what
// [IntermediateTBS] issues for this request: the subject, the key and the extensions that its
// methods return go into the certificate byte for byte. It has not been judged by a policy: whether
// the subject, the zones of the name constraints and the key purposes are the requester's to ask
// for is the policy's. [IntermediateTBS] adds only what needs the issuer: the key and the subject of
// the request against the issuer's.
type Request struct {
	der     []byte
	subject []byte
	name    name
	spki    []byte
	point   []byte
	key     *ecdsa.PublicKey
	exts    []pkix.Extension
	asked   requested
}

// NameAttribute is one attribute of a name: its type and its text.
type NameAttribute struct {
	// Type is the object identifier of the attribute type (2.5.4.3 for the common name).
	Type asn1.ObjectIdentifier
	// Value is the text of the value: printable ASCII, U+0020 to U+007E, with no space at its start
	// or its end and no two spaces in a row (the contract's rule for the subject in version 1; see
	// checkNameText).
	Value string
}

// ParseRequest reads a certificate request from its DER bytes (copied at the top of the call) and returns what it holds. It is the
// only reading of a request in this package: [IntermediateTBS] calls it on its own parameter, so the
// request that a caller shows to a policy through this value is the request that is issued, when
// the caller gives IntermediateTBS the bytes that [Request.DER] returns.
//
// The request is refused unless every byte of it is read and has the form of the contract:
//
//   - it is at most [MaxRequestSize] long (checked before anything is parsed), and is one DER
//     SEQUENCE of exactly three elements, with nothing after it;
//   - the first element, the CertificationRequestInfo, holds exactly a version, a subject, a
//     public key and the attributes, and nothing after them (RFC 2986, section 4.1);
//   - the version is 0 ("v1"), the only value of RFC 2986;
//   - the signature algorithm is ecdsa-with-SHA384, as the contract says, with no parameters and
//     nothing else: not SHA-1, SHA-256 or SHA-512 (check 5, possession);
//   - the public key is ECDSA on P-384, in the canonical form that a P-384 key encodes to, so that
//     the bytes that go into a certificate are the bytes that were read;
//   - the signature is one DER ECDSA value and verifies, over the first element, with that key;
//   - the attributes are exactly one attribute, the extensionRequest (RFC 2985, section 5.4.2),
//     with exactly one value, the Extensions (RFC 5280, section 4.1); no other attribute, such as a
//     challenge password, and no second value. The attributes are read from the bytes of the
//     request and not from a merged reading, because the standard library takes the union of every
//     extension request while OpenSSL reads only the first one, so a tool and this package would
//     disagree about which extensions a request with two of them asks for;
//   - each extension is a SEQUENCE of an object identifier, an optional critical flag that is TRUE
//     when it is present (DER leaves the default out), and the value as an OCTET STRING, with
//     nothing after the value;
//   - the subject is a name by RFC 5280, section 4.1.2.4 with the strings and sizes of Appendix A.1
//     and the contract's text rule for version 1: printable ASCII (U+0020 to U+007E) in every string
//     type, no space at the ends of a value or two in a row, an attribute type once in a relative name
//     and once in a subject but for OU and DC in different relative names (see checkNameText);
//   - the extensions are those of the profile, each once: basic constraints (critical, cA true, path
//     length 0), key usage (critical, keyCertSign, cRLSign and digitalSignature only, in the one DER
//     form), name constraints (critical, required, the rules of nameconstraints.go: permitted DNS
//     names and URI hosts in lower-case host syntax, at least one; excluded none or exactly both IP
//     ranges), and extended key usage (required, not critical: serverAuth, clientAuth or both, each
//     once, and no other purpose, not anyExtendedKeyUsage).
//
// An error wraps [ErrRequest] and says which check of the contract refused the request: see [CheckOf]
// (check 2, malformed: the form; 4, algorithm-unsupported: the key; 5, possession-invalid: the
// algorithm and the signature; 9, policy: the content, which is the strings and the text of the
// subject, the extensions and the name constraints). The text is fixed words. (The one exception is a
// request that the caller changed while the call copied it, an [ErrParams].) The request that is
// returned is nil on every error, a refusal of the content included: there is no half-read request.
//
// The order of refusals. The hand-off contract checks, in this order: the form (2), the key (4), the
// signature (5), the store (6), the evidence (7), the key in the evidence (8) and the policy (9).
// ParseRequest makes 2, 4 and 5 in that order, whatever the order of the faults in the request (a fault
// of form anywhere in the request, in the subject too, is named before a fault of content that stands
// earlier), and then the content, which the contract counts in the policy (9). It makes no check of 6
// to 8: the store and the evidence are the later code's, so a request with a fault of content and a
// fault of the store or of the evidence would, by ParseRequest alone, be refused for its content before
// the later code has run 6 to 8. To keep the contract's order the later code calls [RequestKey] first:
// it makes checks 2, 4 and 5 and returns the key of the request; an error of it is the answer. The
// later code then runs its checks 6 to 8 with that key, and then calls ParseRequest: an error of it is
// the policy refusal (or, if the two calls could ever disagree about 2, 4 and 5, which they cannot,
// the same refusal). The two calls must be given the same bytes, and the caller compares
// [Request.PublicKey] with the key that [RequestKey] returned: see [RequestKey] for why.
func ParseRequest(der []byte) (*Request, error) {
	s, err := readSigned(der)
	if err != nil {
		return nil, err
	}
	// The content (check 9, "policy"): the strings of the subject and their text, the extensions and
	// their values.
	if s.nameErr != nil {
		return nil, s.nameErr
	}
	if err := checkNameText("the subject of the request", s.name, ErrRequest); err != nil {
		return nil, err
	}
	asked, err := requestedExtensions(s.exts)
	if err != nil {
		return nil, err
	}
	return &Request{der: s.der, subject: s.subject, spki: s.spki, point: s.point, key: s.key, name: s.name, exts: s.exts, asked: asked}, nil
}

// RequestKey reads a request as far as the contract's checks 2 (form), 4 (key) and 5 (possession) and
// returns its key; the content of the request is not judged. On a nil error the request is formed, its
// key is ECDSA on P-384 in the canonical form, and the request is signed with ecdsa-with-SHA384 by that
// key. The key is for the contract's checks 6 to 8 only: the check of the store, the check of the
// evidence and the match of the key in the evidence with the key of the request. It says nothing about
// what the request asks for: the subject, the extensions and the name constraints are not read for their
// content, so a request whose key is returned may still be refused by [ParseRequest] (with the check
// [CheckPolicy]). On an error the key is nil and [CheckOf] says malformed, algorithm-unsupported or
// possession-invalid; the error and the key are of the same reading as [ParseRequest] makes of those
// three checks (they share one function), so the two never disagree about them. The copy, the size
// limit and the text of the errors are those of ParseRequest.
//
// The caller gives the same bytes to RequestKey, to [ParseRequest] and to the builders of the
// certificate, and compares [Request.PublicKey] with the key that RequestKey returned before it uses
// the result of its checks 6 to 8 (the store, the evidence and the match of the key). The package
// cannot do that for it: each call reads the bytes it is given and knows no other. With two different
// requests (a file that was read again and changed between the two reads, or two slices that are not
// equal) the checks of the store, of the evidence and of the key would run on the key of one request,
// and a certificate would be issued for the key of another. Read the file once and give that one slice
// to [RequestKeyFile] and to [ParseRequestFile]; give the builders the DER of [Request.DER]; for a
// request that is not a file, give the one slice of DER to every call.
func RequestKey(der []byte) (*ecdsa.PublicKey, error) {
	s, err := readSigned(der)
	if err != nil {
		return nil, err
	}
	return clonePublicKey(s.key), nil
}

// signedRequest is a request that has passed the contract's checks 2, 4 and 5.
type signedRequest struct {
	der, subject, spki, point []byte
	key                       *ecdsa.PublicKey
	exts                      []pkix.Extension
	name                      name  // the subject read, when its strings are of the form (nil with nameErr)
	nameErr                   error // the first fault of content in the strings of the subject, to be judged after the signature
}

// readSigned makes the contract's checks 2, 4 and 5 on a request, in that order, and is the one
// function that does: [ParseRequest] and [RequestKey] call it.
func readSigned(der []byte) (*signedRequest, error) {
	if len(der) > MaxRequestSize {
		return nil, failRequest(CheckMalformed, "the request is longer than %d octets", MaxRequestSize)
	}
	// The request keeps its own copy: the caller's slice may change after the read.
	der, err := copyBytes(der)
	if err != nil {
		return nil, err
	}

	// The form of the request (check 2, "malformed"): the elements, their tags, the version, the
	// attributes, the extensions and the structure of the subject.
	outer, err := readOne(der, asn1.TagSequence)
	if err != nil {
		return nil, failRequest(CheckMalformed, "the request is not one DER sequence with nothing after it (RFC 2986, section 4.2)")
	}
	var info, alg, sig asn1.RawValue
	rest := outer
	for _, part := range []*asn1.RawValue{&info, &alg, &sig} {
		if rest, err = asn1.Unmarshal(rest, part); err != nil {
			return nil, failRequest(CheckMalformed, "the request is not a certification request info, an algorithm and a signature (RFC 2986, section 4.2)")
		}
	}
	if len(rest) != 0 {
		return nil, failRequest(CheckMalformed, "the request has an element after its signature (RFC 2986, section 4.2)")
	}
	if info.Class != asn1.ClassUniversal || info.Tag != asn1.TagSequence || !info.IsCompound {
		return nil, failRequest(CheckMalformed, "the certification request info is not a sequence (RFC 2986, section 4.1)")
	}
	// The algorithm is an AlgorithmIdentifier (an object identifier and optional parameters, nothing
	// after them): any other element is a fault of form. Whether it is ecdsa-with-SHA384 is the
	// possession (check 5), below.
	if !isAlgorithmIdentifier(alg) {
		return nil, failRequest(CheckMalformed, "the signature algorithm of the request is not an AlgorithmIdentifier (RFC 2986, section 4.2)")
	}
	var version, subject, spkiRaw, attributes asn1.RawValue
	rest = info.Bytes
	for _, part := range []*asn1.RawValue{&version, &subject, &spkiRaw, &attributes} {
		if rest, err = asn1.Unmarshal(rest, part); err != nil {
			return nil, failRequest(CheckMalformed, "the certification request info is not a version, a subject, a key and the attributes (RFC 2986, section 4.1)")
		}
	}
	if len(rest) != 0 {
		return nil, failRequest(CheckMalformed, "the certification request info has an element after its attributes (RFC 2986, section 4.1)")
	}
	if !bytes.Equal(version.FullBytes, []byte{tagInteger, 0x01, 0x00}) {
		return nil, failRequest(CheckMalformed, "the version of the request is not 0 (RFC 2986, section 4.1)")
	}
	if subject.Class != asn1.ClassUniversal || subject.Tag != asn1.TagSequence || !subject.IsCompound {
		return nil, failRequest(CheckMalformed, "the subject of the request is not a sequence (RFC 2986, section 4.1)")
	}
	if sig.Class != asn1.ClassUniversal || sig.Tag != asn1.TagBitString || sig.IsCompound || len(sig.Bytes) < 1 || sig.Bytes[0] != 0 {
		return nil, failRequest(CheckMalformed, "the signature of the request is not a bit string of whole octets (RFC 2986, section 4.2)")
	}
	exts, err := readAttributes(attributes)
	if err != nil {
		return nil, err
	}
	// The structure of the whole subject is of the form. readName reads all of it and names a fault of
	// form before a fault of content that stands earlier; a fault of content alone comes back to be
	// judged after the signature.
	n, nameErr := readName("the subject of the request", subject.FullBytes, ErrRequest)
	if nameErr != nil && CheckOf(nameErr) == CheckMalformed {
		return nil, nameErr
	}

	// The key (check 4, "algorithm-unsupported").
	key, canonical, point, err := readKey(spkiRaw)
	if err != nil {
		return nil, err
	}

	// The possession (check 5, "possession-invalid"): the algorithm and the signature.
	if !bytes.Equal(alg.FullBytes, algECDSAWithSHA384) {
		return nil, failRequest(CheckPossession, "the request is not signed with ecdsa-with-SHA384, as the hand-off contract says")
	}
	signature := sig.Bytes[1:]
	if err := checkSignatureForm(signature); err != nil {
		return nil, failRequest(CheckPossession, "the signature of the request is not one DER ECDSA value")
	}
	digest := sha512.Sum384(info.FullBytes)
	if !ecdsa.VerifyASN1(key, digest[:], signature) {
		return nil, failRequest(CheckPossession, "the request does not verify with its own key")
	}
	return &signedRequest{der: der, subject: subject.FullBytes, spki: canonical, point: point, key: key, exts: exts, name: n, nameErr: nameErr}, nil
}

// ParseRequestFile reads a request file, `<stem>.csr.pem` of the hand-off contract: "a PKCS#10
// certificate request (RFC 2986), PEM-armoured with the label `CERTIFICATE REQUEST`. The file holds
// one such block and nothing else." The file is refused unless every rule of the list holds; the
// refusal is [CheckMalformed] for every rule but the last, and the last rule can give the other
// checks of [ParseRequest]:
//
//   - it is at most [MaxRequestSize] octets, checked before it is decoded (the contract gives no
//     size for this file; the number is the one that this package uses for a request, and a file
//     of that size holds a request of about three quarters of it);
//   - it is, from its first octet to its last, these lines, in this order and nothing else: the line
//     -----BEGIN CERTIFICATE REQUEST-----, then one or more lines of base64, then the line
//     -----END CERTIFICATE REQUEST-----, then at most one line end;
//   - a line end is LF or CRLF, and it is the same in the whole file (a file that mixes the two is
//     refused);
//   - a line of base64 has 1 to 76 characters, so no line is empty; the lines need not be of equal
//     length (OpenSSL and Go's pem.Encode write 64 characters, some tools write 76, which is the
//     limit of MIME, RFC 2045). The lines together are the standard base64 text of the DER of the
//     request (RFC 4648, section 4, with its padding) and nothing else: no space, no tab, no padding
//     left out and no bits after the end of the data, so that the joined base64 of one request has
//     one text (the file has not: its line end, its line lengths and its last line end can differ,
//     so a hash of the file is not stable);
//   - the two marker lines are exactly the text above: nothing before the first one (not a line end,
//     not a comment, which PEM decoders skip), no space after either, no header line (a line with a
//     colon) between them, and no second block after the first (OpenSSL reads only the first block,
//     and the request_sha256 of the contract is over the DER, so another block would be unread bytes);
//   - the DER inside is read by [ParseRequest].
//
// So the file is the lines that OpenSSL ("openssl req") and Go (pem.Encode) write, with LF or CRLF,
// with the last line end of the file left out or not. A file that either of them reads and that is
// not of this form (a blank line, a space or a tab inside or after a line, text before the block, a
// carriage return that is not part of a CRLF, a second block, more than one line end at the end) is
// refused.
//
// An error wraps [ErrRequest]. The file is copied at the top of the call. The request is nil on every
// error.
func ParseRequestFile(file []byte) (*Request, error) {
	der, err := readRequestFile(file)
	if err != nil {
		return nil, err
	}
	return ParseRequest(der)
}

// RequestKeyFile is [RequestKey] for a request file: the file is read by the rules of
// [ParseRequestFile] (size, the lines of one PEM block and nothing else), and the key of the
// request that is inside is returned after the contract's checks 2, 4 and 5 and no other. The same
// remarks hold, and the rule of the caller too: read the file once, give that one slice to this
// function and to [ParseRequestFile], and compare [Request.PublicKey] with the key returned here (see
// [RequestKey]). The key is for the checks of the store, the evidence and the
// key match, and it says nothing about what the request asks for.
func RequestKeyFile(file []byte) (*ecdsa.PublicKey, error) {
	der, err := readRequestFile(file)
	if err != nil {
		return nil, err
	}
	return RequestKey(der)
}

// maxPEMLine is the longest line of base64 that a PEM file may hold: the limit of MIME (RFC 2045).
const maxPEMLine = 76

// readRequestFile reads the file of a request and returns the DER inside it, by the rule that the doc
// comment of [ParseRequestFile] gives. The rule is [ReadPEMFile] with the label CERTIFICATE REQUEST;
// this function only says each refusal of it in the words about "the request file" and with the check
// [CheckMalformed], as it always has.
func readRequestFile(file []byte) ([]byte, error) {
	der, err := ReadPEMFile(file, "CERTIFICATE REQUEST")
	if err == nil {
		return der, nil
	}
	fault, ok := pemFaultOf(err)
	if !ok {
		return nil, err
	}
	switch fault {
	case pemTooLong:
		return nil, failRequest(CheckMalformed, "the request file is longer than %d octets", MaxRequestSize)
	case pemNoBlock:
		return nil, failRequest(CheckMalformed, "the request file does not start with a PEM block")
	case pemWrongLabel:
		return nil, failRequest(CheckMalformed, "the PEM block of the request file does not have the label CERTIFICATE REQUEST")
	case pemNoEOL:
		return nil, failRequest(CheckMalformed, "the first line of the request file is not followed by a line end of LF or CRLF")
	case pemNoFooter:
		return nil, failRequest(CheckMalformed, "the request file is not a PEM block")
	case pemAfter:
		return nil, failRequest(CheckMalformed, "the request file has something after its PEM block")
	case pemHeaders:
		return nil, failRequest(CheckMalformed, "the PEM block of the request file has headers")
	case pemLine:
		return nil, failRequest(CheckMalformed, "a line of the base64 text of the request file is empty or longer than %d characters", maxPEMLine)
	default:
		return nil, failRequest(CheckMalformed, "the base64 text of the request file is not the standard base64 of one request")
	}
}

// elementsOf splits the content of a constructed element into its elements. It returns nil when a part
// of the content is not a DER element, and nil when the content is empty; every caller needs at least
// one element, so the two are the same fault there. Reading a structure into a Go struct with
// encoding/asn1 ignores an element after the last field, so a structure whose number of elements
// matters is counted here.
func elementsOf(content []byte) []asn1.RawValue {
	var out []asn1.RawValue
	for len(content) > 0 {
		var v asn1.RawValue
		rest, err := asn1.Unmarshal(content, &v)
		if err != nil {
			return nil
		}
		out = append(out, v)
		content = rest
	}
	return out
}

// isAlgorithmIdentifier tells whether v is an AlgorithmIdentifier (RFC 5280, section 4.1.1.2): a
// SEQUENCE of an object identifier and, optionally, one element of parameters, and nothing else. It is
// the test of the algorithm of the signature and of the algorithm of the key.
func isAlgorithmIdentifier(v asn1.RawValue) bool {
	if v.Class != asn1.ClassUniversal || v.Tag != asn1.TagSequence || !v.IsCompound {
		return false
	}
	parts := elementsOf(v.Bytes)
	if len(parts) < 1 || len(parts) > 2 {
		return false
	}
	var oid asn1.ObjectIdentifier
	_, err := asn1.Unmarshal(parts[0].FullBytes, &oid)
	return err == nil
}

// isSubjectPublicKeyInfo tells whether v, one element, is a SubjectPublicKeyInfo (RFC 5280, section
// 4.1): a SEQUENCE of an AlgorithmIdentifier and a BIT STRING, and nothing else.
func isSubjectPublicKeyInfo(v asn1.RawValue) bool {
	if v.Class != asn1.ClassUniversal || v.Tag != asn1.TagSequence || !v.IsCompound {
		return false
	}
	parts := elementsOf(v.Bytes)
	if len(parts) != 2 || !isAlgorithmIdentifier(parts[0]) {
		return false
	}
	bits := parts[1]
	return bits.Class == asn1.ClassUniversal && bits.Tag == asn1.TagBitString && !bits.IsCompound
}

// readOne reads one DER element of the universal class and the tag, constructed, that is the whole
// of b, and returns its content.
func readOne(b []byte, tag int) ([]byte, error) {
	var v asn1.RawValue
	rest, err := asn1.Unmarshal(b, &v)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 || v.Class != asn1.ClassUniversal || v.Tag != tag || !v.IsCompound {
		return nil, asn1.SyntaxError{Msg: "not the element that was expected"}
	}
	return v.Bytes, nil
}

// readKey reads a SubjectPublicKeyInfo and returns the key, the canonical encoding of the key (which
// must be the bytes read) and the point of the key (the content of its BIT STRING). A key that is not
// ECDSA on P-384 is "algorithm-unsupported" when the element is a SubjectPublicKeyInfo (an
// AlgorithmIdentifier and a bit string, see [isAlgorithmIdentifier]), and "malformed" when it is not
// (an algorithm that is no AlgorithmIdentifier is a key that is not a public key structure), or when a
// P-384 key is not in the canonical form.
func readKey(spkiElement asn1.RawValue) (*ecdsa.PublicKey, []byte, []byte, error) {
	if !isSubjectPublicKeyInfo(spkiElement) {
		return nil, nil, nil, failRequest(CheckMalformed, "the key of the request is not a SubjectPublicKeyInfo (RFC 5280, section 4.1)")
	}
	raw := spkiElement.FullBytes
	parsed, err := x509.ParsePKIXPublicKey(raw)
	if err != nil {
		return nil, nil, nil, failRequest(CheckAlgorithm, "the key of the request is not ECDSA on P-384")
	}
	canonical, point, err := spki(parsed)
	if err != nil {
		return nil, nil, nil, failRequest(CheckAlgorithm, "the key of the request is not ECDSA on P-384")
	}
	if !bytes.Equal(canonical, raw) {
		return nil, nil, nil, failRequest(CheckMalformed, "the key of the request is not in the canonical form")
	}
	return parsed.(*ecdsa.PublicKey), canonical, point, nil
}

// readAttributes reads the attributes element, [0] IMPLICIT SET OF Attribute, of a request: exactly
// one attribute, the extensionRequest, with exactly one value, and returns the extensions in the
// order the request has them.
func readAttributes(attributes asn1.RawValue) ([]pkix.Extension, error) {
	if attributes.Class != asn1.ClassContextSpecific || attributes.Tag != 0 || !attributes.IsCompound {
		return nil, failRequest(CheckMalformed, "the attributes of the request are not [0] in the constructed form (RFC 2986, section 4.1)")
	}
	var attr asn1.RawValue
	rest, err := asn1.Unmarshal(attributes.Bytes, &attr)
	if err != nil || attr.Class != asn1.ClassUniversal || attr.Tag != asn1.TagSequence || !attr.IsCompound {
		return nil, failRequest(CheckMalformed, "the request has no attribute: it must have the extension request (RFC 2985, section 5.4.2)")
	}
	if len(rest) != 0 {
		return nil, failRequest(CheckMalformed, "the request has more than one attribute: it may have only the extension request")
	}
	var typ asn1.ObjectIdentifier
	values, err := asn1.Unmarshal(attr.Bytes, &typ)
	if err != nil || !typ.Equal(oidExtensionRequest) {
		return nil, failRequest(CheckMalformed, "the attribute of the request is not the extension request (RFC 2985, section 5.4.2)")
	}
	set, err := readOne(values, asn1.TagSet)
	if err != nil {
		return nil, failRequest(CheckMalformed, "the values of the extension request are not one set with nothing after it (RFC 2985, section 5.4.2)")
	}
	var list asn1.RawValue
	rest, err = asn1.Unmarshal(set, &list)
	if err != nil || list.Class != asn1.ClassUniversal || list.Tag != asn1.TagSequence || !list.IsCompound {
		return nil, failRequest(CheckMalformed, "the extension request has no value that is the extensions (RFC 2985, section 5.4.2)")
	}
	if len(rest) != 0 {
		return nil, failRequest(CheckMalformed, "the extension request has more than one value: it may have only one")
	}
	if len(list.Bytes) == 0 {
		return nil, failRequest(CheckMalformed, "the extensions of the request are an empty sequence (RFC 5280, section 4.1: SIZE (1..MAX))")
	}
	var exts []pkix.Extension
	for body := list.Bytes; len(body) > 0; {
		var raw asn1.RawValue
		if body, err = asn1.Unmarshal(body, &raw); err != nil || raw.Class != asn1.ClassUniversal || raw.Tag != asn1.TagSequence || !raw.IsCompound {
			return nil, failRequest(CheckMalformed, "an extension of the request is not a DER sequence (RFC 5280, section 4.1)")
		}
		e, err := readExtension(raw.Bytes)
		if err != nil {
			return nil, err
		}
		exts = append(exts, e)
	}
	return exts, nil
}

// readExtension reads the content of an Extension: an object identifier, a critical flag that is
// TRUE when it is there, and an OCTET STRING, and nothing after it.
func readExtension(content []byte) (pkix.Extension, error) {
	var e pkix.Extension
	var id asn1.ObjectIdentifier
	rest, err := asn1.Unmarshal(content, &id)
	if err != nil {
		return e, failRequest(CheckMalformed, "an extension of the request does not start with an object identifier (RFC 5280, section 4.1)")
	}
	e.Id = id
	var next asn1.RawValue
	if rest, err = asn1.Unmarshal(rest, &next); err != nil {
		return e, failRequest(CheckMalformed, "an extension of the request has no value (RFC 5280, section 4.1)")
	}
	if next.Class == asn1.ClassUniversal && next.Tag == asn1.TagBoolean && !next.IsCompound {
		if !bytes.Equal(next.FullBytes, []byte{tagBoolean, 0x01, 0xff}) {
			return e, failRequest(CheckMalformed, "an extension of the request has a critical flag that is not TRUE: DER leaves FALSE out (X.690, 11.5)")
		}
		e.Critical = true
		if rest, err = asn1.Unmarshal(rest, &next); err != nil {
			return e, failRequest(CheckMalformed, "an extension of the request has no value (RFC 5280, section 4.1)")
		}
	}
	if next.Class != asn1.ClassUniversal || next.Tag != asn1.TagOctetString || next.IsCompound {
		return e, failRequest(CheckMalformed, "an extension of the request has a value that is not an octet string (RFC 5280, section 4.1)")
	}
	if len(rest) != 0 {
		return e, failRequest(CheckMalformed, "an extension of the request has an element after its value (RFC 5280, section 4.1)")
	}
	e.Value = next.Bytes
	return e, nil
}

// DER returns a copy of the bytes that were read: the request as the requester signed it, and the
// bytes whose SHA-256 is the request_sha256 of the hand-off contract. A caller that hashes these
// bytes and gives them to [IntermediateTBS] is sure that the request it hashed, showed and checked
// is the request that is issued.
func (r *Request) DER() []byte {
	if r == nil {
		return nil
	}
	return slices.Clone(r.der)
}

// Subject returns a copy of the DER of the subject name, as the request has it. It goes into the
// certificate byte for byte. [Request.SubjectName] has the same name read.
func (r *Request) Subject() []byte {
	if r == nil {
		return nil
	}
	return slices.Clone(r.subject)
}

// SubjectName returns the subject read: its relative names in order, each with its attributes in
// order. The smallest form that a policy needs, so that it does not parse the DER again with a reader
// of its own: the type and the text of each attribute, with no string type and no byte of the
// encoding. The DER stays available from [Request.Subject], which is what is issued.
func (r *Request) SubjectName() [][]NameAttribute {
	if r == nil {
		return nil
	}
	out := make([][]NameAttribute, len(r.name))
	for i, set := range r.name {
		out[i] = make([]NameAttribute, len(set))
		for j, a := range set {
			out[i][j] = NameAttribute{Type: slices.Clone(a.typ), Value: string(a.value)}
		}
	}
	return out
}

// NameConstraints returns the name constraints of the request, read: the permitted DNS names and
// URI constraints, and whether every IP address is excluded. A request that is read has them (they
// are required), and they are of the form that this package issues.
func (r *Request) NameConstraints() NameConstraints {
	if r == nil {
		return NameConstraints{}
	}
	return NameConstraints{
		PermittedDNS:  slices.Clone(r.asked.nc.PermittedDNS),
		PermittedURI:  slices.Clone(r.asked.nc.PermittedURI),
		ExcludesAllIP: r.asked.nc.ExcludesAllIP,
	}
}

// PublicKey returns a copy of the public key of the request: ECDSA on P-384. The key that signed
// the request is this key.
func (r *Request) PublicKey() *ecdsa.PublicKey {
	if r == nil {
		return nil
	}
	return clonePublicKey(r.key)
}

// Extensions returns a copy of the extensions that the request asks for, in the order it has them:
// the object identifier, the critical flag and the value, which is the content of the OCTET STRING.
// These are the values that [IntermediateTBS] issues, byte for byte (it adds the two key
// identifiers, and writes the basic constraints from the constant that the request has).
func (r *Request) Extensions() []pkix.Extension {
	if r == nil {
		return nil
	}
	out := make([]pkix.Extension, len(r.exts))
	for i, e := range r.exts {
		out[i] = pkix.Extension{Id: slices.Clone(e.Id), Critical: e.Critical, Value: slices.Clone(e.Value)}
	}
	return out
}

// clonePublicKey returns a key that shares nothing with k, or nil when k is not a point on P-384.
func clonePublicKey(k *ecdsa.PublicKey) *ecdsa.PublicKey {
	b, err := k.Bytes()
	if err != nil {
		return nil
	}
	c, err := ecdsa.ParseUncompressedPublicKey(elliptic.P384(), b)
	if err != nil {
		return nil
	}
	return c
}
