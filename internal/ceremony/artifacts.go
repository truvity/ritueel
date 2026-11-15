package ceremony

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"time"

	"ritueel.id/ritueel/internal/canonjson"
	"ritueel.id/ritueel/internal/ceremony/files"
	"ritueel.id/ritueel/internal/jsonset"
	"ritueel.id/ritueel/internal/jws"
	"ritueel.id/ritueel/internal/rootlist"
	"ritueel.id/ritueel/internal/trustset"
)

// The checks of the artifacts of the first apply (record 0005, rule 12: each artifact is
// judged by code that did not make it). The code that makes a root certificate is internal/pki, and
// the code that makes the root list is internal/trustset. These checks read what was made with
// crypto/x509, encoding/asn1, encoding/pem, encoding/json and the readers of internal/rootlist,
// internal/jws and internal/ceremony/files. They do not import internal/pki, and from
// internal/trustset they take only the type of a Set, which they read through its accessors, and a
// limit: no builder of it is called.
//
// Each check reads the artifact as the bytes that will be written, and compares it with the plan and
// with the key that was born. A mismatch is an [*ArtifactError] that names the artifact and the
// member and shows no key and no digest of a secret.

// ArtifactError is a check of an artifact that failed: which artifact, which member, and what is
// wrong. Its text is made once, in printable ASCII.
type ArtifactError struct {
	// Artifact names the check and the artifact, for example "root certificate A".
	Artifact string
	// Member is the member or the part at fault.
	Member string
	// Reason says what is wrong.
	Reason string
}

// Error says the artifact, the member and the reason.
func (e *ArtifactError) Error() string {
	if e == nil {
		return "artifact check: no error"
	}
	return "artifact check " + e.Artifact + ": " + e.Member + ": " + e.Reason
}

// artifactErr makes an ArtifactError. The arguments that come from outside are the caller's to
// escape; the text as a whole goes through the escape of jsonset once more.
func artifactErr(artifact, member, format string, args ...any) *ArtifactError {
	return &ArtifactError{
		Artifact: jsonset.Escape(artifact),
		Member:   jsonset.Escape(member),
		Reason:   jsonset.Escape(fmt.Sprintf(format, args...)),
	}
}

// The identifiers that the checks compare with. They are written here from the pages and are not
// taken from internal/pki.
var (
	oidCommonName       = asn1.ObjectIdentifier{2, 5, 4, 3}
	oidECDSAWithSHA384  = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	oidBasicConstraints = asn1.ObjectIdentifier{2, 5, 29, 19}
	oidSubjectKeyID     = asn1.ObjectIdentifier{2, 5, 29, 14}
	oidKeyUsage         = asn1.ObjectIdentifier{2, 5, 29, 15}
	oidAuthorityKeyID   = asn1.ObjectIdentifier{2, 5, 29, 35}
	oidNameConstraints  = asn1.ObjectIdentifier{2, 5, 29, 30}
)

// The names of the checks, in the order that they run: the members of [Made.Checked].
const (
	// CheckedRootCertificate is [CheckRootCertificate].
	CheckedRootCertificate = "root-certificate"
	// CheckedRemovalAuthorisation is [CheckRemovalAuthorisation].
	CheckedRemovalAuthorisation = "removal-authorisation"
	// CheckedRootList is [CheckRootList].
	CheckedRootList = "root-list"
	// CheckedCABundle is [CheckCABundle].
	CheckedCABundle = "ca-bundle"
	// CheckedRootJSON is [CheckRootJSON].
	CheckedRootJSON = "root-json"
	// CheckedPlan is [CheckPlanAgainstKeys].
	CheckedPlan = "plan"
	// CheckedJournals is [CheckJournals].
	CheckedJournals = "journals"
)

// maxCertificateBytes is the most bytes of a certificate that a check reads: a root certificate of
// the profile is under 600 bytes.
const maxCertificateBytes = 16 << 10

// testMark ends the common name of a test root (docs/reference/bundle.md, "The root certificate").
const testMark = " (TEST ONLY)"

// listExpiryMonths is the time from signed_at to expires_at of a root list: 13 calendar months
// (docs/reference/root-list.md, "The list").
const listExpiryMonths = 13

// addMonthsClamped adds n calendar months to t in UTC: the same day and time of the month, or the
// last day of the month when it has none. It is written here, and is not internal/pki's function, so
// that the check of a validity is not made by the code that made it.
func addMonthsClamped(t time.Time, n int) time.Time {
	t = t.UTC()
	y, m, d := t.Date()
	total := int(m) - 1 + n
	year := y + total/12
	month := time.Month(total%12 + 1)
	if last := time.Date(year, month+1, 0, 0, 0, 0, 0, time.UTC).Day(); d > last {
		d = last
	}
	return time.Date(year, month, d, t.Hour(), t.Minute(), t.Second(), 0, time.UTC)
}

// pinOfSPKI is the SHA-256 of a DER SubjectPublicKeyInfo, in lower-case hexadecimal: the pin.
func pinOfSPKI(spki []byte) string {
	sum := sha256.Sum256(spki)
	return hex.EncodeToString(sum[:])
}

// RootCertWant is what [CheckRootCertificate] compares a root certificate with: the name from ritueel.yaml and the label,
// the pin of the key that was born, and the serial and the times that the plan names.
type RootCertWant struct {
	// Name is the name of the bundle, from ritueel.yaml.
	Name string
	// Label is the label of the root key.
	Label string
	// Pin is the pin of the key that was born: the SHA-256 of its DER SubjectPublicKeyInfo.
	Pin string
	// Serial is the serial of the plan, in lower-case hexadecimal.
	Serial string
	// NotBefore is the ceremony time.
	NotBefore time.Time
	// NotAfter is the end of the validity that the plan names.
	NotAfter time.Time
}

// tbsDoc is the TBSCertificate as RFC 5280 writes it. It is read, and written again, so that a
// certificate that holds a part this struct does not know is found.
type tbsDoc struct {
	Raw        asn1.RawContent
	Version    int `asn1:"optional,explicit,default:0,tag:0"`
	Serial     *big.Int
	SigAlg     pkix.AlgorithmIdentifier
	Issuer     asn1.RawValue
	Validity   tbsValidity
	Subject    asn1.RawValue
	PublicKey  asn1.RawValue
	IssuerUID  asn1.BitString   `asn1:"optional,tag:1"`
	SubjectUID asn1.BitString   `asn1:"optional,tag:2"`
	Extensions []pkix.Extension `asn1:"omitempty,optional,explicit,tag:3"`
}

type tbsValidity struct {
	NotBefore, NotAfter asn1.RawValue
}

// CheckRootCertificate judges the DER of the root certificate of one label against the
// profile of docs/reference/bundle.md, "The root certificate", the plan and the key that was born.
// It takes the certificate with x509.ParseCertificate (no byte after it) and reads the TBSCertificate
// and the extension values with encoding/asn1. It requires version 3; the signature algorithm
// ecdsa-with-SHA384 in both places; the issuer equal to the subject, with one common name,
// "<name> Root <label> (TEST ONLY)"; a public key on P-384 whose SPKI SHA-256 is the pin; the serial of
// the plan; notBefore the ceremony time and notAfter the time of the plan and 36 calendar months later;
// the extensions basic constraints (critical, cA, no path length), subject key identifier (not
// critical, the leftmost 160 bits of the SHA-256 of the public key bits) and key usage (critical,
// keyCertSign and cRLSign), in that order, and no other, the authority key identifier and the name
// constraints included; no unique identifier; and a signature that verifies with the certificate's
// own key (CheckSignatureFrom). The error is an [*ArtifactError].
func CheckRootCertificate(der []byte, w RootCertWant) error {
	art := "root certificate " + w.Label
	bad := func(member, format string, args ...any) error { return artifactErr(art, member, format, args...) }
	if len(der) == 0 || len(der) > maxCertificateBytes {
		return bad("certificate", "is empty or longer than %d bytes", maxCertificateBytes)
	}
	var outer asn1.RawValue
	if rest, err := asn1.Unmarshal(der, &outer); err != nil {
		return bad("certificate", "is not one DER value")
	} else if len(rest) != 0 {
		return bad("certificate", "has bytes after the DER value")
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return bad("certificate", "is refused by the standard library: %v", err)
	}
	var tbs tbsDoc
	if rest, err := asn1.Unmarshal(cert.RawTBSCertificate, &tbs); err != nil || len(rest) != 0 {
		return bad("tbsCertificate", "is not the TBSCertificate of RFC 5280")
	}
	again := tbs
	again.Raw = nil
	if back, err := asn1.Marshal(again); err != nil || !bytes.Equal(back, cert.RawTBSCertificate) {
		return bad("tbsCertificate", "is not written in the one DER form, or holds a part that is not known")
	}
	if cert.Version != 3 || tbs.Version != 2 {
		return bad("version", "is not 3")
	}
	if cert.SignatureAlgorithm != x509.ECDSAWithSHA384 || !tbs.SigAlg.Algorithm.Equal(oidECDSAWithSHA384) || len(tbs.SigAlg.Parameters.FullBytes) != 0 {
		return bad("signature algorithm", "is not ecdsa-with-SHA384 with no parameters, in both places")
	}
	if err := checkSerial(bad, tbs.Serial, w.Serial); err != nil {
		return err
	}
	if err := checkRootNames(bad, tbs, w); err != nil {
		return err
	}
	if err := checkRootValidity(bad, tbs, cert, w); err != nil {
		return err
	}
	if err := checkRootKey(bad, cert, w.Pin); err != nil {
		return err
	}
	if len(tbs.IssuerUID.Bytes) != 0 || len(tbs.SubjectUID.Bytes) != 0 {
		return bad("unique identifiers", "are present")
	}
	if err := checkRootExtensions(bad, tbs, cert); err != nil {
		return err
	}
	if err := cert.CheckSignatureFrom(cert); err != nil {
		return bad("signature", "does not verify with the certificate's own key")
	}
	return nil
}

// checkSerial compares the serial of the certificate with the serial of the plan.
func checkSerial(bad func(string, string, ...any) error, got *big.Int, planSerial string) error {
	want, ok := new(big.Int).SetString(planSerial, 16)
	if !ok || want.Sign() <= 0 {
		return bad("serial", "the serial of the plan is not a positive number in hexadecimal")
	}
	if got == nil || got.Cmp(want) != 0 {
		return bad("serial", "is not the serial of the plan")
	}
	return nil
}

// checkRootNames judges the issuer and the subject: the same bytes, one common name, the name of the
// bundle, " Root ", the label and " (TEST ONLY)".
func checkRootNames(bad func(string, string, ...any) error, tbs tbsDoc, w RootCertWant) error {
	if !bytes.Equal(tbs.Issuer.FullBytes, tbs.Subject.FullBytes) {
		return bad("issuer", "is not the subject")
	}
	var seq pkix.RDNSequence
	if rest, err := asn1.Unmarshal(tbs.Subject.FullBytes, &seq); err != nil || len(rest) != 0 {
		return bad("subject", "is not a name")
	}
	if len(seq) != 1 || len(seq[0]) != 1 || !seq[0][0].Type.Equal(oidCommonName) {
		return bad("subject", "is not one common name and nothing else")
	}
	cn, ok := seq[0][0].Value.(string)
	if !ok {
		return bad("subject", "the common name is not a text")
	}
	if want := w.Name + " Root " + w.Label + testMark; cn != want {
		return bad("subject", "the common name is not <name> Root <label> (TEST ONLY) for this key")
	}
	return nil
}

// checkRootValidity judges the two times: their encoding, the ceremony time, the end of the plan, and
// the 36 calendar months between them.
func checkRootValidity(bad func(string, string, ...any) error, tbs tbsDoc, cert *x509.Certificate, w RootCertWant) error {
	for _, v := range []struct {
		name string
		raw  asn1.RawValue
		at   time.Time
	}{{"notBefore", tbs.Validity.NotBefore, cert.NotBefore}, {"notAfter", tbs.Validity.NotAfter, cert.NotAfter}} {
		wantTag := asn1.TagUTCTime
		if y := v.at.UTC().Year(); y < 1950 || y >= 2050 {
			wantTag = asn1.TagGeneralizedTime
		}
		if v.raw.Class != asn1.ClassUniversal || v.raw.Tag != wantTag || v.raw.IsCompound {
			return bad(v.name, "is not written with the time type that RFC 5280 asks for its year")
		}
		if !isRFC5280Time(v.raw.Bytes, wantTag) {
			return bad(v.name, "is not written in the form of RFC 5280: Zulu, with seconds, no offset and no fraction")
		}
	}
	if !cert.NotBefore.Equal(w.NotBefore) || cert.NotBefore.Nanosecond() != 0 {
		return bad("notBefore", "is not the ceremony time")
	}
	if !cert.NotAfter.Equal(w.NotAfter) {
		return bad("notAfter", "is not the end of the validity that the plan names")
	}
	if !cert.NotAfter.Equal(addMonthsClamped(cert.NotBefore, 36)) {
		return bad("notAfter", "is not 36 calendar months after notBefore")
	}
	return nil
}

// isRFC5280Time reports whether b, the content bytes of a time of a certificate, is written as RFC
// 5280, 4.1.2.5, asks: a UTCTime as YYMMDDhhmmssZ (13 bytes) and a GeneralizedTime as YYYYMMDDhhmmssZ
// (15 bytes), digits only, then Z. The standard library reads the other spellings of the same instant (no
// seconds, an offset, a fraction), so the bytes are judged as they stand and not only the instant.
func isRFC5280Time(b []byte, tag int) bool {
	n := 13
	if tag == asn1.TagGeneralizedTime {
		n = 15
	}
	if len(b) != n || b[n-1] != 'Z' {
		return false
	}
	for _, c := range b[:n-1] {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// checkRootKey judges the public key: ECDSA on P-384, with the pin that was born.
func checkRootKey(bad func(string, string, ...any) error, cert *x509.Certificate, pin string) error {
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if cert.PublicKeyAlgorithm != x509.ECDSA || !ok || pub.Curve != elliptic.P384() {
		return bad("public key", "is not an ECDSA key on P-384")
	}
	if pinOfSPKI(cert.RawSubjectPublicKeyInfo) != pin {
		return bad("public key", "is not the key that was born in this ceremony")
	}
	return nil
}

// checkRootExtensions judges the extensions: exactly three, in the order of the page, each with the
// criticality and the value that the page gives. The values are written here with encoding/asn1.
func checkRootExtensions(bad func(string, string, ...any) error, tbs tbsDoc, cert *x509.Certificate) error {
	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if rest, err := asn1.Unmarshal(cert.RawSubjectPublicKeyInfo, &spki); err != nil || len(rest) != 0 {
		return bad("public key", "is not a SubjectPublicKeyInfo")
	}
	keyID := sha256.Sum256(spki.PublicKey.Bytes)
	basic, err := asn1.Marshal(struct{ IsCA bool }{true})
	if err != nil {
		return bad("basic constraints", "cannot be written for the comparison")
	}
	ski, err := asn1.Marshal(keyID[:20])
	if err != nil {
		return bad("subject key identifier", "cannot be written for the comparison")
	}
	usage, err := asn1.Marshal(asn1.BitString{Bytes: []byte{0x06}, BitLength: 7})
	if err != nil {
		return bad("key usage", "cannot be written for the comparison")
	}
	want := []struct {
		name     string
		id       asn1.ObjectIdentifier
		critical bool
		value    []byte
	}{
		{"basic constraints", oidBasicConstraints, true, basic},
		{"subject key identifier", oidSubjectKeyID, false, ski},
		{"key usage", oidKeyUsage, true, usage},
	}
	for _, e := range tbs.Extensions {
		switch {
		case e.Id.Equal(oidAuthorityKeyID):
			return bad("extensions", "an authority key identifier is present")
		case e.Id.Equal(oidNameConstraints):
			return bad("extensions", "name constraints are present")
		}
	}
	if len(tbs.Extensions) != len(want) {
		return bad("extensions", "there are %d, and the profile has basic constraints, subject key identifier and key usage, and nothing else", len(tbs.Extensions))
	}
	for i, w := range want {
		e := tbs.Extensions[i]
		if !e.Id.Equal(w.id) {
			return bad("extensions", "the extension %d is not %s: the order is basic constraints, subject key identifier, key usage", i+1, w.name)
		}
		if e.Critical != w.critical {
			return bad(w.name, "has the wrong criticality")
		}
		if !bytes.Equal(e.Value, w.value) {
			return bad(w.name, "does not have the value of the profile")
		}
	}
	if !cert.BasicConstraintsValid || !cert.IsCA || cert.MaxPathLen != -1 || cert.MaxPathLenZero {
		return bad("basic constraints", "are not cA true with no path length, as the standard library reads them")
	}
	if cert.KeyUsage != x509.KeyUsageCertSign|x509.KeyUsageCRLSign {
		return bad("key usage", "is not keyCertSign and cRLSign, as the standard library reads it")
	}
	if !bytes.Equal(cert.SubjectKeyId, keyID[:20]) || len(cert.AuthorityKeyId) != 0 {
		return bad("subject key identifier", "is not the leftmost 160 bits of the SHA-256 of the key, or an authority key identifier stands")
	}
	return nil
}

// isCompactText reports whether s is a text of the compact JWS alphabet: ASCII letters, digits, hyphen, underscore and
// dots.
func isCompactText(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.'
		if !ok {
			return false
		}
	}
	return true
}

// CheckRemovalAuthorisation judges the removal authorisation of one label. text is the text
// that was made, stored is the file as it is read back from the key store, pin is the pin of the key
// and cert is the DER of its certificate. It requires ASCII with two dots and no line feed;
// rootlist.CheckRemoval with the pin as the only held key (the reader that a host uses); the
// certificate in x5c to be the certificate just made; and the stored file to be the same text. The
// error is an [*ArtifactError].
func CheckRemovalAuthorisation(label, pin string, cert []byte, text string, stored []byte) error {
	art := "removal authorisation " + label
	bad := func(member, format string, args ...any) error { return artifactErr(art, member, format, args...) }
	if text == "" || len(text) > trustset.MaxBytes || !isCompactText(text) || strings.Count(text, ".") != 2 {
		return bad("text", "is not ASCII of three parts with two dots and no line break")
	}
	entry := rootlist.Removal{Label: label, X509SPKISHA256: pin, Authorisation: text}
	if err := rootlist.CheckRemoval(entry, nil, []string{pin}); err != nil {
		return bad("signature", "is refused by the reader of the root list: %v", err)
	}
	header, _, _ := strings.Cut(text, ".")
	raw, err := base64.RawURLEncoding.DecodeString(header)
	if err != nil {
		return bad("protected header", "is not Base64url")
	}
	var h struct {
		X5C []string `json:"x5c"`
	}
	if err := json.Unmarshal(raw, &h); err != nil || len(h.X5C) != 1 {
		return bad("x5c", "does not hold exactly one certificate")
	}
	if got, err := base64.StdEncoding.DecodeString(h.X5C[0]); err != nil || !bytes.Equal(got, cert) {
		return bad("x5c", "is not the certificate that was just made for this key")
	}
	if !bytes.Equal(stored, []byte(text)) {
		return bad("stored file", "is not the text that was made")
	}
	return nil
}

// RootListWant is what [CheckRootList] and [CheckCABundle] compare the first trust set with.
type RootListWant struct {
	// Labels are the labels of the keys, in label order.
	Labels []string
	// Pins are their pins, in the same order.
	Pins []string
	// Certificates are the DER of their certificates, in the same order, the ones [CheckRootCertificate] judged.
	Certificates [][]byte
	// SignedAt is the ceremony time.
	SignedAt time.Time
	// Signer is the label of the key that signs the list: the lowest label.
	Signer string
}

func (w RootListWant) valid() bool {
	n := len(w.Labels)
	return n > 0 && len(w.Pins) == n && len(w.Certificates) == n && slices.Contains(w.Labels, w.Signer)
}

// CheckRootList judges root-list.json and root-list.jws of the first trust set with
// rootlist.Verify, trusting the pins of the keys alone and with the clock at signed_at, as a host
// that was installed with those pins would read it. It requires Accepted, and neither Again nor
// Wayback; sequence 1; signed_at the ceremony time; expires_at 13 calendar months later; no
// last_record_sha256 and no removals; the roots in label order with their pins and no OpenPGP
// fingerprint; one signature, whose kid is the pin of the signer and whose x5c is that key's
// certificate; and the name of the set, "1-" and the first eight characters of the SHA-256 of
// root-list.json. It returns the list that the reader accepted. The error is an [*ArtifactError].
func CheckRootList(set *trustset.Set, w RootListWant) (*rootlist.List, error) {
	const art = "root list"
	bad := func(member, format string, args ...any) error { return artifactErr(art, member, format, args...) }
	if set == nil || len(set.ListJSON()) == 0 || len(set.ListJWS()) == 0 {
		return nil, bad("set", "is empty")
	}
	if !w.valid() {
		return nil, bad("want", "the keys of the check are not whole")
	}
	trust, err := rootlist.PinTrust(w.Pins)
	if err != nil {
		return nil, bad("pins", "are refused by the reader: %v", err)
	}
	listJSON, listJWS := set.ListJSON(), set.ListJWS()
	v := rootlist.Verify(rootlist.Signed{JSON: listJSON, JWS: listJWS}, trust, w.SignedAt)
	if !v.Accepted {
		return nil, bad("verdict", "the reader of the root list refuses it: check %d, %s, %s", v.Check, string(v.Reason), v.Detail)
	}
	if v.Again || v.Wayback || v.List == nil {
		return nil, bad("verdict", "is not a plain first list")
	}
	list := v.List
	if list.Version != 1 || list.Sequence != 1 {
		return nil, bad("sequence", "is not 1")
	}
	if !list.SignedAt.Equal(w.SignedAt) || !list.ExpiresAt.Equal(addMonthsClamped(w.SignedAt, listExpiryMonths)) {
		return nil, bad("signed_at", "is not the ceremony time, or expires_at is not 13 calendar months later")
	}
	if list.LastRecordSHA256 != "" || len(list.Removals) != 0 {
		return nil, bad("last_record_sha256", "or removals are present in the first list")
	}
	if len(list.Roots) != len(w.Labels) {
		return nil, bad("roots", "are not the keys that were born")
	}
	for i, r := range list.Roots {
		if r.Label != w.Labels[i] || r.X509SPKISHA256 != w.Pins[i] || r.OpenPGPFingerprint != "" {
			return nil, bad("roots", "the entry %d is not the key %s with its pin and no OpenPGP fingerprint", i+1, w.Labels[i])
		}
	}
	if err := checkListSignature(listJWS, w); err != nil {
		return nil, err
	}
	if got := set.Signers(); len(got) != 1 || got[0] != w.Signer {
		return nil, bad("signers", "are not the one key that signs the first list")
	}
	sum := sha256.Sum256(listJSON)
	if want := "1-" + hex.EncodeToString(sum[:])[:8]; set.Name() != want {
		return nil, bad("name", "of the set is not its number and the first eight characters of the digest of root-list.json")
	}
	return list, nil
}

// checkListSignature judges the detached general JWS: one signature, the kid of the signer, and its
// certificate.
func checkListSignature(listJWS []byte, w RootListWant) error {
	bad := func(member, format string, args ...any) error {
		return artifactErr("root list", member, format, args...)
	}
	g, err := jws.ParseGeneral(listJWS, rootlist.ListTyp)
	if err != nil {
		return bad("root-list.jws", "is refused by its reader: %v", err)
	}
	if len(g.Signatures) != 1 {
		return bad("signatures", "there are %d, and the first list has one", len(g.Signatures))
	}
	i := slices.Index(w.Labels, w.Signer)
	s := g.Signatures[0]
	if s.Header.Kid != w.Pins[i] || s.Cert == nil || !bytes.Equal(s.Cert.Raw, w.Certificates[i]) {
		return bad("signature", "is not by the key of the lowest label, with the certificate that was just made")
	}
	return nil
}

// CheckCABundle judges ca-bundle.pem against the accepted list with rootlist.VerifyCABundle,
// and walks it with encoding/pem: the first line is "# trust-sequence: 1", and the certificates are
// the ones of the root certificates, in the order of the list, byte for byte. The error is an [*ArtifactError].
func CheckCABundle(bundle []byte, list *rootlist.List, w RootListWant) error {
	const art = "ca-bundle.pem"
	bad := func(member, format string, args ...any) error { return artifactErr(art, member, format, args...) }
	if list == nil || len(list.Roots) == 0 || !w.valid() {
		return bad("list", "there is no accepted list to compare with")
	}
	if v := rootlist.VerifyCABundle(bundle, list); !v.Accepted {
		return bad("verdict", "the reader of the CA bundle refuses it: %s", v.Detail)
	}
	body, ok := bytes.CutPrefix(bundle, []byte("# trust-sequence: 1\n"))
	if !ok {
		return bad("first line", "is not the trust sequence line of the first set")
	}
	for i := range w.Certificates {
		blk, rest := pem.Decode(body)
		if blk == nil || blk.Type != "CERTIFICATE" || !bytes.Equal(blk.Bytes, w.Certificates[i]) {
			return bad("certificate", "the block %d is not the certificate that was just made for the key %s", i+1, w.Labels[i])
		}
		body = rest
	}
	if len(body) != 0 {
		return bad("rest", "there are bytes after the last certificate")
	}
	return nil
}

// RootJSONWant is what [CheckRootJSON] compares a root.json with.
type RootJSONWant struct {
	// Label is the label of the key.
	Label string
	// Pin is the pin of the key.
	Pin string
	// CreatedAt is the ceremony time.
	CreatedAt time.Time
	// RemovalSHA256 is the SHA-256 of the text of the removal authorisation.
	RemovalSHA256 string
}

// CheckRootJSON reads the bytes of a root.json with files.ReadRootJSON, requires them to be
// in the canonical form, and compares each member: the label, store software, test true, created_at
// the ceremony time, the pin and the digest of the removal authorisation, and no member of an OpenPGP
// key. The error is an [*ArtifactError].
func CheckRootJSON(b []byte, w RootJSONWant) error {
	art := "root.json " + w.Label
	bad := func(member, format string, args ...any) error { return artifactErr(art, member, format, args...) }
	r, err := files.ReadRootJSON(b)
	if err != nil {
		return bad("file", "is refused by its reader: %v", err)
	}
	if ok, err := canonjson.IsCanonical(b); err != nil || !ok {
		return bad("file", "is not in the canonical form of RFC 8785")
	}
	switch {
	case r.Label != w.Label:
		return bad("label", "is not the label of the key")
	case r.Store != files.StoreSoftware:
		return bad("store", "is not software")
	case !r.Test:
		return bad("test", "is not true")
	case r.CreatedAt != timeText(w.CreatedAt):
		return bad("created_at", "is not the ceremony time")
	case r.X509SPKISHA256 != w.Pin:
		return bad("x509_spki_sha256", "is not the pin of the key")
	case r.RemovalSHA256 != w.RemovalSHA256:
		return bad("removal_sha256", "is not the digest of the removal authorisation")
	case r.OpenPGPFingerprint != "" || r.OpenPGPCreated != "":
		return bad("openpgp_fingerprint", "a member of an OpenPGP key is present")
	}
	return nil
}

// BornKey is a key that the store made, as the engine saw it: the label, the purpose, the store, the
// place the store gave for it, and the pin. A label may name two keys, one for each purpose: its
// X.509 key and its OpenPGP primary.
type BornKey struct {
	// Label is the label of the key.
	Label string
	// Purpose is what the key is for, the word of the birth in the plan. It is left empty by a
	// caller that knows only X.509 keys; an empty purpose is then the purpose x509-root.
	Purpose string
	// Store is the word of the store that made it.
	Store string
	// Place is the place the store gave for the key.
	Place string
	// Pin is the SHA-256 of the DER SubjectPublicKeyInfo of the key.
	Pin string
	// Fingerprint is the 40-digit fingerprint of an OpenPGP primary; it is empty for an X.509 key.
	Fingerprint string
}

// isX509 reports whether the key is the X.509 key of its label: the purpose is x509-root, or not
// given.
func (k BornKey) isX509() bool { return k.Purpose == "" || k.Purpose == purposeX509Root }

// MadeSignature is a signature that was made, as the engine saw it, once for each signature of the
// plan.
type MadeSignature struct {
	// N is the place of the signature in the plan, from 1.
	N int64
	// Kind is the kind of the signature.
	Kind string
	// Subject is the subject of the signature in the plan.
	Subject string
	// Key is the pin of the key that signed.
	Key string
	// SignatureSHA256 is the digest of the signature as the signer returned it.
	SignatureSHA256 string
}

// CheckPlanAgainstKeys compares the plan with the keys that were born and the signatures
// that were made. The births of the plan and the keys are the same labels, stores and places, in the
// same order; every signature of the plan, derived or not, was made once, in the order of n, with the
// kind and the subject that the plan names. The error is an [*ArtifactError].
func CheckPlanAgainstKeys(p *PlanOut, born []BornKey, made []MadeSignature) error {
	const art = "plan against the keys"
	bad := func(member, format string, args ...any) error { return artifactErr(art, member, format, args...) }
	if p == nil || p.SHA256 == "" {
		return bad("plan", "is empty")
	}
	if len(born) != len(p.Births) {
		return bad("births", "%d keys were born and the plan lists %d", len(born), len(p.Births))
	}
	for i, b := range p.Births {
		k := born[i]
		if k.Label != b.Label || k.Store != b.Store || k.Place != b.Place || !isPin(k.Pin) {
			return bad("births", "the key %d is not the key %s of the plan in its store and place", i+1, b.Label)
		}
		if k.Purpose != "" && k.Purpose != b.Purpose {
			return bad("births", "the key %d is not the key %s of the plan in its purpose", i+1, b.Label)
		}
	}
	if len(made) != len(p.Signatures) {
		return bad("signatures", "%d signatures were made and the plan lists %d", len(made), len(p.Signatures))
	}
	// The pin that signs is the pin of the X.509 key of the label: a primary of the same label has
	// its own key, which the signatures of the kinds primary-* will be held to.
	pins := make(map[string]string, len(born))
	for _, k := range born {
		if k.isX509() {
			pins[k.Label] = k.Pin
		}
	}
	for i, s := range p.Signatures {
		m := made[i]
		if m.N != s.N || m.N != int64(i)+1 || m.Kind != s.Kind || m.Subject != s.Subject || !isPin(m.Key) || !isPin(m.SignatureSHA256) {
			return bad("signatures", "the signature %d is not made once, in order, with the kind and the subject of the plan", i+1)
		}
		if pin, ok := pins[s.Subject]; !ok || m.Key != pin {
			return bad("signatures", "the signature %d is not by the key that was born for %s", i+1, s.Subject)
		}
	}
	return nil
}

// CheckSignatureDigests compares the digest that each line of the journal of signatures holds with the
// digest of the signature that the line stands for, read from the artifact: for a root certificate the
// DER value of the signature in the certificate, for a removal authorisation the 96 bytes r and s of
// its third part, for the list the 96 bytes of the one signature of root-list.jws. certs and removals
// are by label. The lines are those of [JournalRead], so the same check judges the lines that a run
// wrote and the lines that were read back from the file. The error is an [*ArtifactError].
func CheckSignatureDigests(p *PlanOut, certs map[string][]byte, removals map[string]string, set *trustset.Set, signatures JournalRead) error {
	const art = "journals"
	bad := func(member, format string, args ...any) error { return artifactErr(art, member, format, args...) }
	if p == nil || p.SHA256 == "" {
		return bad("plan", "is empty")
	}
	if len(signatures.Partial) != 0 || len(signatures.Lines) != len(p.Signatures) {
		return bad("signatures.jsonl", "does not hold one whole line for each of the %d signatures of the plan", len(p.Signatures))
	}
	for i, s := range p.Signatures {
		l, err := files.ReadSignatureLine(signatures.Lines[i])
		if err != nil {
			return bad("signatures.jsonl", "the line %d is refused by its reader: %v", i+1, err)
		}
		var sig []byte
		switch s.Kind {
		case kindRootCertificate:
			cert, err := x509.ParseCertificate(certs[s.Subject])
			if err != nil {
				return bad("signatures.jsonl", "the certificate of %s for the line %d does not parse", s.Subject, i+1)
			}
			sig = cert.Signature
		case kindRootRemoval:
			parts := strings.Split(removals[s.Subject], ".")
			if len(parts) != 3 {
				return bad("signatures.jsonl", "the removal authorisation of %s for the line %d is not three parts", s.Subject, i+1)
			}
			if sig, err = base64.RawURLEncoding.DecodeString(parts[2]); err != nil {
				return bad("signatures.jsonl", "the removal authorisation of %s for the line %d is not Base64url", s.Subject, i+1)
			}
		case kindRootList:
			if set == nil {
				return bad("signatures.jsonl", "there is no trust set for the line %d", i+1)
			}
			g, err := jws.ParseGeneral(set.ListJWS(), rootlist.ListTyp)
			if err != nil || len(g.Signatures) != 1 {
				return bad("signatures.jsonl", "root-list.jws for the line %d does not hold one signature", i+1)
			}
			sig = g.Signatures[0].Sig
		default:
			return bad("signatures.jsonl", "the kind of the signature %d is not one that this check knows", i+1)
		}
		sum := sha256.Sum256(sig)
		if l.SignatureSHA256 != hex.EncodeToString(sum[:]) {
			return bad("signatures.jsonl", "the line %d does not hold the digest of the signature that it stands for", i+1)
		}
	}
	return nil
}

// isPin reports whether s is 64 lower-case hexadecimal digits.
func isPin(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// JournalRead is a journal as fsx.ReadJournal returns it: the whole lines, and the bytes of a half
// line at the end, if there are any.
type JournalRead struct {
	// Lines are the whole lines, without their line feed.
	Lines [][]byte
	// Partial holds the bytes after the last line feed, which must be none.
	Partial []byte
}

// CheckJournals judges the two journals with the readers of internal/ceremony/files. Every
// line is whole and read by its reader; there is one birth line for each key of the plan, in the order of
// the plan, with the label, purpose, store and place of the plan and the pin of that key; and one
// signature line for each signature of the plan, in the order of n, of the kind of the plan, with the
// pin of the key that signs: the subject of a certificate or a removal authorisation, the signer of
// the list. A pair of label and purpose is born once: a label may have two lines, one for each
// purpose. pins maps each label to the pin of its X.509 key, the key of the purpose x509-root; the pin
// of a key of another purpose is under the text "<label>/<purpose>", and a birth of another purpose
// with no pin under that text is refused. The error is an [*ArtifactError].
func CheckJournals(p *PlanOut, pins map[string]string, births, signatures JournalRead) error {
	const art = "journals"
	bad := func(member, format string, args ...any) error { return artifactErr(art, member, format, args...) }
	if p == nil || p.SHA256 == "" {
		return bad("plan", "is empty")
	}
	if len(births.Partial) != 0 || len(signatures.Partial) != 0 {
		return bad("journal", "ends in a half line")
	}
	if len(births.Lines) != len(p.Births) {
		return bad("births.jsonl", "holds %d lines and the plan lists %d births", len(births.Lines), len(p.Births))
	}
	seen := map[birthKey]bool{}
	for i, raw := range births.Lines {
		l, err := files.ReadBirthLine(raw)
		if err != nil {
			return bad("births.jsonl", "the line %d is refused by its reader: %v", i+1, err)
		}
		b := p.Births[i]
		k := birthKey{l.Label, l.Purpose}
		if seen[k] || l.Label != b.Label || l.Purpose != b.Purpose || l.Store != b.Store || l.Place != b.Place {
			return bad("births.jsonl", "the line %d is not the birth %s of the plan, once", i+1, b.Label)
		}
		seen[k] = true
		pinKey := l.Label
		if l.Purpose != purposeX509Root {
			pinKey = l.Label + "/" + l.Purpose
		}
		if pin, ok := pins[pinKey]; !ok || l.PublicKeySHA256 != pin {
			return bad("births.jsonl", "the line %d does not hold the pin of the key %s", i+1, b.Label)
		}
	}
	if len(signatures.Lines) != len(p.Signatures) {
		return bad("signatures.jsonl", "holds %d lines and the plan lists %d signatures", len(signatures.Lines), len(p.Signatures))
	}
	for i, raw := range signatures.Lines {
		l, err := files.ReadSignatureLine(raw)
		if err != nil {
			return bad("signatures.jsonl", "the line %d is refused by its reader: %v", i+1, err)
		}
		s := p.Signatures[i]
		if l.N != int64(i)+1 || l.N != s.N || l.Kind != s.Kind {
			return bad("signatures.jsonl", "the line %d is not the signature %d of the plan, in order", i+1, i+1)
		}
		if pin, ok := pins[s.Subject]; !ok || l.Key != pin {
			return bad("signatures.jsonl", "the line %d does not hold the pin of the key that signs", i+1)
		}
	}
	return nil
}
