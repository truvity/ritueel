package rootlist

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strconv"

	"ritueel.id/ritueel/internal/jws"
)

// VerifyCABundle checks a CA bundle against an accepted list, as "The CA bundle" of the page says:
// the first line is exactly "# trust-sequence: " and the list's sequence in decimal, then one PEM
// block labelled CERTIFICATE for each root of the list, in the order of roots, whose key has the
// root's pin, and nothing else. The bundle is text with LF line ends and ends with the line feed
// that closes its last block. Anything else gives CABundleMismatch.
//
// Each block must be the one spelling that a writer makes (RFC 7468: the label, no header lines,
// Base64 in lines of 64 characters, the last line shorter or equal), and no byte stands outside the
// first line and the blocks, not a blank line, not a carriage return, not a comment. A PEM reader
// skips text between blocks and accepts other spellings; this check writes each block again from
// the bytes it decoded and demands the same text, so nothing is skipped.
//
// Each certificate must also be a CA certificate (basic constraints present, with the CA flag),
// name itself as its issuer (the issuer name equals the subject name, as bytes) and
// must verify with its own key, so that its text, the names and limits a client takes from it, is
// what the root key signed and not what someone wrote around the key. Dates and names are not
// judged.
//
// The sequence line is compared as text, so "+7", "07" and "7 " are not "7". The pins are of the
// keys in the certificates; a certificate is parsed to read its key and is not otherwise judged.
// The bundle is longer than MaxBytes only when it is not a bundle of this page: that is a
// mismatch too.
func VerifyCABundle(pemData []byte, l *List) Verdict {
	refuse := func(format string, args ...any) Verdict {
		return Verdict{Reason: CABundleMismatch, Detail: fmt.Sprintf(format, args...)}
	}
	if l == nil || len(l.Roots) == 0 {
		panic("rootlist: VerifyCABundle needs an accepted list")
	}
	if len(pemData) > MaxBytes {
		return refuse("the bundle is longer than %d bytes", MaxBytes)
	}
	first := []byte("# trust-sequence: " + strconv.FormatInt(l.Sequence, 10) + "\n")
	body, ok := bytes.CutPrefix(pemData, first)
	if !ok {
		return refuse("the first line is not exactly %q", string(first[:len(first)-1]))
	}
	for i, root := range l.Roots {
		blk, rest := pem.Decode(body)
		if blk == nil {
			return refuse("certificate %d of %d is missing or is not a PEM block", i+1, len(l.Roots))
		}
		consumed := body[:len(body)-len(rest)]
		if blk.Type != "CERTIFICATE" || len(blk.Headers) != 0 || !bytes.Equal(consumed, pem.EncodeToMemory(blk)) {
			return refuse("block %d is not a plain CERTIFICATE block in lines of 64 characters, or has text before it", i+1)
		}
		cert, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return refuse("block %d is not a certificate", i+1)
		}
		if jws.Pin(cert) != root.X509SPKISHA256 {
			return refuse("block %d is not the certificate of root key %s of the list", i+1, root.Label)
		}
		// The text of the certificate is what the root key signed: it must verify with its own key
		// (a root certificate signs itself), be a CA certificate and name itself as its issuer. CheckSignature is called, not
		// CheckSignatureFrom, so that nothing more is asked of the key usage than the page asks.
		// The validity period, the names, the extensions other than basic constraints and the
		// algorithm are not judged.
		if !cert.BasicConstraintsValid || !cert.IsCA {
			return refuse("block %d is not a CA certificate (basic constraints with the CA flag)", i+1)
		}
		// A root certificate names itself as its issuer: the two names, as the bytes of their
		// encoding, are equal. No clock and no name is read for this.
		if !bytes.Equal(cert.RawIssuer, cert.RawSubject) {
			return refuse("block %d does not name itself as its issuer", i+1)
		}
		if err := cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature); err != nil {
			return refuse("block %d does not verify with its own key", i+1)
		}
		body = rest
	}
	if len(body) != 0 {
		return refuse("there is more after the %d certificates of the list", len(l.Roots))
	}
	return Verdict{Accepted: true, List: l}
}
