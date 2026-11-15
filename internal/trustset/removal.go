package trustset

import (
	"encoding/base64"
	"strings"

	"ritueel.id/ritueel/internal/jws"
	"ritueel.id/ritueel/internal/rootlist"
)

// NewRemoval makes the removal authorisation of a root key: the compact JWS of the list page,
// "header.payload.signature" in Base64url without padding, ASCII, no trailing newline, with the
// payload {"version":1,"x509_spki_sha256":"<pin>"} (canonical) and the protected header alg ES384,
// kid the pin, typ rootlist.RemovalTyp and x5c the signer's certificate. It carries no sequence and
// no expiry. All faults that can be found without the key are found before the signer is asked,
// which is once; that includes the length of the whole text. The signature is verified before it
// is returned, and the whole text is judged by rootlist.CheckRemoval with the pin as the only held
// key. It is the function that the first apply and an apply that adds a root key call at the birth
// of a root key. A nil or unusable signer, and a certificate that makes the text longer than
// MaxBytes, are ErrParams; a signer that fails, panics or returns a wrong signature is ErrSign; no text comes
// with an error.
func NewRemoval(s Signer) (string, error) {
	info, err := inspect(s)
	if err != nil {
		return "", err
	}
	protected, err := protectedText(info, rootlist.RemovalTyp)
	if err != nil {
		return "", err
	}
	payload := []byte(`{"version":1,"x509_spki_sha256":"` + info.pin + `"}`)
	// The signature has a fixed length, so the length of the whole text is known before the
	// signature exists: a text over the limit is refused before the key is asked.
	size := len(protected) + 1 + base64.RawURLEncoding.EncodedLen(len(payload)) + 1 +
		base64.RawURLEncoding.EncodedLen(jws.SignatureSize)
	if size > MaxBytes {
		return "", fail(ErrParams, "the removal authorisation would be %d bytes, longer than %d bytes", size, MaxBytes)
	}
	sig, err := ask(s, info, jws.SigningInput(protected, payload))
	if err != nil {
		return "", err
	}
	text := strings.Join([]string{
		protected,
		base64.RawURLEncoding.EncodeToString(payload),
		base64.RawURLEncoding.EncodeToString(sig),
	}, ".")
	entry := rootlist.Removal{Label: info.label, X509SPKISHA256: info.pin, Authorisation: text}
	if err := rootlist.CheckRemoval(entry, nil, []string{info.pin}); err != nil {
		return "", failWith(ErrSign, "the reader of the page refuses the authorisation that was written", err)
	}
	return text, nil
}
