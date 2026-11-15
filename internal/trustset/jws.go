package trustset

import (
	"encoding/base64"

	"ritueel.id/ritueel/internal/canonjson"
	"ritueel.id/ritueel/internal/jws"
	"ritueel.id/ritueel/internal/rootlist"
)

// headerDoc is the protected header of a signature: the four members of the page. The canonical
// form writes them in the order alg, kid, typ, x5c, which is also the order of the fields here.
type headerDoc struct {
	Alg string   `json:"alg"`
	Kid string   `json:"kid"`
	Typ string   `json:"typ"`
	X5C []string `json:"x5c"`
}

// protectedText returns the protected header of a signature by the signer described by info: alg
// ES384, kid the pin, typ the given text and x5c a list of the one certificate, as canonical JSON
// and then Base64url without padding. This is the text that the signature covers.
func protectedText(info signerInfo, typ string) (string, error) {
	text, err := canonjson.Marshal(headerDoc{
		Alg: jws.AlgES384,
		Kid: info.pin,
		Typ: typ,
		X5C: []string{base64.StdEncoding.EncodeToString(info.cert.Raw)},
	})
	if err != nil {
		return "", failWith(ErrParams, "the protected header cannot be written", err)
	}
	return base64.RawURLEncoding.EncodeToString(text), nil
}

// fileSignature is one signature of root-list.jws: the protected text and the 96 bytes.
type fileSignature struct {
	protected string
	sig       []byte
}

type signatureDoc struct {
	Protected string `json:"protected"`
	Signature string `json:"signature"`
}

type generalDoc struct {
	Signatures []signatureDoc `json:"signatures"`
}

// marshalGeneral writes root-list.jws: the canonical JSON {"signatures":[...]} with no trailing
// newline, each element exactly protected and signature, Base64url without padding, in the order
// given. The caller gives the signatures in the order of the signers' labels. It takes one to
// MaxRoots signatures of 96 bytes, refuses an output over MaxBytes, and reads the file back with
// jws.ParseGeneral, which must give the same signatures in the same order (so no kid is twice
// and each header has the form of the page). Every error wraps ErrParams.
func marshalGeneral(sigs []fileSignature) ([]byte, error) {
	if len(sigs) == 0 || len(sigs) > MaxRoots {
		return nil, fail(ErrParams, "a signature file holds from 1 to %d signatures, there are %d", MaxRoots, len(sigs))
	}
	doc := generalDoc{Signatures: make([]signatureDoc, len(sigs))}
	for i, s := range sigs {
		if s.protected == "" || len(s.sig) != jws.SignatureSize {
			return nil, fail(ErrParams, "signature %d has no header or is not %d bytes", i, jws.SignatureSize)
		}
		doc.Signatures[i] = signatureDoc{Protected: s.protected, Signature: base64.RawURLEncoding.EncodeToString(s.sig)}
	}
	out, err := canonjson.Marshal(doc)
	if err != nil {
		return nil, failWith(ErrParams, "the signature file cannot be written", err)
	}
	if len(out) > MaxBytes {
		return nil, fail(ErrParams, "root-list.jws is longer than %d bytes", MaxBytes)
	}
	g, err := jws.ParseGeneral(out, rootlist.ListTyp)
	if err != nil || len(g.Signatures) != len(sigs) {
		return nil, fail(ErrParams, "the reader of the page refuses the signature file that was written")
	}
	for i, s := range g.Signatures {
		if s.Protected != sigs[i].protected || string(s.Sig) != string(sigs[i].sig) {
			return nil, fail(ErrParams, "the signature file that was written reads back as other signatures")
		}
	}
	return out, nil
}
