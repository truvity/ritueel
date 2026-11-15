package handoff

import (
	"encoding/base64"
	"errors"
	"fmt"
	"slices"

	"ritueel.id/ritueel/internal/strictjson"
)

// wireProof is the proof file as the JSON reader fills it. The members that only some types have are
// kept so that "present" can be told from "empty": a list is nil when the member is absent, and the two
// pointers are nil.
type wireProof struct {
	Handoff       int64           `json:"handoff"`
	Type          string          `json:"type"`
	RequestSHA256 string          `json:"request_sha256"`
	Store         string          `json:"store"`
	Evidence      *strictjson.Raw `json:"evidence"`
	Primaries     []string        `json:"primaries"`
	Capabilities  []string        `json:"capabilities"`
	Use           *string         `json:"use"`
}

// wireAttestation is the evidence of piv and openpgp-card.
type wireAttestation struct {
	Attestation []string `json:"attestation"`
}

// wireKMS is the evidence of aws-kms.
type wireKMS struct {
	KeyARN    *string `json:"key_arn"`
	PublicKey *string `json:"public_key"`
}

// errShape is the error of a proof file that is not of the form of the page. Its text is fixed words:
// it is the detail of a refusal with the code malformed.
type errShape string

func (e errShape) Error() string { return string(e) }

// shapef makes a shape error.
func shapef(format string, args ...any) error { return errShape(fmt.Sprintf(format, args...)) }

// The most entries that a proof may hold in a list. The page gives no number, so these are the numbers of
// this package: the lists of the vectors have two entries, a chain of a card is its slot certificate, its
// own certificate and the maker's intermediates (two to four in the chains measured, 2026-11), and the
// root list has the active primaries of the root cards (two, one for each card). A bound is here so that a
// 256 KiB file does not hand a verifier tens of thousands of strings. A list over its bound is `malformed`.
const (
	// MaxAttestation is the most certificates in the `attestation` of a proof: 8.
	MaxAttestation = 8
	// MaxPrimaries is the most fingerprints in the `primaries` of a proof: 26, the most entries that a
	// root list holds (one for each label A to Z), so that every list that the trust set writer and
	// the reader of root lists accept can be checked.
	MaxPrimaries = 26
)

// peekVersion reads the member handoff of a proof file and nothing else: a message of another version is
// refused reading nothing else in it ("Versioning"). It returns the reason when the file has no readable
// version: it is not one JSON object, is larger than the limit, or has the member twice, not as an
// integer or not at all. That is a fault of the form of the file, check 2, and not of its version.
func peekVersion(file []byte) (version int64, reason error) {
	n, ok, err := strictjson.PeekInt(file, "handoff", MaxFileSize)
	if err != nil {
		return 0, shapef("the proof file is not one JSON object with an integer handoff")
	}
	if !ok {
		return 0, shapef("the proof file has no member handoff")
	}
	return n, nil
}

// ErrProofShape is wrapped by the error of [ReadProof] for a proof file that is not of the form of the
// page. Its text is the page's words, the same text as the detail of a refusal with the code
// malformed that the certifier gives for the same file.
var ErrProofShape = errors.New("handoff: the proof file is not of the form of the page")

// ReadProof reads a proof file by the rules of the page, as the certifier reads it, and returns the
// proof. It is for the requester, who reads its own proof file by the rules of the certifier, so that the
// two cannot differ about what a proof is. Like [Checker.Check] it first reads the version alone: a file
// that is longer than [MaxFileSize], is not one JSON object with an integer handoff, or has a version
// other than [Version], is refused before anything else of it is read. A file that is not of the form
// of the page is an error that wraps [ErrProofShape]; the files of the request are not looked at, and
// nothing is returned with an error. The proof that is returned shares nothing with the file.
func ReadProof(file []byte) (*Proof, error) {
	if len(file) > MaxFileSize {
		return nil, fmt.Errorf("%w: the proof file is longer than %d bytes", ErrProofShape, MaxFileSize)
	}
	version, err := peekVersion(file)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrProofShape, err)
	}
	if version != Version {
		return nil, fmt.Errorf("%w: %w", ErrProofShape, shapef("the contract version is %d, and only %d is known", version, Version))
	}
	p, err := readProof(file)
	if err != nil {
		var shape errShape
		if errors.As(err, &shape) {
			return nil, fmt.Errorf("%w: %w", ErrProofShape, shape)
		}
		return nil, err
	}
	return p, nil
}

// readProof reads a proof file by the rules of the page: one JSON object, no member twice, no member the
// page does not define, no null, integers only (the strict reader), and then the members that each type
// has and has not, the values that each member may take, and the shape of the evidence for the store.
// It does not look at the files of the request. An error is an errShape.
func readProof(file []byte) (*Proof, error) {
	var w wireProof
	if err := strictjson.Unmarshal(file, &w, strictjson.Options{MaxBytes: MaxFileSize}); err != nil {
		if !errors.Is(err, strictjson.ErrMalformed) {
			return nil, fmt.Errorf("%w: the proof file could not be read: %w", ErrInternal, err)
		}
		return nil, shapef("the proof file does not parse: it is not one JSON object with only the members of the page, each once")
	}
	if w.Handoff != Version {
		// A caller reads the version first (peekVersion); a proof of another version is not read here.
		return nil, shapef("the proof file has handoff %d, not %d", w.Handoff, Version)
	}
	p := &Proof{Handoff: Version, Type: Type(w.Type), RequestSHA256: w.RequestSHA256, Store: Store(w.Store)}
	switch p.Type {
	case TypeX509, TypeOpenPGP, TypeSSH:
	default:
		return nil, shapef("the type is not one of x509-intermediate, openpgp-subkey and ssh-ca-key")
	}
	if !lowerHex(w.RequestSHA256, 64) {
		return nil, shapef("request_sha256 is not 64 lower-case hexadecimal digits")
	}
	switch p.Store {
	case StorePIV, StoreOpenPGPCard, StoreKMS, StoreSoftware:
	default:
		return nil, shapef("the store is not one of piv, openpgp-card, aws-kms and software")
	}
	if err := readMembersOfType(p, &w); err != nil {
		return nil, err
	}
	if err := readEvidence(p, w.Evidence); err != nil {
		return nil, err
	}
	return p, nil
}

// readMembersOfType reads primaries, capabilities and use, which a type has or has not.
func readMembersOfType(p *Proof, w *wireProof) error {
	switch p.Type {
	case TypeX509:
		if w.Primaries != nil || w.Capabilities != nil || w.Use != nil {
			return shapef("an x509-intermediate proof has none of primaries, capabilities and use")
		}
	case TypeOpenPGP:
		if w.Use != nil {
			return shapef("an openpgp-subkey proof has no use")
		}
		if len(w.Primaries) == 0 {
			return shapef("an openpgp-subkey proof needs primaries, and not an empty list")
		}
		if len(w.Primaries) > MaxPrimaries {
			return shapef("primaries holds more than %d fingerprints", MaxPrimaries)
		}
		for i, f := range w.Primaries {
			if !lowerHex(f, 40) {
				return shapef("a primary is not 40 lower-case hexadecimal digits")
			}
			if slices.Contains(w.Primaries[:i], f) {
				return shapef("primaries holds a fingerprint twice")
			}
		}
		if len(w.Capabilities) != 1 || (w.Capabilities[0] != "sign" && w.Capabilities[0] != "authenticate") {
			return shapef("capabilities is not exactly [\"sign\"] or [\"authenticate\"]")
		}
		p.Primaries = slices.Clone(w.Primaries)
		p.Capabilities = slices.Clone(w.Capabilities)
	case TypeSSH:
		if w.Primaries != nil || w.Capabilities != nil {
			return shapef("an ssh-ca-key proof has no primaries and no capabilities")
		}
		if w.Use == nil || (*w.Use != "user" && *w.Use != "host") {
			return shapef("an ssh-ca-key proof needs use, and it is user or host")
		}
		p.Use = *w.Use
	}
	return nil
}

// readEvidence checks that the member evidence is there for a store that has evidence and absent for a
// software key, and that it has the shape of its store. Its content is the verifier's.
func readEvidence(p *Proof, raw *strictjson.Raw) error {
	if p.Store == StoreSoftware {
		if raw != nil {
			return shapef("a software key has no evidence")
		}
		return nil
	}
	if raw == nil {
		return shapef("this store needs the member evidence")
	}
	opts := strictjson.Options{MaxBytes: MaxFileSize}
	switch p.Store {
	case StorePIV, StoreOpenPGPCard:
		var e wireAttestation
		if err := strictjson.Unmarshal([]byte(*raw), &e, opts); err != nil {
			return shapef("the evidence is not an object with the one member attestation")
		}
		if len(e.Attestation) < 2 {
			return shapef("the attestation is not a list of two or more certificates")
		}
		if len(e.Attestation) > MaxAttestation {
			return shapef("the attestation holds more than %d certificates", MaxAttestation)
		}
		for _, s := range e.Attestation {
			if !standardBase64(s) {
				return shapef("an attested certificate is not Base64 of a DER value")
			}
		}
	case StoreKMS:
		var e wireKMS
		if err := strictjson.Unmarshal([]byte(*raw), &e, opts); err != nil {
			return shapef("the evidence is not an object with the members key_arn and public_key and no other")
		}
		if e.KeyARN == nil || *e.KeyARN == "" {
			return shapef("the evidence has no key_arn")
		}
		if e.PublicKey == nil || !standardBase64(*e.PublicKey) {
			return shapef("the public_key of the evidence is not Base64 of a DER value")
		}
		// The text is canonical Base64 of at least one byte, so this decodes. Whether the bytes are the key
		// of the request is check 8.
		der, err := base64.StdEncoding.DecodeString(*e.PublicKey)
		if err != nil {
			return shapef("the public_key of the evidence is not Base64 of a DER value")
		}
		p.kmsKey = der
	}
	p.Evidence = []byte(*raw)
	return nil
}

// lowerHex reports whether s is exactly n lower-case hexadecimal digits.
func lowerHex(s string, n int) bool {
	if len(s) != n {
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

// standardBase64 reports whether s is standard Base64 with padding (RFC 4648, section 4) of at least one
// byte, written in the one canonical way: no line break, no missing padding, no bit left over.
func standardBase64(s string) bool {
	b, err := base64.StdEncoding.Strict().DecodeString(s)
	return err == nil && len(b) > 0 && base64.StdEncoding.EncodeToString(b) == s
}
