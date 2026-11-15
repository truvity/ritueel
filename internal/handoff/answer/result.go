package answer

import (
	"errors"
	"fmt"
	"slices"
	"time"

	"ritueel.id/ritueel/internal/fsx"
	"ritueel.id/ritueel/internal/handoff"
	"ritueel.id/ritueel/internal/rootlist"
	"ritueel.id/ritueel/internal/strictjson"
)

// The outcomes of an answer ("The answer").
const (
	outcomeIssued  = "issued"
	outcomeRefused = "refused"
)

// shapeError is a result file that is not of the form of the page. Its text is fixed words: it is the detail
// of a refusal with the code malformed, and it holds no byte of the file.
type shapeError string

func (e shapeError) Error() string { return string(e) }

// artifact is one entry of artifacts: the name of a file of the answer and the SHA-256 of its bytes.
type artifact struct {
	name   string
	sha256 string
}

// result is a result file read. Which members are set depends on the outcome and the type, as the table of
// members says (see readResult); a member that its outcome does not have is the zero value.
type result struct {
	typ           handoff.Type
	requestSHA256 string
	outcome       string
	reasons       []handoff.Code // refused: one to MaxReasons distinct codes of the certifier's table
	artifacts     []artifact     // issued
	validFrom     time.Time      // issued
	validUntil    time.Time      // issued, not an ssh-ca-key
	issuer        string         // issued: 64 digits for X.509 and ssh-ca-key, 40 for openpgp-subkey
	trustSequence int64
}

// wireResult is the result file as the JSON reader fills it. A member that only some answers have is a pointer
// or a list, so that "absent" can be told from "empty": a list is nil when the member is absent.
type wireResult struct {
	Handoff       int64          `json:"handoff"`
	Type          string         `json:"type"`
	RequestSHA256 string         `json:"request_sha256"`
	Outcome       string         `json:"outcome"`
	Reasons       []string       `json:"reasons"`
	Artifacts     []wireArtifact `json:"artifacts"`
	ValidFrom     *string        `json:"valid_from"`
	ValidUntil    *string        `json:"valid_until"`
	Issuer        *string        `json:"issuer"`
	TrustSequence *int64         `json:"trust_sequence"`
}

// wireArtifact is one entry of artifacts.
type wireArtifact struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
}

// The members that each outcome and type has and has not ("The answer"). It is the one table of the shape of a
// result file: readResult holds the file to it and to nothing else.
//
//	issued:  artifacts, valid_from, issuer, trust_sequence; valid_until for x509-intermediate and
//	         openpgp-subkey, and not for ssh-ca-key; no reasons.
//	refused: reasons, trust_sequence; no artifacts, no valid_from, no valid_until, no issuer.
//
// The refused row is not on the page: the page says that a refused answer "holds no artifacts and no secret"
// and does not say which of the other members it holds. It is the smallest shape that tells the requester
// which trust set it needs, and it is kept here, in one place.

// peekVersion reads the member handoff of a result file and nothing else, as the certifier reads the version
// of a proof file: an answer of another version is refused reading nothing else in it. The error is returned
// when the file has no readable version: it is not one JSON object within the limit, or has the member twice,
// not as an integer or not at all. That is a fault of the form of the file, check 2.
func peekVersion(file []byte) (int64, error) {
	n, ok, err := strictjson.PeekInt(file, "handoff", MaxFileSize)
	if err != nil {
		return 0, shapeError("the result file is not one JSON object with an integer handoff")
	}
	if !ok {
		return 0, shapeError("the result file has no member handoff")
	}
	return n, nil
}

// readResult reads a result file by the rules of the page: one JSON object of at most MaxFileSize bytes, no
// member twice, no member the page does not define, no null, integers only (the strict reader), and then the
// members that each outcome and type has and has not, and the values that each member may take. It does not
// look at the other files of the answer. An error is a [shapeError], and holds no byte of the file.
func readResult(file []byte) (*result, error) {
	var w wireResult
	if err := strictjson.Unmarshal(file, &w, strictjson.Options{MaxBytes: MaxFileSize}); err != nil {
		if !errors.Is(err, strictjson.ErrMalformed) {
			return nil, fmt.Errorf("%w: the result file could not be read: %w", ErrInternal, err)
		}
		return nil, shapeError("the result file does not parse: it is not one JSON object with only the members of the page, each once")
	}
	if w.Handoff != handoff.Version {
		// The caller reads the version first (peekVersion); an answer of another version is not read here.
		return nil, shapeError("the result file has another handoff than the one that was read")
	}
	res := &result{typ: handoff.Type(w.Type), requestSHA256: w.RequestSHA256, outcome: w.Outcome}
	switch res.typ {
	case handoff.TypeX509, handoff.TypeOpenPGP, handoff.TypeSSH:
	default:
		return nil, shapeError("the type is not one of x509-intermediate, openpgp-subkey and ssh-ca-key")
	}
	if !lowerHex(w.RequestSHA256, 64) {
		return nil, shapeError("request_sha256 is not 64 lower-case hexadecimal digits")
	}
	if w.TrustSequence == nil || *w.TrustSequence < 1 || *w.TrustSequence > strictjson.MaxSafeInt {
		return nil, shapeError("trust_sequence is not an integer from 1 up")
	}
	res.trustSequence = *w.TrustSequence
	switch w.Outcome {
	case outcomeRefused:
		if err := readRefused(res, &w); err != nil {
			return nil, err
		}
	case outcomeIssued:
		if err := readIssued(res, &w); err != nil {
			return nil, err
		}
	default:
		return nil, shapeError("outcome is not issued or refused")
	}
	return res, nil
}

// readRefused reads the members of a refused answer: reasons, and none of the members of an issued one.
func readRefused(res *result, w *wireResult) error {
	if w.Artifacts != nil || w.ValidFrom != nil || w.ValidUntil != nil || w.Issuer != nil {
		return shapeError("a refused answer holds no artifacts, valid_from, valid_until and issuer")
	}
	if len(w.Reasons) == 0 {
		return shapeError("a refused answer needs reasons, and not an empty list")
	}
	if len(w.Reasons) > MaxReasons {
		return shapeError(fmt.Sprintf("reasons holds more than %d codes", MaxReasons))
	}
	for i, s := range w.Reasons {
		c := handoff.Code(s)
		if !certifierCode(c) {
			return shapeError("reasons holds a code that is not one of the table of the contract")
		}
		if slices.Contains(res.reasons[:i], c) {
			return shapeError("reasons holds a code twice")
		}
		res.reasons = append(res.reasons, c)
	}
	return nil
}

// certifierCode tells whether c is one of the eleven codes of the answer table of the contract ("The answer").
func certifierCode(c handoff.Code) bool {
	switch c {
	case handoff.CodeVersionUnsupported, handoff.CodeMalformed, handoff.CodeRequestMismatch,
		handoff.CodeUnknownPrimary, handoff.CodeAlgorithmUnsupported, handoff.CodePossessionInvalid,
		handoff.CodeStoreNotAllowed, handoff.CodeProofInvalid, handoff.CodeKeyMismatch,
		handoff.CodePolicy, handoff.CodeDeclined:
		return true
	}
	return false
}

// readIssued reads the members of an issued answer: artifacts, the dates, issuer, and none of reasons.
func readIssued(res *result, w *wireResult) error {
	if w.Reasons != nil {
		return shapeError("an issued answer holds no reasons")
	}
	if w.Artifacts == nil || w.ValidFrom == nil || w.Issuer == nil {
		return shapeError("an issued answer needs artifacts, valid_from and issuer")
	}
	if len(w.Artifacts) > MaxArtifacts {
		return shapeError(fmt.Sprintf("artifacts holds more than %d entries", MaxArtifacts))
	}
	for _, a := range w.Artifacts {
		if err := checkArtifactName(a.Name); err != nil {
			return shapeError("an artifact has a name that is not a name of a file of the answer")
		}
		if !lowerHex(a.SHA256, 64) {
			return shapeError("an artifact has a sha256 that is not 64 lower-case hexadecimal digits")
		}
		res.artifacts = append(res.artifacts, artifact{name: a.Name, sha256: a.SHA256})
	}
	var ok bool
	if res.validFrom, ok = readTime(*w.ValidFrom); !ok {
		return shapeError("valid_from is not a time of the form YYYY-MM-DDThh:mm:ssZ")
	}
	if res.typ == handoff.TypeSSH {
		if w.ValidUntil != nil || len(w.Artifacts) != 0 {
			return shapeError("an ssh-ca-key answer has valid_from only, and no artifacts")
		}
	} else {
		if w.ValidUntil == nil {
			return shapeError("an issued answer needs valid_until")
		}
		if res.validUntil, ok = readTime(*w.ValidUntil); !ok {
			return shapeError("valid_until is not a time of the form YYYY-MM-DDThh:mm:ssZ")
		}
	}
	n := 64
	if res.typ == handoff.TypeOpenPGP {
		n = 40
	}
	if !lowerHex(*w.Issuer, n) {
		return shapeError("issuer is not the number of lower-case hexadecimal digits of its type")
	}
	res.issuer = *w.Issuer
	return nil
}

// checkArtifactName holds the name of an artifact to its form before it is compared or shown: 1 to 255
// characters of record 0006, rule 38, which is the form that fsx.CheckName holds.
func checkArtifactName(name string) error { return fsx.CheckName(name) }

// readTime reads a time of the one form of the page, YYYY-MM-DDThh:mm:ssZ, and nothing else: the text must
// be what the layout writes for the time it names.
func readTime(s string) (time.Time, bool) {
	t, err := time.Parse(rootlist.TimeLayout, s)
	if err != nil || t.Format(rootlist.TimeLayout) != s {
		return time.Time{}, false
	}
	return t.UTC(), true
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
