package answer

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"slices"
	"time"

	"ritueel.id/ritueel/internal/handoff"
	"ritueel.id/ritueel/internal/openpgp"
	"ritueel.id/ritueel/internal/pki"
)

// The bounds. Every number is checked before the thing that it bounds is read or walked.
const (
	// MaxFileSize is the largest file of an answer that is read: 256 KiB, the limit of a JSON file in the
	// contract ("Messages and files"), the same number that package handoff holds a request file to.
	MaxFileSize = handoff.MaxFileSize
	// MaxArtifacts is the most entries of artifacts that result.json may hold; more is malformed, before any
	// entry is read for its name or its digest.
	MaxArtifacts = 4
	// MaxReasons is the most entries of reasons that result.json may hold.
	MaxReasons = 16
	// MaxAnchors is the most CA certificates of the installed set of the floor.
	MaxAnchors = 64
	// MaxValidityMonths is the largest number of months that [Config.Validity] may name.
	MaxValidityMonths = 60
	// MaxExtensions is the most extensions of a certificate that the profile checks walk over. A
	// certificate of the profile has six, and one of the floor four to eight; more is the code profile,
	// found before any extension is compared.
	MaxExtensions = 32
)

// The suffixes of the files of an answer, as the keys of [Answer.Files] ("Messages and files"). A file is
// `<stem>.<suffix>`.
const (
	// FileResult is the result file, `<stem>.result.json`.
	FileResult = "result.json"
	// FileCert is the issued certificate, `<stem>.cert.pem`, of an x509-intermediate; on the floor it is the
	// whole answer.
	FileCert = "cert.pem"
	// FileBound is the bound subkey, `<stem>.bound.pgp`, of an openpgp-subkey.
	FileBound = "bound.pgp"
)

// answerSuffixes are the files that [LoadAnswer] looks for.
var answerSuffixes = []string{FileResult, FileCert, FileBound}

// Code is a reason code of the requester's table ("What the requester checks before it installs"). The
// codes belong to the requester and are not sent anywhere. It is a type of its own, so that no code of the
// certifier's table ([handoff.Code]) is taken for one of these.
type Code string

// The reason codes of the requester.
const (
	// CodeVersionUnsupported is check 1: the version of the answer is not the one that was sent.
	CodeVersionUnsupported Code = "version-unsupported"
	// CodeRequestMismatch is check 3: the answer is not for this request.
	CodeRequestMismatch Code = "request-mismatch"
	// CodeIssuer is the check of the issuer: the answer does not verify to an anchor that the requester holds.
	CodeIssuer Code = "issuer"
	// CodeKeyMismatch is the check of the key: the answer is not for the requester's own key.
	CodeKeyMismatch Code = "key-mismatch"
	// CodeProfile is the check of the profile: what was issued is not what was asked.
	CodeProfile Code = "profile"
	// CodeValidity is the check of the validity: not the length that the requester expects, or not valid now.
	CodeValidity Code = "validity"
	// CodeMalformed is the check of the form of the files and of the digests of result.json.
	CodeMalformed Code = "malformed"
)

// The errors that [Checker.Check], [New], [LoadAnswer] and the constructors of [Asked] return. Each is wrapped
// with words that say where; test with errors.Is.
var (
	// ErrConfig is returned by [New] for a configuration that is not whole, by [Checker.Check] for a Checker
	// that [New] did not make, a nil or zero [Asked], a nil [Answer] and an answer whose stem is not a stem,
	// and by [AskedFromRequest] and [AskedX509] for the requester's own files, which are not a request of the
	// contract. It says nothing about an answer.
	ErrConfig = errors.New("answer: invalid configuration or request")
	// ErrLoad is returned by [LoadAnswer] when it cannot read the files: a stem that is not a stem, a folder
	// that is not a path, a link anywhere on the way to a file, a file that is not a regular file, a file that
	// cannot be read. It is the caller's problem and not a verdict.
	ErrLoad = errors.New("answer: the files of the answer cannot be read")
	// ErrTypeNotBuilt is returned for an answer to a request of type ssh-ca-key: its checks are not built,
	// because the SSH CA key list has no reader.
	ErrTypeNotBuilt = errors.New("answer: the checks of an ssh-ca-key answer are not built")
	// ErrUnsupported is returned when a floor checker is asked to judge an answer to a request that is not
	// of type x509-intermediate: the floor is X.509 only.
	ErrUnsupported = errors.New("answer: the floor judges only an x509-intermediate answer")
	// ErrFloorHasResult is returned when a floor checker is given an answer that has a result file: the floor
	// has none, and an answer of the full contract is judged by a checker that holds a root list.
	ErrFloorHasResult = errors.New("answer: a floor checker was given an answer that has a result file")
	// ErrNoPrimaryKey is returned for an openpgp-subkey answer that names a primary that the request named and
	// that is on the held list, when [Config.Primaries] holds no key for it: the binding cannot be verified,
	// so the answer is neither accepted nor refused, and check 5 and the checks after it are not-run.
	ErrNoPrimaryKey = errors.New("answer: the checker holds no key for the primary of the answer")
	// ErrInternal is returned when two readers disagreed, when the clock gave a time outside the years 1970
	// to 2106 or panicked, or when a call broke its contract. It is a fault of this package or of the
	// clock, never of the answer.
	ErrInternal = errors.New("answer: a reader or the clock broke its contract")
)

// Answer is the files of one answer, by suffix. Nothing is parsed here.
type Answer struct {
	// Stem is the stem of the file names of the answer (the certifier repeats the stem of the request). The
	// names in artifacts are made from it.
	Stem string
	// Files holds the content of each file by its suffix: "result.json", "cert.pem" and "bound.pgp". A file
	// that is not there has no entry.
	Files map[string][]byte
}

// Asked is what the requester asked for: its own request, as it holds it. It is read once and cannot be
// changed.
type Asked struct {
	typ    handoff.Type
	digest string // request_sha256 that an answer must carry: the digest of this request

	// An x509-intermediate request.
	csr *pki.Request

	// An openpgp-subkey request.
	subkeyFirst []byte          // the Public-Subkey packet, whole
	backSigs    [][]byte        // one back-signature for each primary, in the order of primaries
	sub         *openpgp.Subkey // the subkey
	primaries   []string        // the fingerprints that the request named, in its order
	capability  string          // sign or authenticate
}

// AskedFromRequest makes an Asked from the files of a request that [handoff.LoadRequest] read. The proof
// file is read by [handoff.ReadProof], the same reader as the certifier's, and the type and the files are
// the proof's; for an openpgp-subkey the primaries and the capability are the proof's too. It is an error
// (that wraps [ErrConfig]) if the files are not a request of the contract, if the proof's request_sha256 is
// not the digest of its own request file, or if a file is missing: the requester's own files are wrong,
// which is not a fault of an answer and not a verdict. A request of type ssh-ca-key is read as far as its
// digest, because its checks are not built.
func AskedFromRequest(r *handoff.Request) (*Asked, error) {
	if r == nil {
		return nil, fmt.Errorf("%w: no request", ErrConfig)
	}
	proofFile, ok := r.Files[handoff.FileProof]
	if !ok {
		return nil, fmt.Errorf("%w: the request has no proof file", ErrConfig)
	}
	p, err := handoff.ReadProof(proofFile)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrConfig, err)
	}
	switch p.Type {
	case handoff.TypeX509:
		file, ok := r.Files[handoff.FileCSR]
		if !ok {
			return nil, fmt.Errorf("%w: the request has no file %s", ErrConfig, handoff.FileCSR)
		}
		a, err := AskedX509(file)
		if err != nil {
			return nil, err
		}
		if a.digest != p.RequestSHA256 {
			return nil, fmt.Errorf("%w: request_sha256 of the proof is not the digest of the request", ErrConfig)
		}
		return a, nil
	case handoff.TypeOpenPGP:
		return askedOpenPGP(r, p)
	default:
		file, ok := r.Files[handoff.FileSSHKey]
		if !ok {
			return nil, fmt.Errorf("%w: the request has no file %s", ErrConfig, handoff.FileSSHKey)
		}
		if sum := sha256.Sum256(file); hex.EncodeToString(sum[:]) != p.RequestSHA256 {
			return nil, fmt.Errorf("%w: request_sha256 of the proof is not the digest of the file %s", ErrConfig, handoff.FileSSHKey)
		}
		return &Asked{typ: handoff.TypeSSH, digest: p.RequestSHA256}, nil
	}
}

// askedOpenPGP reads the subkey file of a request whose proof is p.
func askedOpenPGP(r *handoff.Request, p *handoff.Proof) (*Asked, error) {
	file, ok := r.Files[handoff.FileSubkey]
	if !ok {
		return nil, fmt.Errorf("%w: the request has no file %s", ErrConfig, handoff.FileSubkey)
	}
	if len(file) > MaxFileSize {
		return nil, fmt.Errorf("%w: the file %s is longer than %d bytes", ErrConfig, handoff.FileSubkey, MaxFileSize)
	}
	sum := sha256.Sum256(file)
	if hex.EncodeToString(sum[:]) != p.RequestSHA256 {
		return nil, fmt.Errorf("%w: request_sha256 of the proof is not the digest of the file %s", ErrConfig, handoff.FileSubkey)
	}
	first, sigs, err := openpgp.SplitSubkeyFile(file, handoff.MaxPrimaries)
	if err != nil {
		return nil, fmt.Errorf("%w: reading the subkey file: %w", ErrConfig, err)
	}
	sub, err := openpgp.ReadSubkey(first)
	if err != nil {
		return nil, fmt.Errorf("%w: reading the subkey: %w", ErrConfig, err)
	}
	if len(sigs) != len(p.Primaries) || len(p.Capabilities) != 1 {
		return nil, fmt.Errorf("%w: the subkey file does not hold one back-signature for each primary of the proof", ErrConfig)
	}
	return &Asked{
		typ:         handoff.TypeOpenPGP,
		digest:      p.RequestSHA256,
		subkeyFirst: first,
		backSigs:    sigs,
		sub:         sub,
		primaries:   slices.Clone(p.Primaries),
		capability:  p.Capabilities[0],
	}, nil
}

// AskedX509 makes an Asked from a certificate request file alone: what a requester that uses the floor has.
// The file is read by [pki.ParseRequestFile]; an error that wraps [ErrConfig] means that it is not a request
// of the contract.
func AskedX509(csrFile []byte) (*Asked, error) {
	req, err := pki.ParseRequestFile(csrFile)
	if err != nil {
		return nil, fmt.Errorf("%w: the request file: %w", ErrConfig, err)
	}
	sum := sha256.Sum256(req.DER())
	return &Asked{typ: handoff.TypeX509, digest: hex.EncodeToString(sum[:]), csr: req}, nil
}

// Checker judges answers. It is made by [New], holds its own copy of everything in the [Config], and changes
// nothing afterwards, so one Checker serves any number of calls at once. The zero value was not made by New
// and refuses every call with [ErrConfig].
type Checker struct {
	s *settings
}

// Check judges one answer to one request. A refusal is in the [Verdict]; the error is non-nil only when the
// checker cannot decide: [ErrConfig], [ErrTypeNotBuilt], [ErrUnsupported], [ErrFloorHasResult],
// [ErrNoPrimaryKey] and [ErrInternal]. A verdict that comes with an error is never accepted, and it is not
// refused either: test the error first, and then [Verdict.Accepted]. The files of the answer are copied at
// the top of the call. The clock is read once, cut to whole seconds, and a time outside the years 1970 to
// 2106, or a clock that panics, is an [ErrInternal]. Check never panics: a panic inside it is an
// [ErrInternal] and never an acceptance.
func (c *Checker) Check(a *Asked, ans *Answer) (v Verdict, err error) {
	defer func() {
		if r := recover(); r != nil {
			v, err = Verdict{}, fmt.Errorf("%w: a check panicked", ErrInternal)
		}
	}()
	if c == nil || c.s == nil {
		return Verdict{}, fmt.Errorf("%w: the checker was not made by New", ErrConfig)
	}
	if a == nil || a.typ == "" || ans == nil {
		return Verdict{}, fmt.Errorf("%w: no request or no answer", ErrConfig)
	}
	if !handoff.ValidStem(ans.Stem) {
		return Verdict{}, fmt.Errorf("%w: the stem of the answer is not a stem", ErrConfig)
	}
	if c.s.floor {
		if a.typ != handoff.TypeX509 {
			return Verdict{}, fmt.Errorf("%w: the request is of type %s", ErrUnsupported, a.typ)
		}
		if _, has := ans.Files[FileResult]; has {
			return Verdict{}, ErrFloorHasResult
		}
	}
	if a.typ == handoff.TypeSSH {
		return Verdict{}, fmt.Errorf("%w: the request is of type %s", ErrTypeNotBuilt, a.typ)
	}
	r := &run{s: c.s, a: a, files: copyFiles(ans.Files), stem: ans.Stem}
	now, err := c.s.readClock()
	if err != nil {
		return Verdict{}, err
	}
	r.now = now
	switch {
	case c.s.floor:
		return r.checkFloor()
	case a.typ == handoff.TypeOpenPGP:
		return r.checkOpenPGP()
	default:
		return r.checkX509()
	}
}

// run is the state of one call of Check: what is judged, the files as they were copied at the top of the call,
// and the clock that the call read.
type run struct {
	s     *settings
	a     *Asked
	files map[string][]byte
	stem  string
	now   time.Time
	v     Verdict
}

// copyFiles returns a map that shares nothing with m.
func copyFiles(m map[string][]byte) map[string][]byte {
	out := make(map[string][]byte, len(m))
	for k, v := range m {
		out[k] = bytes.Clone(v)
	}
	return out
}

// readClock reads the clock of the configuration once, under the protection of a recover: a clock that
// panics is an [ErrInternal]. The time is cut to whole seconds, and one outside the years 1970 to 2106
// (what an OpenPGP time field holds) is an ErrInternal too.
func (s *settings) readClock() (now time.Time, err error) {
	defer func() {
		if r := recover(); r != nil {
			now, err = time.Time{}, fmt.Errorf("%w: the clock panicked", ErrInternal)
		}
	}()
	t := s.now().UTC().Truncate(time.Second)
	if u := t.Unix(); u < 1 || u > math.MaxUint32 {
		return time.Time{}, fmt.Errorf("%w: the clock is outside the years 1970 to 2106", ErrInternal)
	}
	return t, nil
}

// digestHex is the SHA-256 of b as 64 lower-case hexadecimal digits.
func digestHex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
