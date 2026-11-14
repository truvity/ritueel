package files

import (
	"ritueel.id/ritueel/internal/canonjson"
	"ritueel.id/ritueel/internal/strictjson"
)

// The two commands that leave a ceremony record, and the three outcomes of a record.
const (
	// CommandApply is a ceremony of a plan.
	CommandApply = "apply"
	// CommandClose is the closing record of a ceremony that stopped.
	CommandClose = "close"
	// OutcomeCompleted is a ceremony that signed what its plan said.
	OutcomeCompleted = "completed"
	// OutcomeDeclined is a ceremony in which the person declined the request.
	OutcomeDeclined = "declined"
	// OutcomeClosed is the outcome of a closing record.
	OutcomeClosed = "closed"
)

// FileRef is a file that a record or a plan lists: a path and the SHA-256 of the file's bytes as
// stored.
type FileRef struct {
	// Path is the path of the file: in a bundle for an artifact, and under wanted/ of the
	// ceremony folder for a copy of a wanted file.
	Path string `json:"path"`
	// SHA256 is the digest of the file.
	SHA256 string `json:"sha256"`
}

// PlanRoot is the root key that signs: "root" in the plan and in the record.
type PlanRoot struct {
	// Label is the key's label.
	Label string `json:"label,omitempty"`
	// Store is the key store.
	Store string `json:"store,omitempty"`
	// X509 is the fingerprint of the X.509 key.
	X509 string `json:"x509,omitempty"`
	// OpenPGP is the fingerprint of the OpenPGP primary.
	OpenPGP string `json:"openpgp,omitempty"`
	// Test is true for a test root.
	Test bool `json:"test,omitempty"`
	// Copyable is true for a key file.
	Copyable bool `json:"copyable,omitempty"`
}

// Confirmation is "confirmation" of a record: how the plan was confirmed, and when.
type Confirmation struct {
	// By is "typed" or "flag".
	By string `json:"by"`
	// At is when, a time; it is left out when not known.
	At string `json:"at,omitempty"`
}

// Advisory is "advisory_review" of a record.
type Advisory struct {
	// At is when the holder answered; it is left out when not known.
	At string `json:"at,omitempty"`
	// Note is the short note of what they read.
	Note string `json:"note"`
}

// Declined is "declined" of a declining record.
type Declined struct {
	// Stem is the request declined.
	Stem string `json:"stem"`
	// Reason is the reason the person gave.
	Reason string `json:"reason"`
}

// Closes is "closes" of a closing record: the attempt it resolves.
type Closes struct {
	// Ceremony is the name of the ceremony whose attempt is closed.
	Ceremony string `json:"ceremony"`
	// AttemptSHA256 is the digest of that attempt file.
	AttemptSHA256 string `json:"attempt_sha256"`
	// Reason is the reason the person gave.
	Reason string `json:"reason"`
}

// Record is record.json, version 1: the members of the table "The record" of
// docs/reference/ceremony-record.md. A member whose shape the page leaves open or Proposed is
// kept as any, a list of any or strictjson.Raw, and is not looked into.
//
// What [ReadRecord] requires: version, ceremony, command, outcome, transcript_sha256 and artifacts
// (the member present, the list may be empty) in every record; plan_sha256 and a wanted list
// with at least one entry (a plan always uses ritueel.yaml) in a record of the command apply;
// closes with its ceremony and attempt_sha256 in a record of the command close. The members
// attempt_sha256, births_sha256 and signatures_sha256 are optional, and are only in a completed
// apply. A time inside
// confirmation and advisory_review is checked when it is there, and is not required. It refuses what
// the table says is absent or only in some records: closes only in a closing record, declined
// only when the outcome is declined, no plan_sha256, root or root_reason in a closing record,
// and the command close with the outcome closed and no other.
type Record struct {
	Version          int64          `json:"version"`
	Ceremony         string         `json:"ceremony"`
	Command          string         `json:"command"`
	Arguments        strictjson.Raw `json:"arguments,omitempty"`
	Outcome          string         `json:"outcome"`
	PlanSHA256       string         `json:"plan_sha256,omitempty"`
	PrevRecordSHA256 string         `json:"prev_record_sha256,omitempty"`
	StartedAt        string         `json:"started_at,omitempty"`
	FinishedAt       string         `json:"finished_at,omitempty"`
	Root             *PlanRoot      `json:"root,omitempty"`
	RootReason       string         `json:"root_reason,omitempty"`
	SlotMapVersion   int64          `json:"slot_map_version,omitempty"`
	Confirmation     *Confirmation  `json:"confirmation,omitempty"`
	RanOn            string         `json:"ran_on,omitempty"`
	LimitShown       bool           `json:"limit_shown,omitempty"`
	Requests         []any          `json:"requests,omitempty"`
	Wanted           []FileRef      `json:"wanted,omitempty"`
	Applied          []any          `json:"applied,omitempty"`
	LeftOut          []any          `json:"left_out,omitempty"`
	Signatures       []any          `json:"signatures,omitempty"`
	Artifacts        []FileRef      `json:"artifacts"`
	// The digests of the attempt and of the two journals of the ceremony. They are optional: a
	// record names the file when the ceremony wrote it. The three names are written here and in
	// recordNoEmpty and in validate, and nowhere else.
	AttemptSHA256    string    `json:"attempt_sha256,omitempty"`
	BirthsSHA256     string    `json:"births_sha256,omitempty"`
	SignaturesSHA256 string    `json:"signatures_sha256,omitempty"`
	TrustSequence    int64     `json:"trust_sequence,omitempty"`
	TranscriptSHA256 string    `json:"transcript_sha256"`
	AdvisoryReview   *Advisory `json:"advisory_review,omitempty"`
	Declined         *Declined `json:"declined,omitempty"`
	Closes           *Closes   `json:"closes,omitempty"`
	Revocations      []any     `json:"revocations,omitempty"`
}

// recordNoEmpty are the optional members of a record that are a digest, a time, a name or a word,
// and that are left out rather than written as an empty text.
var recordNoEmpty = []string{
	"prev_record_sha256", "plan_sha256", "started_at", "finished_at", "root_reason", "ran_on",
	"confirmation.at", "advisory_review.at", "attempt_sha256", "births_sha256", "signatures_sha256",
}

// ReadRecord reads the bytes of one record.json. It reads the version first and alone: a version
// other than 1 is a *[VersionError] and nothing else of the file is read. Any other fault
// wraps strictjson.ErrMalformed or is a *[FormatError]. It does not test the canonical form: the
// caller does, on the same bytes, with canonjson.IsCanonical.
func ReadRecord(data []byte) (*Record, error) {
	var r Record
	if err := readVersioned(data, "ceremony record", &r, recordNoEmpty...); err != nil {
		return nil, err
	}
	if err := r.validate(); err != nil {
		return nil, err
	}
	return &r, nil
}

// Canonical returns the record in the canonical form of RFC 8785, with no trailing newline: the
// bytes that ritueel writes and that a digest is over. A nil list of artifacts is written as an
// empty list, because the member always appears.
func (r *Record) Canonical() ([]byte, error) {
	c := *r
	if c.Artifacts == nil {
		c.Artifacts = []FileRef{}
	}
	return canonjson.Marshal(&c)
}

func (r *Record) validate() error {
	c := checker{what: "ceremony record"}
	steps := []error{
		c.name("ceremony", r.Ceremony, true),
		c.oneOf("command", r.Command, CommandApply, CommandClose),
		c.oneOf("outcome", r.Outcome, OutcomeCompleted, OutcomeDeclined, OutcomeClosed),
		c.digest("plan_sha256", r.PlanSHA256, false),
		c.digest("prev_record_sha256", r.PrevRecordSHA256, false),
		c.time("started_at", r.StartedAt, false),
		c.time("finished_at", r.FinishedAt, false),
		c.digest("transcript_sha256", r.TranscriptSHA256, true),
		c.digest("attempt_sha256", r.AttemptSHA256, false),
		c.digest("births_sha256", r.BirthsSHA256, false),
		c.digest("signatures_sha256", r.SignaturesSHA256, false),
	}
	for _, err := range steps {
		if err != nil {
			return err
		}
	}
	if r.Artifacts == nil {
		return c.missing("artifacts")
	}
	if err := c.refs("artifacts", r.Artifacts); err != nil {
		return err
	}
	if err := c.refs("wanted", r.Wanted); err != nil {
		return err
	}
	if cf := r.Confirmation; cf != nil {
		if err := c.oneOf("confirmation.by", cf.By, "typed", "flag"); err != nil {
			return err
		}
		if err := c.time("confirmation.at", cf.At, false); err != nil {
			return err
		}
	}
	if a := r.AdvisoryReview; a != nil {
		if err := c.time("advisory_review.at", a.At, false); err != nil {
			return err
		}
	}
	return r.validateKinds(c)
}

// validateKinds checks what the table says of each kind of record: the closing record, the
// record of a plan, and the declining record.
func (r *Record) validateKinds(c checker) error {
	if r.Declined != nil && r.Outcome != OutcomeDeclined {
		return formatError(c.what, "declined", "is only in a record with the outcome declined")
	}
	// A declined record and a closing record have no attempt and no journals of their own. For a
	// declined request no attempt is written and nothing is signed or born, and the journals are
	// made with the attempt; a closing record names the attempt it closes in closes and has no
	// journals. So the three members are only in a completed apply.
	if r.Outcome != OutcomeCompleted || r.Command != CommandApply {
		for _, m := range []struct{ name, digest string }{
			{"attempt_sha256", r.AttemptSHA256}, {"births_sha256", r.BirthsSHA256}, {"signatures_sha256", r.SignaturesSHA256},
		} {
			if m.digest != "" {
				return formatError(c.what, m.name, "is only in a record of an apply that was completed: a declined record and a closing record have no attempt and no journals")
			}
		}
	}
	if r.Command == CommandApply {
		if r.Outcome == OutcomeClosed {
			return formatError(c.what, "outcome", "closed is the outcome of a closing record only")
		}
		if r.Closes != nil {
			return formatError(c.what, "closes", "is only in a closing record")
		}
		if r.PlanSHA256 == "" {
			return c.missing("plan_sha256")
		}
		if len(r.Wanted) == 0 {
			return c.missing("wanted")
		}
		return nil
	}
	// A closing record.
	switch {
	case r.Outcome != OutcomeClosed:
		return formatError(c.what, "outcome", "a closing record has the outcome closed")
	case r.PlanSHA256 != "":
		return formatError(c.what, "plan_sha256", "is absent in a closing record")
	case r.Root != nil:
		return formatError(c.what, "root", "is absent in a closing record")
	case r.RootReason != "":
		return formatError(c.what, "root_reason", "is absent in a closing record")
	case r.Closes == nil:
		return c.missing("closes")
	}
	if err := c.name("closes.ceremony", r.Closes.Ceremony, true); err != nil {
		return err
	}
	return c.digest("closes.attempt_sha256", r.Closes.AttemptSHA256, true)
}
