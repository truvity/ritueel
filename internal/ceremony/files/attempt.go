package files

import (
	"ritueel.id/ritueel/internal/canonjson"
	"ritueel.id/ritueel/internal/strictjson"
)

// Attempt is attempt.json, version 1: the members of the table "The attempt" of
// docs/reference/ceremony-record.md. [ReadAttempt] requires version, ceremony and plan_sha256, the
// members that a check of the history reads; root and started_at are optional, checked when
// present, and refused as an empty text.
type Attempt struct {
	Version    int64  `json:"version"`
	Ceremony   string `json:"ceremony"`
	PlanSHA256 string `json:"plan_sha256"`
	Root       string `json:"root,omitempty"`
	StartedAt  string `json:"started_at,omitempty"`
}

// ReadAttempt reads the bytes of one attempt.json, as [ReadRecord] reads a record: the version
// first and alone, then the strict reader, then the rules of the page.
func ReadAttempt(data []byte) (*Attempt, error) {
	var a Attempt
	if err := readVersioned(data, "attempt", &a, "root", "started_at"); err != nil {
		return nil, err
	}
	c := checker{what: "attempt"}
	for _, err := range []error{
		c.name("ceremony", a.Ceremony, true),
		c.digest("plan_sha256", a.PlanSHA256, true),
		c.time("started_at", a.StartedAt, false),
	} {
		if err != nil {
			return nil, err
		}
	}
	return &a, nil
}

// Canonical returns the attempt in the canonical form of RFC 8785, with no trailing newline.
func (a *Attempt) Canonical() ([]byte, error) { return canonjson.Marshal(a) }

// Plan is plan.json, version 1: the members of the table "The plan" of
// docs/reference/ceremony-record.md. [ReadPlan] requires version, ceremony, command (apply) and
// trust_sequence, the members that a check of the history reads, and checks the digests, times and paths it
// finds. The members whose shape the page leaves open or Proposed are read as any, a list of
// any, or strictjson.Raw, and are not looked into.
type Plan struct {
	Version          int64          `json:"version"`
	Ceremony         string         `json:"ceremony"`
	Command          string         `json:"command"`
	Arguments        strictjson.Raw `json:"arguments,omitempty"`
	MadeAt           string         `json:"made_at,omitempty"`
	Ritueel          strictjson.Raw `json:"ritueel,omitempty"`
	CeremonyTime     string         `json:"ceremony_time,omitempty"`
	Wanted           []FileRef      `json:"wanted,omitempty"`
	Inputs           []FileRef      `json:"inputs,omitempty"`
	Applies          []any          `json:"applies,omitempty"`
	LeavesOut        []any          `json:"leaves_out,omitempty"`
	LastRecordSHA256 string         `json:"last_record_sha256,omitempty"`
	Root             *PlanRoot      `json:"root,omitempty"`
	RootReason       string         `json:"root_reason,omitempty"`
	Requests         []any          `json:"requests,omitempty"`
	Signatures       []any          `json:"signatures,omitempty"`
	Births           []any          `json:"births,omitempty"`
	Touches          int64          `json:"touches,omitempty"`
	BaseSequence     int64          `json:"base_sequence,omitempty"`
	// TrustSequence is a pointer so that a missing member is told from a zero.
	TrustSequence *int64 `json:"trust_sequence"`
}

// ReadPlan reads the bytes of one plan.json, as [ReadRecord] reads a record.
func ReadPlan(data []byte) (*Plan, error) {
	var p Plan
	if err := readVersioned(data, "plan", &p, "made_at", "ceremony_time", "last_record_sha256", "root_reason"); err != nil {
		return nil, err
	}
	c := checker{what: "plan"}
	for _, err := range []error{
		c.name("ceremony", p.Ceremony, true),
		c.oneOf("command", p.Command, CommandApply),
		c.time("made_at", p.MadeAt, false),
		c.time("ceremony_time", p.CeremonyTime, false),
		c.refs("wanted", p.Wanted),
		c.refs("inputs", p.Inputs),
		c.digest("last_record_sha256", p.LastRecordSHA256, false),
	} {
		if err != nil {
			return nil, err
		}
	}
	if p.TrustSequence == nil {
		return nil, c.missing("trust_sequence")
	}
	return &p, nil
}

// Canonical returns the plan in the canonical form of RFC 8785, with no trailing newline. A plan
// is read with a trust_sequence, so a plan to write has one.
func (p *Plan) Canonical() ([]byte, error) { return canonjson.Marshal(p) }
