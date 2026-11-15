package history

import (
	"cmp"
	"slices"
	"strings"

	"ritueel.id/ritueel/internal/jsonset"
)

// Code is the name of one finding or one notice. Thirteen are the names of the table "The hash
// chain" in docs/reference/ceremony-record.md; FileUnlisted, UnexpectedName and UnexpectedFile
// are for what the check did not expect.
type Code string

// The codes, in the order the findings are reported in: the order of the page's table, with
// FileUnlisted after FileMissing, then the two codes for what was not expected.
const (
	// ChainBroken: the prev_record_sha256 of a record is not the digest of a record, or a record
	// other than the first has none, or two records have none.
	ChainBroken Code = "chain-broken"
	// Fork: two record files name the same record.
	Fork Code = "fork"
	// RecordOffChain: a record.json that is not on the chain.
	RecordOffChain Code = "record-off-chain"
	// RecordNotCanonical: a record is not in canonical form.
	RecordNotCanonical Code = "record-not-canonical"
	// RecordVersionUnknown: the version of a record is an integer other than 1.
	RecordVersionUnknown Code = "record-version-unknown"
	// RecordInvalid: a record breaks the rules of the page, or is not a file that can be read.
	RecordInvalid Code = "record-invalid"
	// TranscriptDigest: the transcript's digest is not the transcript_sha256 of its record.
	TranscriptDigest Code = "transcript-digest"
	// FileDigest: a file that a record lists fails its digest, or is there and is not the file.
	FileDigest Code = "file-digest"
	// FileMissing: a file that a record lists is not there.
	FileMissing Code = "file-missing"
	// FileUnlisted: a file inside a trust set that no ceremony record lists.
	FileUnlisted Code = "file-unlisted"
	// TrustSetUnlisted: a trust set that no record lists, with no open attempt.
	TrustSetUnlisted Code = "trust-set-unlisted"
	// UnfinishedCeremony: a trust set that no record lists, with an open attempt. A notice.
	UnfinishedCeremony Code = "unfinished-ceremony"
	// AnchorUnknown: the last_record_sha256 of a root list is not a record on the chain, or the
	// list cannot be read, or a list that is not the first has none.
	AnchorUnknown Code = "anchor-unknown"
	// RootReturns: a root list holds a root key that left the root list, by its pin or by its
	// OpenPGP fingerprint under another pin (record 0006, rule 54).
	RootReturns Code = "root-returns"
	// UnexpectedName: a name in history/, in trust/, in a ceremony folder or in a trust set that
	// breaks the rule for names (record 0006, rule 38) and does not start with the prefix of a
	// temporary name; or a link, a FIFO, a socket or a device where a ceremony folder or a trust
	// set belongs.
	UnexpectedName Code = "unexpected-name"
	// UnexpectedFile: a valid name that the check does not expect, or a file of another kind
	// than the one expected, or a leftover temporary name. A notice.
	UnexpectedFile Code = "unexpected-file"
)

// codeOrder is the one place where the order of the codes is.
var codeOrder = []Code{
	ChainBroken, Fork, RecordOffChain, RecordNotCanonical, RecordVersionUnknown, RecordInvalid,
	TranscriptDigest, FileDigest, FileMissing, FileUnlisted, TrustSetUnlisted, UnfinishedCeremony, AnchorUnknown,
	RootReturns, UnexpectedName, UnexpectedFile,
}

// Codes returns every code in the order findings are reported in.
func Codes() []Code { return slices.Clone(codeOrder) }

// rank is the place of c in the order; a code that is not known sorts last.
func (c Code) rank() int {
	if i := slices.Index(codeOrder, c); i >= 0 {
		return i
	}
	return len(codeOrder)
}

// Notice reports whether the code is a notice: a finding that does not end the command with exit
// code 3. These are UnfinishedCeremony (the page) and UnexpectedFile.
func (c Code) Notice() bool { return c == UnfinishedCeremony || c == UnexpectedFile }

// Fails reports whether a finding of this code ends the command with exit code 3.
func (c Code) Fails() bool { return !c.Notice() }

// Finding is one finding or one notice.
type Finding struct {
	// Code is the name of the finding.
	Code Code
	// Path is where: a path of the bundle, "/" separated, in printable ASCII. It is built from
	// names that passed fsx.CheckName, or from a path of a record that passed files.CheckPath;
	// the one exception is a name from the stick that breaks the rule for names or is a leftover
	// temporary name, which it holds written with escapes (jsonset.Escape), never as it is.
	Path string
	// Detail says what is wrong, in a few words of printable ASCII. A text of a file in it is
	// quoted and cut short. A longer detail is cut to its first 240 bytes (not inside a character)
	// and ends with "...", so it is at most 243 bytes.
	Detail string
}

// maxDetail is the longest detail a finding keeps whole, in bytes; a longer one is cut to this
// and marked with "...".
const maxDetail = 240

// Line is the line a person reads: the code, the path, a colon and the detail. It writes every
// character beyond printable ASCII as an escape (jsonset.Escape), as a last guard (the path and
// the detail are printable ASCII already), so that no control code, no look-alike of a letter
// and no byte that is not UTF-8 reaches a terminal. It has no line break. The line of a finding
// with no detail is the code and the path.
func (f Finding) Line() string {
	var b strings.Builder
	b.WriteString(string(f.Code))
	if f.Path != "" {
		b.WriteByte(' ')
		b.WriteString(jsonset.Escape(f.Path))
	}
	if f.Detail != "" {
		b.WriteString(": ")
		b.WriteString(jsonset.Escape(f.Detail))
	}
	return b.String()
}

// compare orders two findings: by the order of the codes, then by path, then by detail.
func compare(a, b Finding) int {
	if c := cmp.Compare(a.Code.rank(), b.Code.rank()); c != 0 {
		return c
	}
	if c := strings.Compare(a.Path, b.Path); c != 0 {
		return c
	}
	return strings.Compare(a.Detail, b.Detail)
}
