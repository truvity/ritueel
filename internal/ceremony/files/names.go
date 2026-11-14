package files

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"ritueel.id/ritueel/internal/fsx"
	"ritueel.id/ritueel/internal/jsonset"
)

// FormatVersion is the version of the plan, the attempt and the ceremony record that this
// package reads: the only one there is.
const FormatVersion = 1

// The names of the files of a ceremony folder, history/<ceremony>/ (record 0006, rule 37), and
// of its folder of copies.
const (
	// PlanFile is the plan (record 0006, rule 9).
	PlanFile = "plan.json"
	// AttemptFile is the attempt.
	AttemptFile = "attempt.json"
	// BirthsFile is the birth journal.
	BirthsFile = "births.jsonl"
	// SignaturesFile is the journal of signatures.
	SignaturesFile = "signatures.jsonl"
	// TranscriptFile is the transcript.
	TranscriptFile = "transcript.txt"
	// RecordFile is the ceremony record, written last.
	RecordFile = "record.json"
	// WantedDir is the folder of exact copies of the wanted files that the plan used. The
	// name is Proposed on the page (issue 8).
	WantedDir = "wanted"
)

// MaxPathElements is the most elements a path that a record or a plan lists may have: 12. The
// deepest path that the pages let a ceremony write has 4: trust/<set>/keyring/<file> (the
// keyring package page) and roots/<label>/attestation/<file> (the cards page); the copies of
// the wanted files are listed by the path they have in the bundle, want/<kind>/<file>, 3. 12 is
// three times that. Without a limit a record of 256 KiB could list paths of two thousand
// one-letter elements, and each distinct path costs one system call for each element. With it a
// path is at most 12 elements of at most 255 bytes, 3,071 bytes, so no limit in bytes is needed.
const MaxPathElements = 12

// Digest returns the SHA-256 of b, 64 lower-case hexadecimal characters. A digest of a file is
// over the bytes as stored.
func Digest(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// IsDigest reports whether s is a SHA-256 digest as the pages write it: 64 lower-case
// hexadecimal characters.
func IsDigest(s string) bool {
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

// CheckTime reports whether s is a time as the pages write it: YYYY-MM-DDThh:mm:ssZ, UTC, whole
// seconds, 20 characters. The parser of the standard library also takes a fraction and an offset,
// so the length and the two letters are checked first.
func CheckTime(s string) error {
	if len(s) != 20 || s[10] != 'T' || s[19] != 'Z' {
		return errors.New("not a time of the form YYYY-MM-DDThh:mm:ssZ")
	}
	if _, err := time.Parse(time.RFC3339, s); err != nil {
		return errors.New("not a time of the form YYYY-MM-DDThh:mm:ssZ")
	}
	return nil
}

// CheckPath reports whether p is a path of a bundle as a record lists it: "/" separated, not
// empty, not absolute, at most [MaxPathElements] elements, and every element passes fsx.CheckName (so
// there is no empty element, no "." or "..", no backslash, no name that starts with the prefix of
// a temporary name, no character beyond the ASCII letters, digits, dot, hyphen and underscore).
// The error never holds the path.
func CheckPath(p string) error {
	if p == "" {
		return errors.New("is empty")
	}
	if p[0] == '/' {
		return errors.New("is absolute")
	}
	elems := strings.Split(p, "/")
	if len(elems) > MaxPathElements {
		return fmt.Errorf("has more than %d elements", MaxPathElements)
	}
	for _, e := range elems {
		if err := fsx.CheckName(e); err != nil {
			return errors.New("has an element that is not a plain name (record 0006, rule 38)")
		}
	}
	return nil
}

// shown writes a text from a file for an error: quoted, cut short, with every character beyond
// printable ASCII as an escape.
func shown(s string) string { return jsonset.Quote(s) }
