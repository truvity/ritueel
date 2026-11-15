package bundle

import (
	"errors"
	"fmt"
	"io/fs"
	"strings"

	"ritueel.id/ritueel/internal/fsx"
	"ritueel.id/ritueel/internal/handoff"
	"ritueel.id/ritueel/internal/jsonset"
	"ritueel.id/ritueel/internal/openpgp"
)

// keyringFile is the name of the keyring file inside a trust set: the one place in this package that holds it
// (docs/reference/keyring-package.md, "The first form of the keyring file"). The name and the place of the file
// are decided: one flat file named keyring.gpg, beside the other three files of the trust set. Nothing else in the
// program writes the name down: every sentence that names it takes it from here. The bundle keeps its own copy of
// the name, as it does for the root list and the CA bundle; a test of internal/trustset pins that the two agree.
const keyringFile = "keyring.gpg"

// maxCauseText is the most characters of the cause that the error of a refused keyring file shows.
const maxCauseText = 240

// ErrPrimaries is the kind of every error of [Bundle.Primaries] and of [Bundle.Checker] that comes from the
// OpenPGP primaries of the newest trust set: a trust set that pins them and holds no keyring file, and a keyring
// file that cannot be read or is refused. A root list that pins more of them than the checks take, or gives one
// fingerprint to two entries, is also of this kind, but the reader of the root list refuses both first, so
// through a real bundle they are faults of [Bundle.Roots]. A caller that asks for this one kind finds every fault of this path;
// the text of each is a plain sentence. The faults of the set that [Bundle.Roots] also finds (the list, the CA
// bundle) are not of this kind.
var ErrPrimaries = errors.New("bundle: the OpenPGP primaries of the trust set cannot be taken")

// ErrNoKeyring is wrapped, beside [ErrPrimaries], by the error of [Bundle.Primaries] (and so of [Bundle.Checker])
// for a trust set whose root list pins OpenPGP primaries and that holds no keyring file.
var ErrNoKeyring = errors.New("bundle: the trust set pins OpenPGP primaries and holds no keyring file")

// Primaries returns the OpenPGP primaries of the bundle in the form the checks need, read from the newest trust
// set (the one that [Bundle.Roots] reads): the fingerprint, the key and the creation time of each, in the order
// of its root list, and the set they were read from.
//
// The entries are those of the root list that have an openpgp_fingerprint, in the order of the list. A list that
// pins none gives an empty list and no error, and a keyring file in such a set is an error: it holds a primary
// that is not on the list (this one call reads the file to know). A list that pins primaries and a set with no
// keyring file gives an error that wraps [ErrNoKeyring]. The file is read through package fsx (a link, a folder
// or a file over its size limit is an error here, never "absent") and judged by [openpgp.ReadKeyring] with the
// entries of the list, so every refusal of that reader is an error here, and an error that wraps
// [openpgp.ErrKeyring] when it is one of the file. More primaries than [handoff.MaxPrimaries] is an error too:
// the checker takes no more (the reader of the root list holds no more entries, so this is a second guard), and
// so is a list that gives one fingerprint to two entries, which the reader of the root list refuses first; the
// sentences of both name the list and not the file. Every error of this
// call that comes from the primaries is of the kind [ErrPrimaries]. No primary is returned with an error.
//
// Primaries reads the set that Roots reads, with the same rules: the newest set is never replaced by an older
// one when its files are bad. The signature of the list and its expiry are not checked here.
func (b *Bundle) Primaries() ([]handoff.PrimaryRef, TrustSet, error) {
	n, err := b.readNewest()
	if err != nil {
		return nil, TrustSet{}, err
	}
	refs, err := b.primariesOf(n, true)
	if err != nil {
		return nil, TrustSet{}, err
	}
	return refs, n.set, nil
}

// pinnedEntries returns the entries of the root list that have an openpgp_fingerprint, in the order of the list. A
// list in which only some entries have one is read as it is: the writer refuses such a list, the reader does
// not.
func pinnedEntries(n *newestSet) []openpgp.KeyringEntry {
	var entries []openpgp.KeyringEntry
	for _, r := range n.list.Roots {
		if r.OpenPGPFingerprint != "" {
			entries = append(entries, openpgp.KeyringEntry{Label: r.Label, Fingerprint: r.OpenPGPFingerprint})
		}
	}
	return entries
}

// primariesOf reads the primaries of one reading of the newest set. When the list pins none it returns none; it
// then reads the keyring file only when probe is set, to refuse a file that no entry names. It returns nothing
// with an error.
func (b *Bundle) primariesOf(n *newestSet, probe bool) ([]handoff.PrimaryRef, error) {
	entries := pinnedEntries(n)
	at := TrustDir + "/" + n.set.Name + "/" + keyringFile
	if len(entries) == 0 {
		if !probe {
			return nil, nil
		}
		_, err := fsx.ReadFile(b.fsys, at)
		switch {
		case err == nil:
			return nil, refusedKeyring(n.set, fmt.Errorf("%w: the root list pins no OpenPGP primary, so the file holds a primary that is not on the list", openpgp.ErrKeyringPrimaries))
		case errors.Is(err, fs.ErrNotExist):
			return nil, nil
		default:
			return nil, refusedKeyring(n.set, fmt.Errorf("%w: %w", openpgp.ErrKeyring, err))
		}
	}
	if len(entries) > handoff.MaxPrimaries {
		return nil, &primariesError{text: fmt.Sprintf("the root list of the newest trust set %s pins %d OpenPGP primaries, and the checks take at most %d",
			jsonset.EscapeExact(n.set.Name), len(entries), handoff.MaxPrimaries)}
	}
	if first, second, twice := sameFingerprint(entries); twice {
		return nil, &primariesError{text: fmt.Sprintf("the root list of the newest trust set %s gives one openpgp_fingerprint to two entries: the entry with the label %s and the entry with the label %s",
			jsonset.EscapeExact(n.set.Name), jsonset.EscapeExact(first.Label), jsonset.EscapeExact(second.Label))}
	}
	file, err := fsx.ReadFile(b.fsys, at)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil, noKeyring(n.set, err)
	case err != nil:
		return nil, refusedKeyring(n.set, fmt.Errorf("%w: %w", openpgp.ErrKeyring, err))
	}
	keys, err := openpgp.ReadKeyring(file, entries)
	switch {
	case errors.Is(err, openpgp.ErrParams):
		// The reader refuses the entries before it reads the file: the fault is the list's, not the file's.
		return nil, &primariesError{
			text:  fmt.Sprintf("the root list of the newest trust set %s cannot be held to a keyring file: %s", jsonset.EscapeExact(n.set.Name), causeText(err)),
			cause: err,
		}
	case err != nil:
		return nil, refusedKeyring(n.set, err)
	}
	if len(keys) != len(entries) {
		return nil, refusedKeyring(n.set, fmt.Errorf("%w: the reader gave %d primaries for %d entries", openpgp.ErrKeyringPrimaries, len(keys), len(entries)))
	}
	refs := make([]handoff.PrimaryRef, 0, len(keys))
	for _, k := range keys {
		refs = append(refs, handoff.PrimaryRef{Fingerprint: k.Fingerprint(), Key: k.PublicKey(), Created: k.Created()})
	}
	return refs, nil
}

// sameFingerprint finds the first entry whose fingerprint an earlier entry has already. It returns the earlier
// entry and that one.
func sameFingerprint(entries []openpgp.KeyringEntry) (first, second openpgp.KeyringEntry, twice bool) {
	seen := make(map[string]openpgp.KeyringEntry, len(entries))
	for _, e := range entries {
		if f, ok := seen[e.Fingerprint]; ok {
			return f, e, true
		}
		seen[e.Fingerprint] = e
	}
	return openpgp.KeyringEntry{}, openpgp.KeyringEntry{}, false
}

// primariesError is the error of the primaries of the newest trust set: of its list, of its keyring file, or of
// the file that is missing. It is of the kind [ErrPrimaries]. Its text is a plain sentence that names the set
// and, for a refusal, the cause, escaped and cut once when the error is made; the cause stays reachable with
// errors.Is and errors.As.
type primariesError struct {
	text  string
	cause error
}

func (e *primariesError) Error() string { return e.text }
func (e *primariesError) Unwrap() error { return e.cause }

// Is makes every primariesError of the kind [ErrPrimaries], whatever its cause.
func (e *primariesError) Is(target error) bool { return target == ErrPrimaries }

// noKeyring is the error for a set that pins primaries and holds no keyring file. It wraps [ErrNoKeyring] and
// the error of the read.
func noKeyring(set TrustSet, readErr error) error {
	return &primariesError{
		text:  fmt.Sprintf("the newest trust set %s pins OpenPGP primaries and holds no %s", jsonset.EscapeExact(set.Name), keyringFile),
		cause: fmt.Errorf("%w: %w", ErrNoKeyring, readErr),
	}
}

// refusedKeyring is the error for a keyring file that cannot be read or that the reader refuses.
func refusedKeyring(set TrustSet, cause error) error {
	return &primariesError{
		text:  fmt.Sprintf("%s of the newest trust set %s is refused: %s", keyringFile, jsonset.EscapeExact(set.Name), causeText(cause)),
		cause: cause,
	}
}

// causeText is the text of a cause, taken once, under a recover, escaped and cut. A text of a file never
// reaches it unescaped.
func causeText(cause error) (text string) {
	defer func() {
		if recover() != nil {
			text = "the cause cannot be shown"
		}
	}()
	if cause == nil {
		return "no cause"
	}
	return cutEscaped(cause.Error())
}

// cutEscaped escapes s one character at a time and stops before the character whose escape would pass
// maxCauseText, so that a whole escape is kept or dropped (a character above U+FFFF is a pair of escapes, and the
// pair goes as one). A cut text ends in three dots. The text that [jsonset.Escape] leaves as it is, a backslash
// among it, can still end in what looks like the start of an escape; that end is dropped too.
func cutEscaped(s string) string {
	var b strings.Builder
	for _, r := range s {
		piece := jsonset.Escape(string(r))
		if b.Len()+len(piece) > maxCauseText {
			return dropLooseEscape(b.String()) + "..."
		}
		b.WriteString(piece)
	}
	return b.String()
}

// dropLooseEscape removes from the end of s a backslash, or a backslash and u with fewer than four hexadecimal
// digits, that comes from the text itself.
func dropLooseEscape(s string) string {
	for n := 1; n <= 5 && n <= len(s); n++ {
		if tail := s[len(s)-n:]; tail[0] == '\\' && (n == 1 || (tail[1] == 'u' && strings.Trim(tail[2:], "0123456789abcdefABCDEF") == "")) {
			return s[:len(s)-n]
		}
	}
	return s
}
