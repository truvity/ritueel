package cards

import (
	"context"
	"errors"
	"slices"
	"strconv"
	"strings"

	"ritueel.id/ritueel/internal/fsx"
	"ritueel.id/ritueel/internal/wanted"
)

// yamlSuffix ends the name of every wanted card file.
const yamlSuffix = ".yaml"

// Report is what [Inspect] found. Only Inspect makes a usable one: the zero Report and a Report that a
// caller built by hand are not usable (the unexported field made), so that a caller that forgot to run the
// check cannot read "no finding" from it. A caller treats a Report and its cards as read-only: it does not
// change a field, a finding or a card, and it does not keep a changed copy as if the check had made it.
type Report struct {
	// Cards are the cards whose files passed their reader, in the order of their names. A card that is in a
	// finding of the set (SerialTwice) is in this list too: its file is valid.
	Cards []*wanted.Card
	// Findings are in the order of [Codes], then by path, then by detail.
	Findings []Finding

	made bool
}

// Valid reports whether r was made by [Inspect]. It is false for a nil Report and for the zero value.
func (r *Report) Valid() bool { return r != nil && r.made }

// Refusals returns the findings that stop apply, in the order of Findings. It returns nil for a Report that is
// not Valid, and when no finding refuses.
func (r *Report) Refusals() []Finding {
	if !r.Valid() {
		return nil
	}
	var out []Finding
	for _, f := range r.Findings {
		if f.Code.Refuses() {
			out = append(out, f)
		}
	}
	return out
}

// Clean reports whether the report is Valid and no finding refuses. It is false for a nil Report and for the
// zero Report: a zero value fails closed.
func (r *Report) Clean() bool { return r.Valid() && len(r.Refusals()) == 0 }

// cardPath is the path of the card file of a name that passed [wanted.ValidName].
func cardPath(name string) string { return wanted.CardsDir + "/" + name + yamlSuffix }

// Inspect reads every card file of the bundle that fsys is the root of, once, one at a time, and returns the
// cards and the findings. It reads no card, no other wanted file and no other folder. A file that fails its
// reader is a finding (FileInvalid), not an error; so is a file over the limit of a read of package fsx,
// which is a fault of the file and not of the system. An error is returned, and no report, when the check
// cannot run: no context or file system, a canceled context, a folder that cannot be listed, a name that
// breaks the rules, more than [wanted.MaxCards] names (and then no file is read), or a file that cannot be
// read for a reason that is not its text (a read fault, a link, a file that went away after it was listed).
// The error of a canceled context is the context's own.
func Inspect(ctx context.Context, fsys fsx.FS) (*Report, error) {
	if ctx == nil {
		return nil, errors.New("cards: there is no context")
	}
	if fsys == nil {
		return nil, errors.New("cards: there is no bundle to read")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	names, err := wanted.ListCardNames(fsys)
	if err != nil {
		return nil, err
	}
	if len(names) > wanted.MaxCards {
		return nil, &wanted.Error{Path: wanted.CardsDir, Msg: "there are more than " + strconv.Itoa(wanted.MaxCards) + " card files, and none was read"}
	}
	rep := &Report{Cards: make([]*wanted.Card, 0, len(names))}
	for _, name := range names {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		c, err := wanted.LoadCard(fsys, name)
		if err != nil {
			f, ferr := fileFinding(name, err)
			if ferr != nil {
				return nil, ferr
			}
			rep.Findings = append(rep.Findings, f)
			continue
		}
		if !c.Valid() || c.SerialKey() == "" {
			return nil, &wanted.Error{Path: cardPath(name), Msg: "the reader of card files gave a card that is not usable"}
		}
		rep.Cards = append(rep.Cards, c)
	}
	rep.Findings = append(rep.Findings, serialTwice(rep.Cards)...)
	slices.SortStableFunc(rep.Findings, compareFindings)
	rep.made = true
	return rep, nil
}

// fileFinding turns the error of reading one card file into a finding, or says that it is an error of the
// check. A fault of the text of a file is a [*wanted.Error] with no cause; a file over the limit of a read
// has the cause [fsx.ErrTooLarge] and is a fault of the file too. Every other error has a cause that is a
// fault of the system, or is not a [*wanted.Error] at all, and stops the check. The line and the text are
// taken from the fields of the error once: no method of a cause is called.
func fileFinding(name string, err error) (Finding, error) {
	var we *wanted.Error
	if !errors.As(err, &we) || we == nil {
		return Finding{}, err
	}
	if errors.Unwrap(we) != nil && !errors.Is(err, fsx.ErrTooLarge) {
		return Finding{}, err
	}
	detail := we.Msg
	if we.Line > 0 {
		detail = "line " + strconv.Itoa(we.Line) + ": " + detail
	}
	return newFinding(FileInvalid, cardPath(name), detail), nil
}

// firstFile is the first file of one card, as the set check keeps it.
type firstFile struct {
	path string
	kind wanted.CardKind
}

// serialTwice is the set check: the valid cards are grouped by the identity of their serial, and every file
// after the first of a group, in the order of the names, is a finding at its own path. It holds one map from
// the identity to the first file, so its memory is that of the names.
func serialTwice(cards []*wanted.Card) []Finding {
	var out []Finding
	seen := make(map[string]firstFile, len(cards))
	for _, c := range cards {
		key := c.SerialKey()
		f, ok := seen[key]
		if !ok {
			seen[key] = firstFile{path: cardPath(c.Name), kind: c.Kind}
			continue
		}
		detail := "the same card as " + f.path
		if f.kind != c.Kind {
			detail += "; the kinds differ"
		}
		out = append(out, newFinding(SerialTwice, cardPath(c.Name), detail))
	}
	return out
}

// compareFindings orders findings by the order of [Codes], then by path, then by detail.
func compareFindings(a, b Finding) int {
	if c := slices.Index(codes, a.Code) - slices.Index(codes, b.Code); c != 0 {
		return c
	}
	if c := strings.Compare(a.Path, b.Path); c != 0 {
		return c
	}
	return strings.Compare(a.Detail, b.Detail)
}

// errNoReport is the error of a check that gave a report that is not usable.
var errNoReport = errors.New("cards: the check of the card files gave no usable report")
