package cards

import (
	"context"
	"strconv"

	"ritueel.id/ritueel/internal/fsx"
	"ritueel.id/ritueel/internal/wanted"
)

// Check is [Inspect] for apply (record 0005, rule 19): nil when the report is valid and no finding refuses,
// and otherwise a [*wanted.Error] whose path is the path of the first refusing finding and whose text is its
// detail and, when there are more refusing findings, their number. An error of Inspect is returned as it
// is. The text of the error is made from fixed words and the detail of a finding; no method of a cause is
// called.
func Check(ctx context.Context, fsys fsx.FS) error {
	_, err := Load(ctx, fsys)
	return err
}

// Load is [Check] that also returns the cards: when it returns nil as the error, the cards are the valid cards
// of the bundle in the order of their names, every one of them read in this call and none of them skipped. A
// refusing finding is an error and no card comes with it.
func Load(ctx context.Context, fsys fsx.FS) ([]*wanted.Card, error) {
	rep, err := Inspect(ctx, fsys)
	if err != nil {
		return nil, err
	}
	if !rep.Valid() {
		return nil, errNoReport
	}
	refusals := rep.Refusals()
	if len(refusals) == 0 {
		return rep.Cards, nil
	}
	msg := refusals[0].Detail
	switch more := len(refusals) - 1; {
	case more == 1:
		msg += " (and 1 more finding)"
	case more > 1:
		msg += " (and " + strconv.Itoa(more) + " more findings)"
	}
	return nil, &wanted.Error{Path: refusals[0].Path, Msg: msg}
}
