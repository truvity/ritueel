package fsx_test

// CheckName is the rule of one final name, for a name that the caller has from somewhere else (a
// folder listing: data from the stick) and wants to know the writer would take. One table drives
// both: a name that CheckName accepts is written as a final name by each method, and one that it
// refuses is refused by the writer, with the same reason.

import (
	"errors"
	"strconv"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/fsx"
)

// checkNameText is the text of CheckName for a refusal with the reason.
func checkNameText(name, reason string) string {
	return invalidPrefix + "name " + strconv.QuoteToASCII(name) + " " + reason
}

// refusedForCheckName is every refused name of the tables with the reason of its refusal.
func refusedForCheckName() []nameRow {
	var rows []nameRow
	rows = append(rows, refusedBytes(true)...)
	rows = append(rows, refusedOther...)
	rows = append(rows, refusedDeviceNames...)
	for _, c := range notPlainNames {
		reason := strings.TrimPrefix(c.text, fileText(c.name, ""))
		rows = append(rows, nameRow{c.why, c.name, reason})
	}
	for _, c := range prefixNames {
		rows = append(rows, nameRow{c.why, c.name, whyNotPlain})
	}
	return rows
}

func TestCheckNameRefusesWhatTheWriterRefusesWithTheSameReason(t *testing.T) {
	rows := refusedForCheckName()
	if len(rows) < 600 {
		t.Fatalf("only %d rows", len(rows))
	}
	for _, row := range rows {
		err := fsx.CheckName(row.name)
		want := checkNameText(row.name, row.reason)
		if err == nil || err.Error() != want || !errors.Is(err, fsx.ErrInvalid) {
			t.Fatalf("%s: CheckName(%q) = %v, want an ErrInvalid error with the text\n  %s", row.why, row.name, err, want)
		}
		requirePrintableASCII(t, err.Error())
	}
}

// The writer, for a sample that holds each kind of refusal, says the same reason.
func TestTheWriterAgreesWithCheckNameOnTheReasonOfARefusal(t *testing.T) {
	for _, row := range refusedForCheckName() {
		f := newMemFS("b", "b/d")
		w := newWriter(t, f, 1)
		err := w.WriteSet("b/d/s", []fsx.NewFile{{Name: row.name, Perm: 0o600}})
		want := fileText(row.name, row.reason)
		if err == nil || err.Error() != want {
			t.Fatalf("%s: WriteSet = %v, want\n  %s", row.why, err, want)
		}
		// the reason is the one of CheckName, word for word
		if got := strings.TrimPrefix(err.Error(), fileText(row.name, "")); got != row.reason {
			t.Fatalf("%s: the writer's reason is %q, CheckName's is %q", row.why, got, row.reason)
		}
	}
}

func TestCheckNameAcceptsWhatTheWriterWritesAsAFinalName(t *testing.T) {
	for _, row := range acceptedNames {
		if err := fsx.CheckName(row.name); err != nil {
			t.Fatalf("%s: CheckName(%q) = %v, want nil", row.why, row.name, err)
		}
		for _, use := range pathUses {
			for _, pl := range placements {
				acceptedAt(t, use, pl, row.name)
			}
		}
	}
	for _, c := range allowedChars() {
		for _, name := range []string{string(rune(c)) + "x1", "x" + string(rune(c)) + "1", "x1" + string(rune(c)), string(rune(c))} {
			wantOK := name != "." && !strings.HasSuffix(name, ".")
			if err := fsx.CheckName(name); (err == nil) != wantOK {
				t.Fatalf("CheckName(%q) = %v, want ok=%v", name, err, wantOK)
			}
		}
	}
}

func TestCheckNameAtTheLimitOfLength(t *testing.T) {
	for n, ok := range map[int]bool{1: true, 254: true, 255: true, 256: false, 4096: false} {
		err := fsx.CheckName(rep("a", n))
		if (err == nil) != ok {
			t.Errorf("CheckName of %d bytes = %v, want ok=%v", n, err, ok)
		}
	}
}

func TestCheckNameOfAHostileNameIsPrintableASCII(t *testing.T) {
	for _, s := range append(append([]string{}, controlHostile...), printableBeyondASCII...) {
		for _, name := range []string{s, "a" + s, s + "a", "." + s} {
			err := fsx.CheckName(name)
			if !errors.Is(err, fsx.ErrInvalid) {
				t.Errorf("CheckName(%q) = %v, want ErrInvalid", name, err)
				continue
			}
			requirePrintableASCII(t, err.Error())
		}
	}
	if err := fsx.CheckName(""); !errors.Is(err, fsx.ErrInvalid) {
		t.Errorf("CheckName(\"\") = %v", err)
	}
}
