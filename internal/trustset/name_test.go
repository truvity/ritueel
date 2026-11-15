package trustset_test

import (
	"math"
	"regexp"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/fsx"
	"ritueel.id/ritueel/internal/strictjson"
	"ritueel.id/ritueel/internal/trustset"
)

// bundleSpelling is the spelling that internal/bundle reads for the name of a trust set.
var bundleSpelling = regexp.MustCompile(`^[1-9][0-9]*-[0-9a-f]{8}$`)

func TestSetName(t *testing.T) {
	digest := "3fa9c1d2" + strings.Repeat("0", 56)
	for _, c := range []struct {
		seq  int64
		want string
	}{
		{1, "1-3fa9c1d2"},
		{13, "13-3fa9c1d2"},
		{100, "100-3fa9c1d2"},
		{strictjson.MaxSafeInt, "9007199254740991-3fa9c1d2"},
	} {
		got, err := trustset.SetName(c.seq, digest)
		if err != nil {
			t.Errorf("SetName(%d): %v", c.seq, err)
			continue
		}
		if got != c.want {
			t.Errorf("SetName(%d) = %q, want %q", c.seq, got, c.want)
		}
		if !bundleSpelling.MatchString(got) {
			t.Errorf("%q is not the spelling that internal/bundle reads", got)
		}
		if err := fsx.CheckName(got); err != nil {
			t.Errorf("fsx.CheckName(%q): %v", got, err)
		}
	}
}

// Only the first eight characters of the digest are used, and the first eight, not any others.
func TestSetNameTakesTheFirstEightCharacters(t *testing.T) {
	d := "0123456789abcdef" + strings.Repeat("f", 48)
	got, err := trustset.SetName(5, d)
	if err != nil {
		t.Fatal(err)
	}
	if got != "5-01234567" {
		t.Errorf("SetName = %q, want 5-01234567", got)
	}
	// The same first eight characters give one name, the rest does not matter.
	other, err := trustset.SetName(5, d[:8]+strings.Repeat("0", 56))
	if err != nil || other != got {
		t.Errorf("SetName with another tail = %q, %v; want %q", other, err, got)
	}
}

func TestSetNameRefusals(t *testing.T) {
	good := strings.Repeat("a", 64)
	for _, c := range []struct {
		name   string
		seq    int64
		digest string
	}{
		{"sequence 0", 0, good},
		{"sequence -1", -1, good},
		{"sequence min int64", math.MinInt64, good},
		{"sequence above the safe range", strictjson.MaxSafeInt + 1, good},
		{"sequence max int64", math.MaxInt64, good},
		{"digest of 63 digits", 1, good[:63]},
		{"digest of 65 digits", 1, good + "a"},
		{"empty digest", 1, ""},
		{"digest in upper case", 1, strings.Repeat("A", 64)},
		{"digest with one upper-case digit", 1, good[:10] + "F" + good[11:]},
		{"digest with a non-hex character", 1, good[:10] + "g" + good[11:]},
		{"digest with 0x", 1, "0x" + good[:62]},
		{"digest with a space", 1, good[:63] + " "},
		{"digest with a newline", 1, good[:63] + "\n"},
		{"digest with a NUL", 1, good[:63] + "\x00"},
		{"digest of 64 bytes that are not ASCII", 1, strings.Repeat("\xc3", 64)},
		{"digest of 64 characters, two of them multi-byte", 1, good[:62] + "\u00e9"},
		{"huge digest", 1, strings.Repeat("a", 1<<20)},
	} {
		got, err := trustset.SetName(c.seq, c.digest)
		if err == nil {
			t.Errorf("%s: SetName = %q, want an error", c.name, got)
			continue
		}
		if got != "" {
			t.Errorf("%s: a name %q comes with the error", c.name, got)
		}
		wantParams(t, err)
	}
}

// The name has no leading zero in its number, and a number is plain decimal.
func TestSetNameNumberIsPlainDecimal(t *testing.T) {
	for seq := int64(1); seq < 1200; seq += 7 {
		got, err := trustset.SetName(seq, strings.Repeat("c", 64))
		if err != nil {
			t.Fatal(err)
		}
		if !bundleSpelling.MatchString(got) {
			t.Fatalf("%q does not match %s", got, bundleSpelling)
		}
	}
}
