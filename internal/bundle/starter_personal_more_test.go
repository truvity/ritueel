package bundle_test

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/bundle"
	"ritueel.id/ritueel/internal/wanted"
)

// The starter of a person: the day of its key follows the instant of the clock and nothing else, each file says
// what it is in a comment, the files are read back as the person will write them, and Create writes them once.

var starterDay = regexp.MustCompile(`valid_until: "([0-9]{4}-[0-9]{2}-[0-9]{2})"`)

func personalDayOf(t *testing.T, now time.Time) string {
	t.Helper()
	files, err := bundle.Starter(bundle.StarterOptions{Template: bundle.TemplatePersonal, Now: now})
	if err != nil {
		t.Fatalf("the clock %v: %v", now, err)
	}
	m := starterDay.FindSubmatch(files[0].Data)
	if m == nil {
		t.Fatalf("no day in the root file:\n%s", files[0].Data)
	}
	return string(m[1])
}

func TestTheDayOfTheStarterKeyIsTwentyFourMonthsFromTheInstantOfTheClock(t *testing.T) {
	for name, tc := range map[string]struct {
		now  time.Time
		want string
	}{
		"a normal day":                {time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC), "2028-11-27"},
		"a second before midnight":    {time.Date(2026, 11, 27, 23, 59, 59, 0, time.UTC), "2028-11-27"},
		"midnight":                    {time.Date(2026, 11, 28, 0, 0, 0, 0, time.UTC), "2028-11-28"},
		"the last day of a month":     {time.Date(2026, 11, 30, 12, 0, 0, 0, time.UTC), "2028-11-30"},
		"the last day of a leap year": {time.Date(2027, 2, 28, 12, 0, 0, 0, time.UTC), "2029-02-28"},
		"the leap day":                {time.Date(2028, 2, 29, 12, 0, 0, 0, time.UTC), "2030-02-28"},
		"the 29th of January":         {time.Date(2026, 1, 29, 12, 0, 0, 0, time.UTC), "2028-01-29"},
		"a zone far east":             {time.Date(2026, 11, 28, 9, 0, 0, 0, time.FixedZone("east", 14*3600)), "2028-11-27"},
		"a zone far west":             {time.Date(2026, 11, 27, 20, 0, 0, 0, time.FixedZone("west", -12*3600)), "2028-11-28"},
		"the first day of the years":  {time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC), "2002-01-01"},
		"the last year that works":    {time.Date(2103, 12, 31, 23, 59, 59, 0, time.UTC), "2105-12-31"},
	} {
		t.Run(name, func(t *testing.T) {
			if got := personalDayOf(t, tc.now); got != tc.want {
				t.Errorf("the day is %s, want %s", got, tc.want)
			}
		})
	}
}

func TestTheStarterIsTheSameForTheSameInstantAndSharesNothing(t *testing.T) {
	at := time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)
	first, err := bundle.Starter(bundle.StarterOptions{Template: bundle.TemplatePersonal, Now: at})
	if err != nil {
		t.Fatal(err)
	}
	for _, z := range []*time.Location{time.UTC, time.FixedZone("east", 14*3600), time.FixedZone("west", -12*3600)} {
		again, err := bundle.Starter(bundle.StarterOptions{Template: bundle.TemplatePersonal, Now: at.In(z)})
		if err != nil || len(again) != len(first) {
			t.Fatal(err)
		}
		for i := range first {
			if again[i].Path != first[i].Path || !bytes.Equal(again[i].Data, first[i].Data) || again[i].SHA256 != first[i].SHA256 {
				t.Errorf("%s differs in %v", first[i].Path, z)
			}
		}
	}
	// A change of what was returned is no change of the next call.
	want := string(first[0].Data)
	first[0].Data[0] ^= 0xff
	next, err := bundle.Starter(bundle.StarterOptions{Template: bundle.TemplatePersonal, Now: at})
	if err != nil || string(next[0].Data) != want {
		t.Errorf("the second call shares its bytes with the first: %v", err)
	}
	// The starter of a company is as it was, and has no part of a person.
	company, err := bundle.Starter(bundle.StarterOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range company {
		if strings.Contains(string(f.Data), "personal") && f.Path == wanted.SettingsPath || strings.Contains(string(f.Data), "adopted") {
			t.Errorf("a part of a person in the starter of a company: %s", f.Path)
		}
	}
}

func TestEachStarterFileOfAPersonSaysWhatItIsAndPassesItsReaderOnceEdited(t *testing.T) {
	files, err := bundle.Starter(bundle.StarterOptions{Template: bundle.TemplatePersonal, Now: personalNow})
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 3 {
		t.Fatalf("%d files", len(files))
	}
	for _, f := range files {
		text := string(f.Data)
		if !strings.HasPrefix(text, "# ") || !strings.HasSuffix(text, "\n") || strings.Contains(text, "\n\n") || strings.ContainsAny(text, "\r\t") || !isPlainASCII(f.Data) {
			t.Errorf("%s:\n%s", f.Path, text)
		}
		for i, line := range strings.Split(strings.TrimSuffix(text, "\n"), "\n") {
			if line != strings.TrimRight(line, " ") || len(line) > 140 {
				t.Errorf("%s line %d is too long or ends with a space: %q", f.Path, i+1, line)
			}
		}
	}
	// The root file says where the person writes the fingerprint and the day, and that the placeholder is one.
	root := string(files[0].Data)
	for _, w := range []string{"Replace the placeholder", "40 hexadecimal digits", "valid_until", "36 months"} {
		if !strings.Contains(root, w) {
			t.Errorf("the root file does not say %q", w)
		}
	}
	// Edited as the page tells, each file passes its reader: a fingerprint and a person of the person's own.
	edited := strings.Replace(root, wanted.PlaceholderFingerprint, "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678", 1)
	settings := strings.NewReplacer(wanted.ExamplePersonName, "Eve Example", wanted.ExamplePersonAddress, "eve@example.com").Replace(string(files[2].Data))
	s, err := wanted.ParseSettings(wanted.SettingsPath, []byte(settings))
	if err != nil {
		t.Fatal(err)
	}
	r, err := wanted.ParseRoot("openpgp", []byte(edited))
	if err != nil {
		t.Fatal(err)
	}
	u, err := wanted.ParseUserIDs(files[1].Data)
	if err != nil {
		t.Fatal(err)
	}
	// Every day from the clock to 36 months after it keeps the key valid; the day itself and the day after the
	// 36th month do not.
	for _, tc := range []struct {
		now time.Time
		ok  bool
	}{
		{personalNow, true},
		{time.Date(2028, 11, 25, 23, 59, 59, 0, time.UTC), true}, // a second before the key ends
		{time.Date(2028, 11, 26, 0, 0, 0, 0, time.UTC), false},
	} {
		err := wanted.CheckPersonal(s, []*wanted.Root{r}, nil, nil, u, tc.now)
		if tc.ok != (err == nil) {
			t.Errorf("at %v: %v", tc.now, err)
		}
	}
	// The same file with the placeholder, and the same with the example person, is refused by name, in every case
	// of the letters of the example.
	if _, err := wanted.ParseRoot("openpgp", files[0].Data); err == nil || !strings.Contains(err.Error(), "placeholder") {
		t.Errorf("the placeholder: %v", err)
	}
	for _, text := range []string{string(files[2].Data), strings.NewReplacer("Ada Example", "ADA EXAMPLE", "ada@example.com", "ADA@EXAMPLE.COM").Replace(string(files[2].Data))} {
		if _, err := wanted.ParseSettings(wanted.SettingsPath, []byte(text)); err == nil || !strings.Contains(err.Error(), "example person") {
			t.Errorf("the example person: %v", err)
		}
	}
}

func TestCreateOfThePersonalStarterWritesItOnceAndNeverAClockThatFails(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ada")
	files, err := bundle.Create(dir, bundle.StarterOptions{Template: bundle.TemplatePersonal, Now: personalNow})
	if err != nil || len(files) != 3 {
		t.Fatalf("%v %v", files, err)
	}
	for _, f := range files {
		got, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(f.Path)))
		if err != nil || !bytes.Equal(got, f.Data) {
			t.Errorf("%s: %v", f.Path, err)
		}
	}
	before := listFiles(t, dir)
	_, err = bundle.Create(dir, bundle.StarterOptions{Template: bundle.TemplatePersonal, Now: personalNow.AddDate(1, 0, 0)})
	var ce *bundle.CreateError
	if !errors.As(err, &ce) || ce.Made {
		t.Fatalf("the second call: %v", err)
	}
	for i, got := range listFiles(t, dir) {
		if got != before[i] {
			t.Errorf("the second call changed %s", got)
		}
	}
	// A clock that gives no starter makes no folder.
	for name, opt := range map[string]bundle.StarterOptions{
		"no time":           {Template: bundle.TemplatePersonal},
		"a time too late":   {Template: bundle.TemplatePersonal, Now: time.Date(2104, 3, 1, 0, 0, 0, 0, time.UTC)},
		"a time beyond":     {Template: bundle.TemplatePersonal, Now: time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC)},
		"a template at all": {Template: "personal ", Now: personalNow},
	} {
		other := filepath.Join(t.TempDir(), "ada")
		_, err := bundle.Create(other, opt)
		if err == nil {
			t.Errorf("%s: Create accepts it", name)
			continue
		}
		if _, serr := os.Lstat(other); !os.IsNotExist(serr) {
			t.Errorf("%s: the folder exists", name)
		}
		if !errors.As(err, &ce) || ce.Made || len(ce.Written) != 0 {
			t.Errorf("%s: %v", name, err)
		}
	}
}
