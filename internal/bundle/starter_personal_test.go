package bundle_test

import (
	"strings"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/bundle"
	"ritueel.id/ritueel/internal/wanted"
)

// The starter files of a person, `new --template personal`: the settings of a personal bundle, a root file with
// the placeholder fingerprint, and a file of further user IDs that holds none.

var personalNow = time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)

const goldenPersonalRoot = `# Your OpenPGP key. ritueel adopts the key you have; it makes no new primary key here.
version: 1
kind: openpgp
encryption: true                 # an encryption subkey on each day-to-day card
# revocation_reasons: [retired]  # more reasons to keep ready; compromised and superseded are always made
keys:
  # Replace the placeholder with the fingerprint of your key: 40 hexadecimal digits.
  # valid_until is the day the key expires: after today and at most 36 months from the day you apply.
  - {label: A, role: adopted, fingerprint: "0000000000000000000000000000000000000000", valid_until: "2028-11-26"}
`

const goldenPersonalUserIDs = `# The further user IDs of your key. The name and address of ritueel.yaml are always the first one.
# An entry adds a user ID. Write "retire: true" to retire one; a line that you delete retires nothing.
version: 1
user_ids: []
`

const goldenPersonalSettings = `# The settings of this bundle. A person writes this file; ritueel never changes it.
version: 1
kind: personal
person:
  name: Ada Example              # your name, as in your key; 1 to 64 characters
  address: ada@example.com       # your address; with the name it is the first user ID of your key
policy:
  stores: [openpgp-card, software]
  min_firmware: 5.7.0
  pin_policy: [once, always]
  require_name_constraints: true
  validity_months: 13
`

func TestThePersonalStarterIsReadAsMeantAndRefusedWhileThePlaceholderStands(t *testing.T) {
	files, err := bundle.Starter(bundle.StarterOptions{Template: bundle.TemplatePersonal, Now: personalNow})
	if err != nil {
		t.Fatal(err)
	}
	want := []starterWant{{"want/roots/openpgp.yaml", goldenPersonalRoot}, {"want/openpgp.yaml", goldenPersonalUserIDs}, {"ritueel.yaml", goldenPersonalSettings}}
	if len(files) != len(want) {
		t.Fatalf("%d files, want %d", len(files), len(want))
	}
	for i, f := range files {
		if f.Path != want[i].path || string(f.Data) != want[i].text || f.SHA256 != sha256hex(f.Data) || !isPlainASCII(f.Data) {
			t.Errorf("file %d: %s\n%s", i, f.Path, f.Data)
		}
	}
	// While the placeholder stands the reader refuses the root file, by name.
	if _, err := wanted.ParseRoot("openpgp", files[0].Data); err == nil || !strings.Contains(err.Error(), "replace the placeholder with the fingerprint of your key") {
		t.Errorf("the root file with the placeholder: %v", err)
	}
	// When the person has written a fingerprint, every file passes its reader and the files pass the check
	// across them, today and on the day before the key expires.
	text := strings.Replace(string(files[0].Data), wanted.PlaceholderFingerprint, "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678", 1)
	root, err := wanted.ParseRoot("openpgp", []byte(text))
	if err != nil {
		t.Fatal(err)
	}
	// The example person is refused by name too; with a person of their own the settings pass.
	if _, err := wanted.ParseSettings(wanted.SettingsPath, files[2].Data); err == nil || !strings.Contains(err.Error(), "replace the example person with your name and address") {
		t.Errorf("the settings with the example person: %v", err)
	}
	own := strings.Replace(strings.Replace(string(files[2].Data), "Ada Example", "Eve Example", 1), "ada@example.com", "eve@example.com", 1)
	settings, err := wanted.ParseSettings(wanted.SettingsPath, []byte(own))
	if err != nil || !settings.Personal || settings.Person.Name != "Eve Example" || settings.Person.Address != "eve@example.com" {
		t.Fatalf("%+v %v", settings, err)
	}
	ids, err := wanted.ParseUserIDs(files[1].Data)
	if err != nil || len(ids.Entries()) != 0 {
		t.Fatalf("%+v %v", ids, err)
	}
	for _, now := range []time.Time{personalNow, time.Date(2028, 11, 25, 23, 0, 0, 0, time.UTC)} {
		if err := wanted.CheckPersonal(settings, []*wanted.Root{root}, nil, nil, ids, now); err != nil {
			t.Errorf("at %v: %v", now, err)
		}
	}
	// The day follows the time that is given: a clock a year later gives a day a year later.
	later, err := bundle.Starter(bundle.StarterOptions{Template: bundle.TemplatePersonal, Now: personalNow.AddDate(1, 0, 0)})
	if err != nil || !strings.Contains(string(later[0].Data), `valid_until: "2029-11-26"`) {
		t.Errorf("a later clock: %v\n%s", err, later[0].Data)
	}
}

func TestTheStarterIsRefusedWhileEitherExampleStands(t *testing.T) {
	files, err := bundle.Starter(bundle.StarterOptions{Template: bundle.TemplatePersonal, Now: personalNow})
	if err != nil {
		t.Fatal(err)
	}
	// A real fingerprint with the example person, and the example fingerprint with a real person.
	if _, err := wanted.ParseRoot("openpgp", []byte(strings.Replace(string(files[0].Data), wanted.PlaceholderFingerprint, "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678", 1))); err != nil {
		t.Errorf("a real fingerprint: %v", err)
	}
	if _, err := wanted.ParseRoot("openpgp", []byte(strings.Replace(string(files[0].Data), wanted.PlaceholderFingerprint, wanted.ExampleFingerprint, 1))); err == nil || !strings.Contains(err.Error(), "the fingerprint of the examples") {
		t.Errorf("the example fingerprint: %v", err)
	}
}

func TestThePersonalStarterRefusesWhatItCannotMake(t *testing.T) {
	for name, opt := range map[string]bundle.StarterOptions{
		"no time":                  {Template: bundle.TemplatePersonal},
		"a test root":              {Template: bundle.TemplatePersonal, TestRoot: true, Now: personalNow},
		"a template that is not":   {Template: "cloud", Now: personalNow},
		"a time outside the years": {Template: bundle.TemplatePersonal, Now: time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)},
	} {
		if files, err := bundle.Starter(opt); err == nil || files != nil {
			t.Errorf("%s: %v, %v", name, files, err)
		}
	}
}
