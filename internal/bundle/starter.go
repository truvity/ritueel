package bundle

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"ritueel.id/ritueel/internal/pki"
	"ritueel.id/ritueel/internal/wanted"
)

// TemplatePersonal is the template of the starter files of a person: the settings of a personal bundle, an
// OpenPGP root file for the key that the person adopts, and an empty file of further user IDs. The other
// template names of the page are proposed and not built.
const TemplatePersonal = "personal"

// StarterOptions are the choices of [Starter] and [Create].
type StarterOptions struct {
	// TestRoot marks the roots of the new bundle as test roots (record 0005, rule 26): each wanted root file
	// holds "test: true", and the policy allows the software store for the requests of a test bundle.
	TestRoot bool
	// Template names a family of starter files. "" is the company bundle with an X.509 and an OpenPGP root;
	// [TemplatePersonal] is the bundle of a person. Any other name is an error. A personal bundle is no test
	// bundle: TestRoot with it is an error.
	Template string
	// Now is the time that the personal starter takes the day its key expires from. It is required for
	// [TemplatePersonal], and read from nothing else.
	Now time.Time
}

// The paths of the starter files in a new bundle.
const (
	starterX509Path    = wanted.RootsDir + "/x509.yaml"
	starterOpenPGPPath = wanted.RootsDir + "/openpgp.yaml"
)

// settingsText is the starter ritueel.yaml, with the stores line left to fill. The name and the address are
// examples that a holder changes before the first apply (the reserved example.org, never a real address).
const settingsText = `# The settings of this bundle. A person writes this file; ritueel never changes it.
version: 1
name: Example                    # in the names of the root keys; 1 to 45 characters
release_address: release@example.org
policy:
  stores: [%s]
  min_firmware: 5.7.0
  pin_policy: [once, always]
  require_name_constraints: true
  validity_months: 13
`

// rootText is a starter wanted root file, with the kind and the comment to fill. Its keys are made by the
// first apply.
const rootText = `# One %s root. Its keys are made by the first apply.
version: 1
kind: %s
test: %s
`

// testMarkComment follows "test: true" in the root files of a test bundle.
const testMarkComment = "  # set at birth; a real root never becomes a test root"

// Starter returns the starter wanted files of a new bundle in the order they are written, with ritueel.yaml
// last, so that a folder that a stop leaves half made holds no ritueel.yaml and is taken for no bundle. Each
// file is read back by package wanted before it is returned, and a file that its own reader refuses, or that
// the reader reads as something other than was meant, is an error: a fault of this program, found before a
// byte is written. The text is plain ASCII with LF line ends and a final LF.
func Starter(opt StarterOptions) ([]wanted.File, error) {
	switch opt.Template {
	case "":
	case TemplatePersonal:
		return personalStarter(opt)
	default:
		return nil, errors.New("bundle: the starter template is not built")
	}
	stores := "piv, openpgp-card, aws-kms"
	test := "false"
	if opt.TestRoot {
		stores += ", software"
		test = "true"
	}
	var files []wanted.File
	for _, r := range []struct {
		path, label string
		kind        wanted.RootKind
	}{
		{starterX509Path, "X.509", wanted.RootX509},
		{starterOpenPGPPath, "OpenPGP", wanted.RootOpenPGP},
	} {
		text := fmt.Sprintf(rootText, r.label, r.kind, test)
		if opt.TestRoot {
			text = replaceLast(text, "test: true\n", "test: true"+testMarkComment+"\n")
		}
		name := nameOf(r.path)
		got, err := wanted.ParseRoot(name, []byte(text))
		if err != nil {
			return nil, fmt.Errorf("bundle: the starter file %s does not pass its own reader: %w", r.path, err)
		}
		if got.Kind != r.kind || got.Test != opt.TestRoot || got.File.Path != r.path || !bytes.Equal(got.File.Data, []byte(text)) {
			return nil, fmt.Errorf("bundle: the starter file %s is not read back as it was made", r.path)
		}
		files = append(files, got.File)
	}
	text := fmt.Sprintf(settingsText, stores)
	got, err := wanted.ParseSettings(wanted.SettingsPath, []byte(text))
	if err != nil {
		return nil, fmt.Errorf("bundle: the starter file %s does not pass its own reader: %w", wanted.SettingsPath, err)
	}
	if got.Personal || got.Name != "Example" || got.ReleaseAddress != "release@example.org" ||
		slices.Contains(got.Policy.Stores, "software") != opt.TestRoot || !bytes.Equal(got.File.Data, []byte(text)) {
		return nil, fmt.Errorf("bundle: the starter file %s is not read back as it was made", wanted.SettingsPath)
	}
	return append(files, got.File), nil
}

// nameOf is the name of an object from the path of its file: the last element without ".yaml".
func nameOf(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			path = path[i+1:]
			break
		}
	}
	return path[:len(path)-len(".yaml")]
}

// replaceLast replaces the last occurrence of old in s with repl.
func replaceLast(s, old, repl string) string {
	i := strings.LastIndex(s, old)
	if i < 0 {
		return s
	}
	return s[:i] + repl + s[i+len(old):]
}

// The starter files of a person. The fingerprint is a placeholder that the readers refuse by name until the
// person writes the fingerprint of their own key, and the day is a made-up one. The comments are for the person
// who edits the files.
const (
	personalSettingsText = `# The settings of this bundle. A person writes this file; ritueel never changes it.
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
	personalRootText = `# Your OpenPGP key. ritueel adopts the key you have; it makes no new primary key here.
version: 1
kind: openpgp
encryption: true                 # an encryption subkey on each day-to-day card
# revocation_reasons: [retired]  # more reasons to keep ready; compromised and superseded are always made
keys:
  # Replace the placeholder with the fingerprint of your key: 40 hexadecimal digits.
  # valid_until is the day the key expires: after today and at most 36 months from the day you apply.
  - {label: A, role: adopted, fingerprint: "%s", valid_until: "%s"}
`
	personalUserIDsText = `# The further user IDs of your key. The name and address of ritueel.yaml are always the first one.
# An entry adds a user ID. Write "retire: true" to retire one; a line that you delete retires nothing.
version: 1
user_ids: []
`
	// personalMonths is how far from now the starter puts the day the key expires, in calendar months.
	personalMonths = 24
	// The read-back of the starter puts a stand-in fingerprint and a stand-in person in the place of the
	// placeholder and of the example person, which the readers refuse by name. The readers have no way to let
	// them through: the starter is read back with the text changed, and the files that are written are not.
	standInFingerprint = "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678"
	standInName        = "Eve Example"
	standInAddress     = "eve@example.com"
)

// personalStarter returns the starter files of a person: want/roots/openpgp.yaml, want/openpgp.yaml and
// ritueel.yaml last. The root file holds the placeholder fingerprint and the settings hold the example person,
// which their readers refuse by name until the person writes their own. Each file is read back, the root with a
// stand-in fingerprint and the settings with a stand-in person in their place, and the three are judged against
// each other, so that they pass once the person has replaced both.
func personalStarter(opt StarterOptions) ([]wanted.File, error) {
	if opt.TestRoot {
		return nil, errors.New("bundle: a personal bundle has no test root")
	}
	if opt.Now.IsZero() {
		return nil, errors.New("bundle: the personal starter needs the time")
	}
	end, err := pki.AddMonths(opt.Now, personalMonths)
	if err != nil {
		return nil, fmt.Errorf("bundle: the day of the expiry of the starter key: %w", err)
	}
	day := end.Format(time.DateOnly)
	rootText := fmt.Sprintf(personalRootText, wanted.PlaceholderFingerprint, day)
	_, err = wanted.ParseRoot(nameOf(starterOpenPGPPath), []byte(rootText))
	if err == nil {
		return nil, fmt.Errorf("bundle: the starter file %s is accepted with the placeholder", starterOpenPGPPath)
	}
	if !strings.Contains(err.Error(), "placeholder") {
		return nil, fmt.Errorf("bundle: the starter file %s is not refused for its placeholder: %w", starterOpenPGPPath, err)
	}
	standIn := fmt.Sprintf(personalRootText, standInFingerprint, day)
	root, err := wanted.ParseRoot(nameOf(starterOpenPGPPath), []byte(standIn))
	if err != nil {
		return nil, fmt.Errorf("bundle: the starter file %s does not pass its own reader: %w", starterOpenPGPPath, err)
	}
	keys := root.Keys()
	if enc, set := root.Encryption(); !enc || !set || len(keys) != 1 || keys[0].Fingerprint != standInFingerprint || keys[0].ValidUntil.String() != day {
		return nil, fmt.Errorf("bundle: the starter file %s is not read back as it was made", starterOpenPGPPath)
	}
	ids, err := wanted.ParseUserIDs([]byte(personalUserIDsText))
	if err != nil {
		return nil, fmt.Errorf("bundle: the starter file %s does not pass its own reader: %w", wanted.UserIDsPath, err)
	}
	if len(ids.Entries()) != 0 || ids.File.Path != wanted.UserIDsPath {
		return nil, fmt.Errorf("bundle: the starter file %s is not read back as it was made", wanted.UserIDsPath)
	}
	_, err = wanted.ParseSettings(wanted.SettingsPath, []byte(personalSettingsText))
	if err == nil {
		return nil, fmt.Errorf("bundle: the starter file %s is accepted with the example person", wanted.SettingsPath)
	}
	if !strings.Contains(err.Error(), "example person") {
		return nil, fmt.Errorf("bundle: the starter file %s is not refused for its example person: %w", wanted.SettingsPath, err)
	}
	person := strings.Replace(strings.Replace(personalSettingsText, wanted.ExamplePersonName, standInName, 1), wanted.ExamplePersonAddress, standInAddress, 1)
	settings, err := wanted.ParseSettings(wanted.SettingsPath, []byte(person))
	if err != nil {
		return nil, fmt.Errorf("bundle: the starter file %s does not pass its own reader: %w", wanted.SettingsPath, err)
	}
	if !settings.Personal || settings.Person == nil || settings.Person.Name != standInName || settings.Person.Address != standInAddress {
		return nil, fmt.Errorf("bundle: the starter file %s is not read back as it was made", wanted.SettingsPath)
	}
	if err := wanted.CheckPersonal(settings, []*wanted.Root{root}, nil, nil, ids, opt.Now); err != nil {
		return nil, fmt.Errorf("bundle: the starter files do not pass the check across them: %w", err)
	}
	file := func(path, text string) wanted.File {
		sum := sha256.Sum256([]byte(text))
		return wanted.File{Path: path, Data: []byte(text), SHA256: hex.EncodeToString(sum[:])}
	}
	return []wanted.File{file(starterOpenPGPPath, rootText), file(wanted.UserIDsPath, personalUserIDsText), file(wanted.SettingsPath, personalSettingsText)}, nil
}
