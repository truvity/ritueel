package bundle

import (
	"bytes"
	"fmt"
	"slices"
	"strings"

	"ritueel.id/ritueel/internal/wanted"
)

// StarterOptions are the choices of [Starter] and [Create].
type StarterOptions struct {
	// TestRoot marks the roots of the new bundle as test roots (record 0005, rule 26): each wanted root file
	// holds "test: true", and the policy allows the software store for the requests of a test bundle.
	TestRoot bool
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
