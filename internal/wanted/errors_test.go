package wanted_test

import (
	"errors"
	"io/fs"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/wanted"
)

func TestTheTextOfAnError(t *testing.T) {
	for _, tc := range []struct {
		e    wanted.Error
		want string
	}{
		{wanted.Error{Path: "ritueel.yaml", Line: 3, Msg: "name is wrong"}, "ritueel.yaml:3: name is wrong"},
		{wanted.Error{Path: "ritueel.yaml", Line: 0, Msg: "no document"}, "ritueel.yaml: no document"},
		{wanted.Error{Path: "a\x00b\n.yaml", Line: 2, Msg: "m\u00e9"}, `a\u0000b\u000a.yaml:2: m\u00e9`},
		{wanted.Error{Path: "\u202e", Msg: "\u202e\x7f"}, `\u202e: \u202e\u007f`},
	} {
		if got := tc.e.Error(); got != tc.want {
			t.Errorf("Error() = %q, want %q", got, tc.want)
		}
		if !printable(tc.e.Error()) {
			t.Errorf("not printable: %q", tc.e.Error())
		}
	}
}

func TestANilErrorDoesNotPanic(t *testing.T) {
	var e *wanted.Error
	if e.Error() == "" || !printable(e.Error()) {
		t.Errorf("Error() of nil is %q", e.Error())
	}
	if e.Unwrap() != nil {
		t.Error("Unwrap() of nil is not nil")
	}
}

func TestOnlyTheFailureOfAReadHasACause(t *testing.T) {
	_, fsys := bundleDir(t, nil)
	_, err := wanted.LoadSettings(fsys)
	var e *wanted.Error
	if !errors.As(err, &e) || !errors.Is(err, fs.ErrNotExist) || e.Unwrap() == nil {
		t.Errorf("a missing file: %v", err)
	}
	_, err = wanted.ParseSettings(settingsPath, []byte(""))
	if !errors.As(err, &e) || e.Unwrap() != nil || errors.Is(err, fs.ErrNotExist) {
		t.Errorf("a fault of the text: %v", err)
	}
}

func TestValidName(t *testing.T) {
	for _, ok := range []string{"a", "0", "a-", "a--b", "acme-tls", "x509", "9-a", strings.Repeat("a", 63), "break-glass-x"} {
		if err := wanted.ValidName(ok); err != nil {
			t.Errorf("ValidName(%q) = %v", ok, err)
		}
	}
	for _, bad := range []string{"", strings.Repeat("a", 64), "-a", "-", "A", "aB", "a_b", "a.b", "a b", "a/b", "..", ".", ".rt-x", "a.yaml", "a.yml", "\u00e4", "a\x00", "a\n", "\u0430", "a\u200b", " a", "a "} {
		err := wanted.ValidName(bad)
		if err == nil {
			t.Errorf("ValidName(%q) is nil", bad)
			continue
		}
		if !printable(err.Error()) || strings.Contains(err.Error(), bad) && len(bad) > 3 {
			t.Errorf("ValidName(%q) says %q: fixed printable words only", bad, err.Error())
		}
	}
}

func TestTheConstantsAreTheOnesOfThePages(t *testing.T) {
	if wanted.Version != 1 || wanted.MaxBytes != 256<<10 || wanted.MaxDepth != 16 || wanted.MaxNodes != 10000 || wanted.MaxNameLen != 45 || wanted.MaxFiles != 1000 {
		t.Errorf("limits %d %d %d %d %d %d", wanted.Version, wanted.MaxBytes, wanted.MaxDepth, wanted.MaxNodes, wanted.MaxNameLen, wanted.MaxFiles)
	}
	if wanted.SettingsPath != "ritueel.yaml" || wanted.RootsDir != "want/roots" || wanted.DelegationsDir != "want/delegations" {
		t.Errorf("paths %q %q %q", wanted.SettingsPath, wanted.RootsDir, wanted.DelegationsDir)
	}
	if wanted.TypeX509Intermediate != "x509-intermediate" || wanted.TypeOpenPGPSubkey != "openpgp-subkey" || wanted.TypeSSHCAKey != "ssh-ca-key" {
		t.Error("the spellings of the types changed")
	}
}
