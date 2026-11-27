package wanted_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/wanted"
)

// The fuzz targets read bytes in memory only: they start no program and touch no file. Run in the ordinary way
// they run their seeds; `go test -fuzz` mutates them. Each checks that a reader never panics, returns exactly one
// of a value and an error, and that a value holds the bytes it was given and their digest, and an error is a
// *wanted.Error whose text is printable ASCII.

// seedTexts are the files of the tests: every accepted file and every file that strict YAML refuses.
func seedTexts() []string {
	seeds := []string{
		goodSettings, goodPersonal, goodX509Delegation, goodOpenPGPDelegation, goodSSHDelegation, goodRoot, "", "---\n", "{}", "[]",
		personalOpenPGP, personalSign, personalPerson, "version: 1\nuser_ids:\n  - {name: Ada Example, address: ada@example.org, retire: true}\n",
		goodSettings + "keyring:\n  license: CC0-1.0\naws_kms:\n  account: \"111122223333\"\n  region: eu-west-1\n  replica_region: eu-central-1\n  admin_role: arn:aws:iam::111122223333:role/a\n  ceremony_role: arn:aws:iam::111122223333:role/b\n",
		"x: &a [1]\ny: *a\n", "<<: {a: 1}\n", "? a\n: b\n", "a: !!str b\n", "%YAML 1.2\n---\na: 1\n", "a: 1\n...\n---\nb: 2\n",
		"\ufeffversion: 1\n", "version: 1\r\n", "version:\t1\n", "version: 1\n# \u202e\n", "a: \xff\n", strings.Repeat("[", 300), "x: " + strings.Repeat("[", 300) + "\n",
	}
	for _, r := range strictRows() {
		seeds = append(seeds, r.text)
	}
	return seeds
}

// checkResult holds what every reader must hold of its result.
func checkResult(t *testing.T, name string, data []byte, valid bool, file wanted.File, err error) {
	t.Helper()
	switch {
	case valid && err != nil:
		t.Fatalf("%s: a value beside the error %v", name, err)
	case !valid && err == nil:
		t.Fatalf("%s: neither a value nor an error", name)
	case err != nil:
		var e *wanted.Error
		if !errors.As(err, &e) {
			t.Fatalf("%s: the error is %T: %v", name, err, err)
		}
		if !printable(err.Error()) || e.Msg == "" || e.Line < 0 {
			t.Fatalf("%s: the error is not printable ASCII, has no message or a negative line: %q line %d", name, err.Error(), e.Line)
		}
		if e.Unwrap() != nil {
			t.Fatalf("%s: the fault of a text wraps a cause: %v", name, e.Unwrap())
		}
		if len(data) > wanted.MaxBytes && e.Line != 0 {
			t.Fatalf("%s: a file over the limit is refused with a line %d", name, e.Line)
		}
	default:
		if !bytes.Equal(file.Data, data) || file.SHA256 != sha256hex(data) {
			t.Fatalf("%s: the bytes or the digest of the value are not the input's", name)
		}
		if len(data) > wanted.MaxBytes {
			t.Fatalf("%s: a file over the limit is accepted", name)
		}
		if len(data) > 0 {
			before := data[0]
			file.Data[0] ^= 0xff
			if data[0] != before {
				t.Fatalf("%s: the value shares memory with the input", name)
			}
			file.Data[0] ^= 0xff
		}
	}
}

func FuzzParseSettings(f *testing.F) {
	for _, s := range seedTexts() {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		s, err := wanted.ParseSettings(settingsPath, data)
		var file wanted.File
		if s != nil {
			file = s.File
			if !s.Valid() || s.Version != 1 || !s.Policy.RequireNameConstraints || s.Policy.ValidityMonths < 1 || len(s.Policy.Stores) == 0 || len(s.Policy.PINPolicy) == 0 {
				t.Fatalf("a value that breaks what the reader promises: %+v", s)
			}
			if s.Personal == (s.Person == nil) || s.Personal != (s.Name == "" && s.ReleaseAddress == "") {
				t.Fatalf("a value that is neither company nor personal: %+v", s)
			}
			if !s.Personal && (len(s.Name) == 0 || len(s.Name) > wanted.MaxNameLen || strings.HasPrefix(s.Name, " ") || strings.HasSuffix(s.Name, " ")) {
				t.Fatalf("a name that the page refuses: %q", s.Name)
			}
			// What was read is read again from the same bytes: the digest and the members are the same.
			again, err2 := wanted.ParseSettings(settingsPath, data)
			if err2 != nil || again.File.SHA256 != s.File.SHA256 || !equalSettings(s, again) {
				t.Fatalf("a second reading differs: %v", err2)
			}
		}
		checkResult(t, "settings", data, s != nil, file, err)
	})
}

func FuzzParseDelegation(f *testing.F) {
	for _, s := range seedTexts() {
		f.Add([]byte(s))
	}
	settings := mustSettings(f, goodSettings)
	f.Fuzz(func(t *testing.T, data []byte) {
		d, err := wanted.ParseDelegation("example", data, settings)
		var file wanted.File
		if d != nil {
			file = d.File
			if !d.Valid() || d.Name != "example" || wanted.ValidName(d.Root) != nil {
				t.Fatalf("a value that breaks what the reader promises: %+v", d)
			}
			switch d.Type {
			case wanted.TypeX509Intermediate:
				if d.Capability != "" || d.Use != "" || len(d.PermittedURIHosts)+len(d.PermittedDNSNames) == 0 {
					t.Fatalf("an x509 delegation that breaks its rules: %+v", d)
				}
			case wanted.TypeOpenPGPSubkey:
				if d.Capability == "" || d.Use != "" || len(d.PermittedURIHosts)+len(d.PermittedDNSNames) != 0 {
					t.Fatalf("an openpgp delegation that breaks its rules: %+v", d)
				}
			case wanted.TypeSSHCAKey:
				if d.Use == "" || d.Capability != "" || len(d.PermittedURIHosts)+len(d.PermittedDNSNames) != 0 {
					t.Fatalf("an ssh delegation that breaks its rules: %+v", d)
				}
			default:
				t.Fatalf("a type that the page does not have: %q", d.Type)
			}
			for acct, arn := range d.KMSReadRoles {
				if len(acct) != 12 || !strings.Contains(arn, ":iam::"+acct+":role/") {
					t.Fatalf("a role outside its account: %s %s", acct, arn)
				}
			}
		}
		checkResult(t, "delegation", data, d != nil, file, err)
	})
}

func FuzzParseRoot(f *testing.F) {
	for _, s := range seedTexts() {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		r, err := wanted.ParseRoot("x509", data)
		var file wanted.File
		if r != nil {
			file = r.File
			if !r.Valid() || (r.Kind != wanted.RootX509 && r.Kind != wanted.RootOpenPGP && r.Kind != wanted.RootSSH) {
				t.Fatalf("a value that breaks what the reader promises: %+v", r)
			}
			keys := r.Keys()
			if len(keys) > wanted.MaxKeys || (len(keys) > 0 && r.Kind != wanted.RootOpenPGP) {
				t.Fatalf("keys that break what the reader promises: %+v", keys)
			}
			for _, k := range keys {
				if k.Role != wanted.RoleAdopted || len(k.Fingerprint) != wanted.FingerprintLen || k.Fingerprint == wanted.PlaceholderFingerprint || k.ValidUntil.IsZero() || k.Fingerprint != strings.ToLower(k.Fingerprint) {
					t.Fatalf("a key that breaks what the reader promises: %+v", k)
				}
			}
		}
		checkResult(t, "root", data, r != nil, file, err)
	})
}

func FuzzParseUserIDs(f *testing.F) {
	for _, s := range seedTexts() {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		u, err := wanted.ParseUserIDs(data)
		var file wanted.File
		if u != nil {
			file = u.File
			entries := u.Entries()
			active := 0
			for _, e := range entries {
				if !e.Retire {
					active++
				}
				if strings.Count(e.Address, "@") != 1 || strings.ContainsAny(e.Name+e.Address, "<>\n") || !printable(e.Name+e.Address) {
					t.Fatalf("a user ID that breaks what the reader promises: %+v", e)
				}
			}
			if len(entries) > wanted.MaxUserIDs || active > wanted.MaxActiveUserIDs {
				t.Fatalf("too many user IDs: %d, %d active", len(entries), active)
			}
		}
		checkResult(t, "user ids", data, u != nil, file, err)
	})
}
