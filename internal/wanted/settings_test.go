package wanted_test

import (
	"reflect"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/wanted"
)

// ritueel.yaml: docs/reference/bundle.md, "ritueel.yaml" (the table, the schema and "Two rules the schema cannot
// state"), the decisions on the name, and record 0006, rule 5.

func TestACompanyBundleIsRead(t *testing.T) {
	s := mustSettings(t, goodSettings)
	want := wanted.Settings{
		Version: 1, Name: "Example", ReleaseAddress: "release@example.org",
		Policy: wanted.Policy{
			Stores: []string{"piv", "openpgp-card", "aws-kms"}, MinFirmware: "5.7.0", PINPolicy: []string{"once", "always"},
			RequireNameConstraints: true, ValidityMonths: 13,
		},
	}
	if !equalSettings(s, &want) {
		t.Errorf("settings %+v, want %+v", *s, want)
	}
	if s.Personal || s.Person != nil || s.KMS != nil || s.KeyringLicense != "" {
		t.Errorf("a company bundle holds %+v", s)
	}
}

// equalSettings compares the members that a reader fills, leaving the unexported flag out.
func equalSettings(a, b *wanted.Settings) bool {
	x, y := *a, *b
	x.File, y.File = wanted.File{}, wanted.File{}
	return x.Version == y.Version && x.Personal == y.Personal && x.Name == y.Name && x.ReleaseAddress == y.ReleaseAddress &&
		reflect.DeepEqual(x.Person, y.Person) && reflect.DeepEqual(x.Policy, y.Policy) && x.KeyringLicense == y.KeyringLicense && reflect.DeepEqual(x.KMS, y.KMS)
}

func TestAPersonalBundleIsRead(t *testing.T) {
	s := mustSettings(t, goodPersonal)
	if !s.Personal || s.Person == nil || s.Person.Name != "Example Person" || s.Person.Address != "person@example.org" {
		t.Errorf("person %+v, personal %v", s.Person, s.Personal)
	}
	if s.Name != "" || s.ReleaseAddress != "" {
		t.Errorf("a personal bundle holds a name %q or a release address %q", s.Name, s.ReleaseAddress)
	}
}

func TestEveryMemberOfTheSchemaIsRead(t *testing.T) {
	text := goodSettings + "keyring:\n  license: CC0-1.0\naws_kms:\n  account: \"111122223333\"\n  region: eu-west-1\n  replica_region: eu-central-1\n" +
		"  admin_role: arn:aws:iam::111122223333:role/example-admin\n  ceremony_role: arn:aws-cn:iam::111122223333:role/path/example-ceremony\n"
	s := mustSettings(t, text)
	if s.KeyringLicense != "CC0-1.0" {
		t.Errorf("license %q", s.KeyringLicense)
	}
	if s.KMS == nil || *s.KMS != (wanted.KMS{Account: "111122223333", Region: "eu-west-1", ReplicaRegion: "eu-central-1",
		AdminRole: "arn:aws:iam::111122223333:role/example-admin", CeremonyRole: "arn:aws-cn:iam::111122223333:role/path/example-ceremony"}) {
		t.Errorf("kms %+v", s.KMS)
	}
	// An empty keyring block is a keyring with no license.
	if s := mustSettings(t, goodSettings+"keyring: {}\n"); s.KeyringLicense != "" {
		t.Errorf("license %q", s.KeyringLicense)
	}
}

func TestEveryRequiredMemberMissingIsRefusedByName(t *testing.T) {
	for _, tc := range []struct{ name, drop, word string }{
		{"version", "version: 1\n", "version"},
		{"policy", "policy:\n  stores: [piv, openpgp-card, aws-kms]\n  min_firmware: 5.7.0\n  pin_policy: [once, always]\n  require_name_constraints: true\n  validity_months: 13\n", "policy"},
		{"name", "name: Example\n", "name"},
		{"release_address", "release_address: release@example.org\n", "release_address"},
		{"stores", "  stores: [piv, openpgp-card, aws-kms]\n", "policy.stores"},
		{"min_firmware", "  min_firmware: 5.7.0\n", "policy.min_firmware"},
		{"pin_policy", "  pin_policy: [once, always]\n", "policy.pin_policy"},
		{"require_name_constraints", "  require_name_constraints: true\n", "policy.require_name_constraints"},
		{"validity_months", "  validity_months: 13\n", "policy.validity_months"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_ = refuseSettings(t, replaceOnce(t, goodSettings, tc.drop, ""), -1, tc.word, "required")
		})
	}
	for _, tc := range []struct{ name, drop, word string }{
		{"person", "person:\n  name: Example Person\n  address: person@example.org\n", "person"},
		{"person.name", "  name: Example Person\n", "person.name"},
		{"person.address", "  address: person@example.org\n", "person.address"},
	} {
		t.Run("personal "+tc.name, func(t *testing.T) {
			_ = refuseSettings(t, replaceOnce(t, goodPersonal, tc.drop, ""), -1, tc.word)
		})
	}
	for _, drop := range []string{"account: \"111122223333\"\n", "region: eu-west-1\n", "replica_region: eu-central-1\n", "admin_role: arn:aws:iam::111122223333:role/a\n", "ceremony_role: arn:aws:iam::111122223333:role/b\n"} {
		kms := "aws_kms:\n  account: \"111122223333\"\n  region: eu-west-1\n  replica_region: eu-central-1\n  admin_role: arn:aws:iam::111122223333:role/a\n  ceremony_role: arn:aws:iam::111122223333:role/b\n"
		mustSettings(t, goodSettings+kms)
		member := strings.SplitN(drop, ":", 2)[0]
		t.Run("aws_kms "+member, func(t *testing.T) {
			_ = refuseSettings(t, goodSettings+replaceOnce(t, kms, "  "+drop, ""), -1, "aws_kms."+member, "required")
		})
	}
}

func TestEveryUnknownMemberIsRefusedByName(t *testing.T) {
	good := goodSettings
	kms := "aws_kms:\n  account: \"111122223333\"\n  region: eu-west-1\n  replica_region: eu-central-1\n  admin_role: arn:aws:iam::111122223333:role/a\n  ceremony_role: arn:aws:iam::111122223333:role/b\n"
	for name, tc := range map[string]struct{ text, ctx string }{
		"at the top":              {good + "extra: 1\n", ""},
		"keyservers":              {good + "keyservers: [keys.openpgp.org]\n", ""},
		"keyservers, the block":   {good + "keyservers:\n  - address: keys.openpgp.org\n", ""},
		"in policy":               {replaceOnce(t, good, "  validity_months: 13\n", "  validity_months: 13\n  extra: 1\n"), "policy: "},
		"in person":               {replaceOnce(t, goodPersonal, "  address: person@example.org\n", "  address: person@example.org\n  extra: x\n"), "person: "},
		"in keyring":              {good + "keyring:\n  license: CC0-1.0\n  extra: x\n", "keyring: "},
		"in keyring, alone":       {good + "keyring:\n  extra: x\n", "keyring: "},
		"in aws_kms":              {good + kms + "  extra: x\n", "aws_kms: "},
		"a member of a root file": {good + "keys: []\n", ""},
		"a name in another case":  {replaceOnce(t, good, "name:", "Name:"), ""},
		"a delegation member":     {good + "type: x509-intermediate\n", ""},
		"version spelled upper":   {replaceOnce(t, good, "version:", "VERSION:"), ""},
		"a name with a space":     {good + "release address: x\n", ""},
		"a quoted name":           {good + "\"extra\": 1\n", ""},
	} {
		t.Run(name, func(t *testing.T) { _ = refuseSettings(t, tc.text, -1, tc.ctx+"the member", "not known") })
	}
}

func TestTheKindOfABundle(t *testing.T) {
	// A company bundle has name and release_address and no person; a personal bundle the reverse.
	_ = refuseSettings(t, goodSettings+"person:\n  name: Example Person\n  address: person@example.org\n", 10, "person is only allowed with kind: personal")
	_ = refuseSettings(t, strings.Replace(goodPersonal, "kind: personal\n", "", 1), -1, "person is only allowed")
	_ = refuseSettings(t, goodPersonal+"name: Example\n", -1, "name is not allowed in a personal bundle")
	_ = refuseSettings(t, goodPersonal+"release_address: release@example.org\n", -1, "release_address is not allowed in a personal bundle")
	_ = refuseSettings(t, replaceOnce(t, goodPersonal, "person:\n  name: Example Person\n  address: person@example.org\n", ""), -1, "needs the member person")
	// kind has the one value personal.
	for _, k := range []string{"company", "Personal", "PERSONAL", "personal ", "", "true", "1", "personal-x", "[personal]"} {
		text := strings.Replace(goodPersonal, "kind: personal", "kind: "+quoteYAML(k), 1)
		t.Run("kind "+k, func(t *testing.T) { _ = refuseSettings(t, text, 2, "kind", "personal") })
	}
	_ = refuseSettings(t, strings.Replace(goodPersonal, "kind: personal", "kind: 1", 1), 2, "kind")
	_ = refuseSettings(t, strings.Replace(goodPersonal, "kind: personal", "kind: [personal]", 1), 2, "kind")
}

// quoteYAML writes s as a double-quoted YAML string, for the rows whose point is the value and not its spelling.
func quoteYAML(s string) string {
	return "\"" + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + "\""
}

func TestEveryEnumRefusesAWrongValueAWrongCaseAndARepeat(t *testing.T) {
	for _, tc := range []struct {
		name, old string
		prefix    string
		values    []string
	}{
		{"stores", "[piv, openpgp-card, aws-kms]", "policy.stores", []string{"piv", "openpgp-card", "aws-kms", "software"}},
		{"pin_policy", "[once, always]", "policy.pin_policy", []string{"never", "once", "always"}},
	} {
		for _, v := range tc.values {
			mustSettings(t, replaceOnce(t, goodSettings, tc.old, "["+v+"]"))
		}
		first := tc.values[0]
		for name, list := range map[string]string{
			"a wrong value":   "[" + first + ", tpm]",
			"upper case":      "[" + strings.ToUpper(first) + "]",
			"a capital":       "[" + strings.ToUpper(first[:1]) + first[1:] + "]",
			"a repeat":        "[" + first + ", " + first + "]",
			"a space":         "[\"" + first + " \"]",
			"an empty list":   "[]",
			"a scalar":        first,
			"a number":        "[1]",
			"a boolean":       "[true]",
			"a nested list":   "[[" + first + "]]",
			"a mapping entry": "[{a: b}]",
			"an empty entry":  "[\"\"]",
		} {
			t.Run(tc.name+" "+name, func(t *testing.T) {
				_ = refuseSettings(t, replaceOnce(t, goodSettings, tc.old, list), -1, tc.prefix)
			})
		}
	}
	// The messages say which entry.
	e := refuseSettings(t, replaceOnce(t, goodSettings, "[piv, openpgp-card, aws-kms]", "[piv, tpm]"), 5, "policy.stores entry 2", "one of piv, openpgp-card, aws-kms, software")
	if strings.Contains(e.Msg, "tpm") {
		t.Errorf("the message holds the value: %s", e.Msg)
	}
	_ = refuseSettings(t, replaceOnce(t, goodSettings, "[piv, openpgp-card, aws-kms]", "[piv, openpgp-card, piv]"), 5, "policy.stores entry 3", "repeats")
}

func TestTheNameOfACompanyBundle(t *testing.T) {
	good := func(name string) string {
		return replaceOnce(t, goodSettings, "name: Example", "name: "+quoteYAML(name))
	}
	for _, ok := range []string{"E", "Example", "Acme Corp", "a-b", "-", "A1 B2-C3", "9", strings.Repeat("a", 45), strings.Repeat("ab ", 15)[:44] + "x", "a - b"} {
		if s := mustSettings(t, good(ok)); s.Name != ok {
			t.Errorf("name %q read as %q", ok, s.Name)
		}
	}
	// Each value is the YAML text after "name: ".
	for name, bad := range map[string]struct{ yaml, words string }{
		"46 characters":        {quoteYAML(strings.Repeat("a", 46)), "1 to 45 characters"},
		"empty":                {`""`, "1 to 45 characters"},
		"a leading space":      {`" Example"`, "no space at the start or the end"},
		"a trailing space":     {`"Example "`, "no space at the start or the end"},
		"two spaces":           {`"Acme  Corp"`, "no two spaces in a row"},
		"a Cyrillic A":         {"\"\u0410cme\"", "ASCII letters"},
		"a Greek omicron":      {"\"Acme \u039f\"", "ASCII letters"},
		"an accent":            {"\"caf\u00e9\"", "ASCII letters"},
		"a full-width letter":  {"\"\uff21cme\"", "ASCII letters"},
		"a tab":                {`"Acme\tCorp"`, "ASCII letters"},
		"a line feed":          {`"Acme\nCorp"`, "ASCII letters"},
		"a block scalar":       {"|\n  Acme", "ASCII letters"},
		"an underscore":        {`"acme_corp"`, "ASCII letters"},
		"a period":             {`"acme.corp"`, "ASCII letters"},
		"an apostrophe":        {`"Acme's"`, "ASCII letters"},
		"a slash":              {`"acme/corp"`, "ASCII letters"},
		"a parenthesis":        {`"Acme (TEST ONLY)"`, "ASCII letters"},
		"a non-breaking space": {"\"Acme\u00a0Corp\"", "ASCII letters"},
		"a space and 46 chars": {quoteYAML("a " + strings.Repeat("b", 44)), "1 to 45 characters"},
		"a space and a tab":    {`"Acme \t"`, "ASCII letters"},
	} {
		t.Run(name, func(t *testing.T) {
			_ = refuseSettings(t, replaceOnce(t, goodSettings, "name: Example", "name: "+bad.yaml), 2, "name", bad.words)
		})
	}
	// A name is a string: a number or a boolean written plain is not one.
	for _, plain := range []string{"2024", "0x1F", "true", "1.5", "2024-01-01", "1_000"} {
		t.Run("plain "+plain, func(t *testing.T) {
			_ = refuseSettings(t, replaceOnce(t, goodSettings, "name: Example", "name: "+plain), 2, "name must be a string", "quotes")
		})
	}
	// ...and a number in quotes is a name.
	mustSettings(t, good("2024"))
	for _, other := range []string{"[Example]", "{a: b}"} {
		_ = refuseSettings(t, replaceOnce(t, goodSettings, "name: Example", "name: "+other), 2, "name must be a string")
	}
	// A name of 45 characters leaves room for " Root A (TEST ONLY)" in the 64 of a common name.
	if got := wanted.MaxNameLen + len(" Root A") + len(" (TEST ONLY)"); got > 64 {
		t.Errorf("a name of MaxNameLen characters makes a common name of %d characters", got)
	}
	if wanted.MaxNameLen != 45 {
		t.Errorf("MaxNameLen is %d, the decision is 45", wanted.MaxNameLen)
	}
}

func TestThePersonOfAPersonalBundle(t *testing.T) {
	good := func(name string) string {
		return replaceOnce(t, goodPersonal, "name: Example Person", "name: "+quoteYAML(name))
	}
	for _, ok := range []string{"A", "Example Person", "O'Neil-Smith Jr.", "Example Test 2", "9 lives", strings.Repeat("a", 64), "A. B.", "Example  Person "} {
		if s := mustSettings(t, good(ok)); s.Person.Name != ok {
			t.Errorf("name %q read as %q", ok, s.Person.Name)
		}
	}
	for name, bad := range map[string]string{
		"65 characters": strings.Repeat("a", 65), "empty": "", "a leading space": " Example", "a leading hyphen": "-Example", "a leading period": ".Example",
		"a leading apostrophe": "'Example", "a Cyrillic letter": "\u0410xample", "an accent": "Ren\u00e9", "a comma": "Example, Person", "an underscore": "Example_Person",
		"an at sign": "a@b", "a slash": "a/b", "a bracket": "a <b>",
	} {
		t.Run(name, func(t *testing.T) { _ = refuseSettings(t, good(bad), 4, "person.name") })
	}
	_ = refuseSettings(t, replaceOnce(t, goodPersonal, "name: Example Person", "name: 2024"), 4, "person.name must be a string")
	_ = refuseSettings(t, replaceOnce(t, goodPersonal, "person:\n  name: Example Person\n  address: person@example.org\n", "person: Example\n"), 3, "person must be a mapping")
}

func TestAddresses(t *testing.T) {
	local := func(n int) string { return strings.Repeat("a", n) + "@example.org" }
	for _, ok := range []string{"release@example.org", "a@b", "a.b+c@example.org", "a-b_c@example.org", "RELEASE@EXAMPLE.ORG", local(242), "a@example.org"} {
		if s := mustSettings(t, replaceOnce(t, goodSettings, "release@example.org", ok)); s.ReleaseAddress != ok {
			t.Errorf("release address %q read as %q", ok, s.ReleaseAddress)
		}
		if s := mustSettings(t, replaceOnce(t, goodPersonal, "person@example.org", ok)); s.Person.Address != ok {
			t.Errorf("person address %q read as %q", ok, s.Person.Address)
		}
	}
	if len(local(242)) != 254 {
		t.Fatalf("the long address has %d bytes", len(local(242)))
	}
	// Each value is the YAML text after the key.
	for name, bad := range map[string]string{
		"a name and an address":        `"Example Person <a@example.org>"`,
		"an address in angle brackets": `"<a@example.org>"`,
		"no domain":                    "a@",
		"no local part":                `"@example.org"`,
		"no at sign":                   "example.org",
		"two at signs":                 `"a@b@example.org"`,
		"a non-ASCII address":          "\"r\u00e9lease@example.org\"",
		"a non-ASCII domain":           "\"release@\u00e9xample.org\"",
		"a space":                      `"release @example.org"`,
		"a quoted local part":          `"\"a b\"@example.org"`,
		"a comment":                    `"a@example.org(note)"`,
		"255 bytes":                    local(243),
		"empty":                        `""`,
		"a group":                      `"g:a@example.org;"`,
		"a trailing line feed":         `"a@example.org\n"`,
		"two addresses":                `"a@example.org,b@example.org"`,
		"a tab":                        `"a@example.org\t"`,
		"a full-width at sign":         "\"a\uff20example.org\"",
	} {
		t.Run(name, func(t *testing.T) {
			_ = refuseSettings(t, replaceOnce(t, goodSettings, "release_address: release@example.org", "release_address: "+bad), 3, "release_address")
			_ = refuseSettings(t, replaceOnce(t, goodPersonal, "address: person@example.org", "address: "+bad), 5, "person.address")
		})
	}
	_ = refuseSettings(t, replaceOnce(t, goodSettings, "release@example.org", "42"), 3, "release_address must be a string")
	_ = refuseSettings(t, replaceOnce(t, goodPersonal, "person@example.org", "42"), 5, "person.address must be a string")
}

func TestThePolicy(t *testing.T) {
	// min_firmware is three numbers of up to nine digits, joined by periods, as handoff.New takes it.
	for _, ok := range []string{"5.7.0", "5.10.0", "05.7.0", "0.0.0", "999999999.999999999.999999999", "5.7.100"} {
		if s := mustSettings(t, replaceOnce(t, goodSettings, "5.7.0", quoteYAML(ok))); s.Policy.MinFirmware != ok {
			t.Errorf("firmware %q read as %q", ok, s.Policy.MinFirmware)
		}
	}
	for _, bad := range []string{"5.7", "5.7.0.1", "5.7.x", "1234567890.0.0", "5", "", " 5.7.0", "5.7.0 ", "-5.7.0", "5..0", "5.7.", "v5.7.0", "5,7,0", "\\u0665.7.0"} {
		t.Run("min_firmware "+bad, func(t *testing.T) {
			_ = refuseSettings(t, replaceOnce(t, goodSettings, "5.7.0", quoteYAML(bad)), 6, "policy.min_firmware")
		})
	}
	// Written plain, 5.7 is a number and 5.7.0 is a string.
	_ = refuseSettings(t, replaceOnce(t, goodSettings, "5.7.0", "5.7"), 6, "policy.min_firmware must be a string")
	_ = refuseSettings(t, replaceOnce(t, goodSettings, "5.7.0", "5"), 6, "policy.min_firmware must be a string")
	mustSettings(t, replaceOnce(t, goodSettings, "5.7.0", "05.7.0"))

	// require_name_constraints is true, written plain (only true is accepted: a policy cannot switch the rule off).
	for _, bad := range []string{"yes", "no", "on", "off", "True", "TRUE", "False", "\"true\"", "'true'", "1", "0", "y", "n", "[true]", "{a: true}", "tru", "true # x\n  x: y"} {
		t.Run("require_name_constraints "+bad, func(t *testing.T) {
			text := replaceOnce(t, goodSettings, "require_name_constraints: true", "require_name_constraints: "+bad)
			if _, err := wanted.ParseSettings(settingsPath, []byte(text)); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	_ = refuseSettings(t, replaceOnce(t, goodSettings, "require_name_constraints: true", "require_name_constraints: yes"), 8, "policy.require_name_constraints must be true or false")
	_ = refuseSettings(t, replaceOnce(t, goodSettings, "require_name_constraints: true", "require_name_constraints: \"true\""), 8, "must be true or false")
	_ = refuseSettings(t, replaceOnce(t, goodSettings, "require_name_constraints: true", "require_name_constraints: false"), 8, "policy.require_name_constraints must be true", "cannot switch")
	if s := mustSettings(t, goodSettings); !s.Policy.RequireNameConstraints {
		t.Error("RequireNameConstraints is false in an accepted file")
	}

	// validity_months is an integer of plain decimal digits, at least 1, at most nine digits.
	for _, tc := range []struct {
		text string
		want int
	}{{"1", 1}, {"13", 13}, {"36", 36}, {"120", 120}, {"999999999", 999999999}} {
		if s := mustSettings(t, replaceOnce(t, goodSettings, "validity_months: 13", "validity_months: "+tc.text)); s.Policy.ValidityMonths != tc.want {
			t.Errorf("validity %s read as %d", tc.text, s.Policy.ValidityMonths)
		}
	}
	for _, bad := range []string{"013", "0x0d", "0o15", "+13", "13.0", "1_3", "\"13\"", "1234567890", "-1", "1e1", "0b1101", ".5", "13.", "1,3", "yes", "thirteen", "[13]", "{a: 13}", "0013", "99999999999999999999"} {
		t.Run("validity_months "+bad, func(t *testing.T) {
			_ = refuseSettings(t, replaceOnce(t, goodSettings, "validity_months: 13", "validity_months: "+bad), 9, "policy.validity_months must be an integer of plain decimal digits")
		})
	}
	_ = refuseSettings(t, replaceOnce(t, goodSettings, "validity_months: 13", "validity_months: 0"), 9, "policy.validity_months must be at least 1")
	_ = refuseSettings(t, replaceOnce(t, goodSettings, "version: 1", "version: 2"), 1, "version must be 1")
	for _, bad := range []string{"0", "\"1\"", "1.0", "01", "true", "-1", "[1]", "0x1"} {
		t.Run("version "+bad, func(t *testing.T) {
			_ = refuseSettings(t, replaceOnce(t, goodSettings, "version: 1", "version: "+bad), 1, "version")
		})
	}
}

func TestAnAwsKmsBlock(t *testing.T) {
	const acct = "111122223333"
	kms := func(change func(s string) string) string {
		block := "aws_kms:\n  account: \"" + acct + "\"\n  region: eu-west-1\n  replica_region: eu-central-1\n" +
			"  admin_role: arn:aws:iam::" + acct + ":role/example-admin\n  ceremony_role: arn:aws:iam::" + acct + ":role/example-ceremony\n"
		if change != nil {
			block = change(block)
		}
		return goodSettings + block
	}
	mustSettings(t, kms(nil))
	for name, tc := range map[string]struct {
		change func(string) string
		line   int
		words  []string
	}{
		"an account that is not quoted":  {func(s string) string { return strings.Replace(s, `"`+acct+`"`, acct, 1) }, 11, []string{"aws_kms.account must be quoted"}},
		"an account with a leading zero": {func(s string) string { return strings.Replace(s, `"`+acct+`"`, "011122223333", 1) }, 11, []string{"must be quoted"}},
		"an account that is a float":     {func(s string) string { return strings.Replace(s, `"`+acct+`"`, "1.5", 1) }, 11, []string{"must be quoted"}},
		"an account of 11 digits":        {func(s string) string { return strings.Replace(s, acct, "11112222333", 1) }, 11, []string{"12 digits"}},
		"an account of 13 digits":        {func(s string) string { return strings.Replace(s, `"`+acct+`"`, `"1111222233334"`, 1) }, 11, []string{"12 digits"}},
		"an account with a letter":       {func(s string) string { return strings.Replace(s, `"`+acct+`"`, `"11112222333a"`, 1) }, 11, []string{"12 digits"}},
		"an empty account":               {func(s string) string { return strings.Replace(s, `"`+acct+`"`, `""`, 1) }, 11, []string{"12 digits"}},
		"equal Regions":                  {func(s string) string { return strings.Replace(s, "eu-central-1", "eu-west-1", 1) }, 13, []string{"replica_region differs"}},
		"an empty Region":                {func(s string) string { return strings.Replace(s, "region: eu-west-1", `region: ""`, 1) }, 12, []string{"aws_kms.region"}},
		"a Region with a space":          {func(s string) string { return strings.Replace(s, "region: eu-west-1", `region: "eu west"`, 1) }, 12, []string{"aws_kms.region"}},
		"a Region of 65 characters": {func(s string) string {
			return strings.Replace(s, "region: eu-west-1", "region: "+strings.Repeat("a", 65), 1)
		}, 12, []string{"aws_kms.region"}},
		"a role in another account": {func(s string) string {
			return strings.Replace(s, "iam::"+acct+":role/example-admin", "iam::999988887777:role/example-admin", 1)
		}, 14, []string{"aws_kms.admin_role is a role in the account"}},
		"the ceremony role in another one": {func(s string) string {
			return strings.Replace(s, "iam::"+acct+":role/example-ceremony", "iam::999988887777:role/example-ceremony", 1)
		}, 15, []string{"aws_kms.ceremony_role is a role in the account"}},
		"a role ARN with nothing after": {func(s string) string { return strings.Replace(s, "role/example-admin", "role/", 1) }, 14, []string{"aws_kms.admin_role is a role ARN"}},
		"a user ARN":                    {func(s string) string { return strings.Replace(s, ":role/example-admin", ":user/example-admin", 1) }, 14, []string{"role ARN"}},
		"a role ARN with a space":       {func(s string) string { return strings.Replace(s, "example-admin", `"x y"`, 1) }, 14, []string{"role ARN"}},
		"a role that is not a string":   {func(s string) string { return strings.Replace(s, "arn:aws:iam::"+acct+":role/example-admin", "5", 1) }, 14, []string{"aws_kms.admin_role must be a string"}},
		"an ARN of another service":     {func(s string) string { return strings.Replace(s, "arn:aws:iam", "arn:aws:s3", 1) }, 14, []string{"role ARN"}},
		"a partition that is not aws": {func(s string) string {
			return strings.Replace(s, "arn:aws:iam::"+acct+":role/example-admin", "arn:gcp:iam::"+acct+":role/example-admin", 1)
		}, 14, []string{"role ARN"}},
		"an ARN over 2048 characters": {func(s string) string {
			return strings.Replace(s, "role/example-admin", "role/"+strings.Repeat("a", 2048), 1)
		}, 14, []string{"role ARN"}},
		"a block that is a list": {func(string) string { return "aws_kms: [a]\n" }, 10, []string{"aws_kms must be a mapping"}},
	} {
		t.Run(name, func(t *testing.T) { _ = refuseSettings(t, kms(tc.change), tc.line, tc.words...) })
	}
	// An ARN of exactly 2048 characters is the longest.
	long := func(n int) string {
		arn := "arn:aws:iam::" + acct + ":role/"
		return arn + strings.Repeat("a", n-len(arn))
	}
	for _, n := range []int{2048, 2049} {
		text := kms(func(s string) string {
			return strings.Replace(s, "arn:aws:iam::"+acct+":role/example-admin", long(n), 1)
		})
		if n == 2048 {
			mustSettings(t, text)
		} else {
			_ = refuseSettings(t, text, 14, "role ARN")
		}
	}
	// The members of the block are strings of the reader's, and the message names the Region by the member.
	_ = refuseSettings(t, kms(func(s string) string { return strings.Replace(s, "eu-west-1", "5", 1) }), 12, "aws_kms.region must be a string")
}

func TestTheLicenseOfTheKeyring(t *testing.T) {
	for _, ok := range []string{"CC0-1.0", "MIT", "Apache-2.0 OR MIT", strings.Repeat("a", 128)} {
		if s := mustSettings(t, goodSettings+"keyring:\n  license: "+quoteYAML(ok)+"\n"); s.KeyringLicense != ok {
			t.Errorf("license %q read as %q", ok, s.KeyringLicense)
		}
	}
	for name, bad := range map[string]string{"empty": `""`, "129 characters": strings.Repeat("a", 129), "a non-ASCII letter": "\"caf\u00e9\"", "a number": "1", "a list": "[MIT]"} {
		t.Run(name, func(t *testing.T) {
			_ = refuseSettings(t, goodSettings+"keyring:\n  license: "+bad+"\n", 11, "keyring.license")
		})
	}
	_ = refuseSettings(t, goodSettings+"keyring: MIT\n", 10, "keyring must be a mapping")
}

func TestSettingsAreNeverMadeByHand(t *testing.T) {
	var zero wanted.Settings
	if zero.Valid() {
		t.Error("the zero Settings is valid")
	}
	var nilSettings *wanted.Settings
	if nilSettings.Valid() {
		t.Error("a nil *Settings is valid")
	}
	s := mustSettings(t, goodSettings)
	hand := *s
	hand.Name = "Other"
	if !hand.Valid() {
		t.Log("a copy of a made value keeps the flag: the flag cannot be set from outside, only copied")
	}
	byHand := wanted.Settings{Version: 1, Name: "Example", ReleaseAddress: "release@example.org", Policy: s.Policy}
	if byHand.Valid() {
		t.Error("a Settings that a caller filled in is valid")
	}
}
