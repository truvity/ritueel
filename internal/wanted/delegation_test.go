package wanted_test

import (
	"reflect"
	"strconv"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/wanted"
)

// A delegation file: docs/reference/bundle.md, "A delegation file", its schema and its "Five rules".

const delegationPath = "want/delegations/example.yaml"

func TestTheThreeExamplesOfThePageAreRead(t *testing.T) {
	d := mustDelegation(t, "acme-tls", goodX509Delegation)
	if d.Name != "acme-tls" || d.Type != wanted.TypeX509Intermediate || d.Root != "acme-tls" ||
		!reflect.DeepEqual(d.PermittedURIHosts, []string{"example.org"}) || !reflect.DeepEqual(d.PermittedDNSNames, []string{"example.org"}) {
		t.Errorf("x509: %+v", d)
	}
	if d.Capability != "" || d.Use != "" || d.KMSReadRoles != nil {
		t.Errorf("x509 holds members of another type: %+v", d)
	}
	d = mustDelegation(t, "acme-release", goodOpenPGPDelegation)
	if d.Type != wanted.TypeOpenPGPSubkey || d.Root != "acme-release" || d.Capability != "sign" || d.Use != "" || len(d.PermittedURIHosts)+len(d.PermittedDNSNames) != 0 {
		t.Errorf("openpgp: %+v", d)
	}
	if !reflect.DeepEqual(d.KMSReadRoles, map[string]string{"111122223333": "arn:aws:iam::111122223333:role/example-certifier-read"}) {
		t.Errorf("roles %v", d.KMSReadRoles)
	}
	d = mustDelegation(t, "acme-ssh", goodSSHDelegation)
	if d.Type != wanted.TypeSSHCAKey || d.Use != "user" || d.Capability != "" || d.Root != "acme-ssh" {
		t.Errorf("ssh: %+v", d)
	}
}

func TestACapabilityAndAUseHaveTheirValuesAndNoOthers(t *testing.T) {
	for _, c := range []string{"sign", "authenticate"} {
		if d := mustDelegation(t, "example", replaceOnce(t, goodOpenPGPDelegation, "capability: sign", "capability: "+c)); d.Capability != c {
			t.Errorf("capability %s read as %q", c, d.Capability)
		}
	}
	for _, u := range []string{"user", "host"} {
		if d := mustDelegation(t, "example", replaceOnce(t, goodSSHDelegation, "use: user", "use: "+u)); d.Use != u {
			t.Errorf("use %s read as %q", u, d.Use)
		}
	}
	for _, c := range []string{"encrypt", "certify", "Sign", "SIGN", "sign,authenticate", "[sign]", "both", "", "\"sign \"", "1", "true"} {
		t.Run("capability "+c, func(t *testing.T) {
			text := replaceOnce(t, goodOpenPGPDelegation, "capability: sign", "capability: "+quoteIf(c))
			_ = refuseDelegation(t, text, 4, "capability")
		})
	}
	for _, u := range []string{"both", "User", "HOST", "users", "", "[user]", "1", "true", "user host", "client"} {
		t.Run("use "+u, func(t *testing.T) {
			text := replaceOnce(t, goodSSHDelegation, "use: user", "use: "+quoteIf(u))
			_ = refuseDelegation(t, text, 4, "use")
		})
	}
}

// quoteIf writes a value for the rows that test the value and not its spelling: a bracket, a number or a boolean
// stays as typed, and anything else is quoted.
func quoteIf(s string) string {
	if s == "" || strings.HasPrefix(s, "[") || s == "1" || s == "true" {
		if s == "" {
			return `""`
		}
		return s
	}
	return quoteYAML(s)
}

func TestEachMemberThatDoesNotBelongToTheTypeIsRefused(t *testing.T) {
	const roles = "kms_read_roles:\n  \"111122223333\": arn:aws:iam::111122223333:role/a\n"
	x509 := goodX509Delegation
	pgp := "version: 1\ntype: openpgp-subkey\nroot: acme-release\ncapability: sign\n"
	ssh := goodSSHDelegation
	for name, tc := range map[string]struct {
		text, member string
	}{
		"x509 with capability":        {x509 + "capability: sign\n", "capability"},
		"x509 with use":               {x509 + "use: user\n", "use"},
		"openpgp with uri hosts":      {pgp + "permitted_uri_hosts: [example.org]\n", "permitted_uri_hosts"},
		"openpgp with dns names":      {pgp + "permitted_dns_names: [example.org]\n", "permitted_dns_names"},
		"openpgp with an empty list":  {pgp + "permitted_dns_names: []\n", "permitted_dns_names"},
		"openpgp with use":            {pgp + "use: user\n", "use"},
		"ssh with uri hosts":          {ssh + "permitted_uri_hosts: [example.org]\n", "permitted_uri_hosts"},
		"ssh with dns names":          {ssh + "permitted_dns_names: [example.org]\n", "permitted_dns_names"},
		"ssh with capability":         {ssh + "capability: sign\n", "capability"},
		"x509 with both of the other": {x509 + "use: user\ncapability: sign\n", "capability"},
	} {
		t.Run(name, func(t *testing.T) {
			e := refuseDelegation(t, tc.text, -1, tc.member+" is not a member of a delegation of the type")
			if e.Line == 0 {
				t.Error("no line")
			}
		})
	}
	// kms_read_roles belongs to every type.
	for name, text := range map[string]string{"x509": x509 + roles, "openpgp": pgp + roles, "ssh": ssh + roles} {
		t.Run("roles with "+name, func(t *testing.T) {
			if d := mustDelegation(t, "example", text); len(d.KMSReadRoles) != 1 {
				t.Errorf("roles %v", d.KMSReadRoles)
			}
		})
	}
}

func TestEachTypeNeedsItsOwnMember(t *testing.T) {
	_ = refuseDelegation(t, "version: 1\ntype: openpgp-subkey\nroot: acme-release\n", 1, "openpgp-subkey delegation needs the member capability")
	_ = refuseDelegation(t, "version: 1\ntype: ssh-ca-key\nroot: acme-ssh\n", 1, "ssh-ca-key delegation needs the member use")
	_ = refuseDelegation(t, "version: 1\ntype: x509-intermediate\nroot: acme-tls\n", 1, "permitted_uri_hosts or in permitted_dns_names", "requires name constraints")
	for name, text := range map[string]string{
		"both lists empty":     "version: 1\ntype: x509-intermediate\nroot: acme-tls\npermitted_uri_hosts: []\npermitted_dns_names: []\n",
		"one list empty":       "version: 1\ntype: x509-intermediate\nroot: acme-tls\npermitted_uri_hosts: []\n",
		"the other list empty": "version: 1\ntype: x509-intermediate\nroot: acme-tls\npermitted_dns_names: []\n",
		"a role and no names":  "version: 1\ntype: x509-intermediate\nroot: acme-tls\nkms_read_roles:\n  \"111122223333\": arn:aws:iam::111122223333:role/a\n",
	} {
		t.Run(name, func(t *testing.T) { _ = refuseDelegation(t, text, 1, "name constraints") })
	}
	// One entry in one of the two lists is enough.
	mustDelegation(t, "example", "version: 1\ntype: x509-intermediate\nroot: acme-tls\npermitted_uri_hosts: [example.org]\n")
	mustDelegation(t, "example", "version: 1\ntype: x509-intermediate\nroot: acme-tls\npermitted_dns_names: [example.org]\npermitted_uri_hosts: []\n")
	mustDelegation(t, "example", "version: 1\ntype: x509-intermediate\nroot: acme-tls\npermitted_uri_hosts: [\".example.org\"]\n")
}

// The names that the 17 vectors of the manifest list on purpose are the rows of the form: every row of that
// configuration is refused as an entry here, with its position and never its value.
func TestEveryEntryOfAListIsInTheFormOfTheContract(t *testing.T) {
	label := func(c byte, n int) string { return strings.Repeat(string(c), n) }
	name253 := label('a', 63) + "." + label('b', 63) + "." + label('c', 63) + "." + label('d', 61)
	name254 := label('a', 63) + "." + label('b', 63) + "." + label('c', 63) + "." + label('d', 62)
	if len(name253) != 253 || len(name254) != 254 {
		t.Fatalf("the long names have %d and %d characters", len(name253), len(name254))
	}
	type row struct {
		entry     string
		uri, dns  bool // accepted in the list of URI hosts, in the list of DNS names
		whyBadURI string
	}
	rows := []row{
		{"example.org", true, true, ""},
		{".example.org", true, false, ""},
		{"a.example.org", true, true, ""},
		{"1.example.org", true, true, ""},
		{"example-1.org", true, true, ""},
		{"xn--bcher-kva.example", true, true, ""},
		{"a", true, true, ""},
		{label('a', 63) + ".example", true, true, ""},
		{label('a', 64) + ".example", false, false, ""},
		{name253, true, true, ""},
		{name254, false, false, ""},
		{"." + name253, true, false, ""},
		{"." + name254, false, false, ""},
		{"https://example.org", false, false, ""},
		{"example.org:8080", false, false, ""},
		{"example.org/ca", false, false, ""},
		{"user@example.org", false, false, ""},
		{"EXAMPLE.ORG", false, false, ""},
		{"Example.org", false, false, ""},
		{"*.example.org", false, false, ""},
		{"*", false, false, ""},
		{"", false, false, ""},
		{"example.org.", false, false, ""},
		{".example.org.", false, false, ""},
		{"..example.org", false, false, ""},
		{".", false, false, ""},
		{"example..org", false, false, ""},
		{"example.123", false, false, ""},
		{"10.0.0.1", false, false, ""},
		{"a_b.example.org", false, false, ""},
		{"-a.example.org", false, false, ""},
		{"a-.example.org", false, false, ""},
		{"a b.example.org", false, false, ""},
		{" example.org", false, false, ""},
		{"example.org ", false, false, ""},
		{"b\u00fccher.example", false, false, ""},
		{"\u4f8b.example", false, false, ""},
		{"example.org\\n", false, false, ""},
	}
	for _, r := range rows {
		name := strconv.Quote(r.entry)
		if len(name) > 50 {
			name = name[:50]
		}
		t.Run(name, func(t *testing.T) {
			// The entry as a YAML double-quoted string; a backslash-n row means a line feed.
			entry := strings.ReplaceAll(strconv.Quote(r.entry), `\\n`, `\n`)
			uri := "version: 1\ntype: x509-intermediate\nroot: acme-tls\npermitted_uri_hosts: [" + entry + "]\n"
			dns := "version: 1\ntype: x509-intermediate\nroot: acme-tls\npermitted_dns_names: [" + entry + "]\n"
			if strings.ContainsAny(r.entry, "\u00fc\u4f8b") {
				uri = strings.ReplaceAll(uri, entry, quoteYAML(r.entry))
				dns = strings.ReplaceAll(dns, entry, quoteYAML(r.entry))
			}
			if r.uri {
				mustDelegation(t, "example", uri)
			} else {
				e := refuseDelegation(t, uri, 4, "permitted_uri_hosts entry 1", "form of the hand-off contract")
				if r.entry != "" && strings.Contains(e.Msg, strings.TrimSpace(r.entry)) && len(r.entry) > 3 {
					t.Errorf("the message holds the entry: %s", e.Msg)
				}
			}
			if r.dns {
				mustDelegation(t, "example", dns)
			} else {
				e := refuseDelegation(t, dns, 4, "permitted_dns_names entry 1", "form of the hand-off contract")
				if len(r.entry) > 3 && strings.Contains(e.Msg, r.entry) {
					t.Errorf("the message holds the entry: %s", e.Msg)
				}
			}
		})
	}
}

func TestAnEntryThatFailsIsNamedByItsPosition(t *testing.T) {
	text := "version: 1\ntype: x509-intermediate\nroot: acme-tls\npermitted_uri_hosts: [example.org, .example.org, \"HTTPS://X\"]\npermitted_dns_names: [example.org, \"bad name\"]\n"
	_ = refuseDelegation(t, text, 4, "permitted_uri_hosts entry 3")
	text = strings.Replace(text, `, "HTTPS://X"`, "", 1)
	_ = refuseDelegation(t, text, 5, "permitted_dns_names entry 2")
	// A block list: the line is the line of the entry.
	text = "version: 1\ntype: x509-intermediate\nroot: acme-tls\npermitted_dns_names:\n  - example.org\n  - Example.org\n"
	_ = refuseDelegation(t, text, 6, "permitted_dns_names entry 2")
}

func TestAListHasNoRepeatAndItsEntriesAreStrings(t *testing.T) {
	_ = refuseDelegation(t, "version: 1\ntype: x509-intermediate\nroot: acme-tls\npermitted_uri_hosts: [example.org, example.org]\n", 4, "permitted_uri_hosts entry 2", "repeats")
	_ = refuseDelegation(t, "version: 1\ntype: x509-intermediate\nroot: acme-tls\npermitted_dns_names: [a.org, b.org, a.org]\n", 4, "permitted_dns_names entry 3", "repeats")
	// The same name in the two lists is not a repeat: they are two lists.
	mustDelegation(t, "example", goodX509Delegation)
	// A host and its period form are two entries.
	mustDelegation(t, "example", "version: 1\ntype: x509-intermediate\nroot: acme-tls\npermitted_uri_hosts: [example.org, .example.org]\n")
	for name, entry := range map[string]string{"a number": "1", "a boolean": "true", "a date": "2024-01-01", "a nested list": "[a]", "a mapping": "{a: b}", "a float": "1.5"} {
		t.Run(name, func(t *testing.T) {
			_ = refuseDelegation(t, "version: 1\ntype: x509-intermediate\nroot: acme-tls\npermitted_dns_names: ["+entry+"]\n", 4, "permitted_dns_names entry 1 must be a string")
		})
	}
	_ = refuseDelegation(t, "version: 1\ntype: x509-intermediate\nroot: acme-tls\npermitted_dns_names: example.org\n", 4, "permitted_dns_names must be a list")
	_ = refuseDelegation(t, "version: 1\ntype: x509-intermediate\nroot: acme-tls\npermitted_uri_hosts: {a: b}\n", 4, "permitted_uri_hosts must be a list")
}

func TestKMSReadRoles(t *testing.T) {
	pgp := func(roles string) string {
		return "version: 1\ntype: openpgp-subkey\nroot: acme-release\ncapability: sign\nkms_read_roles:\n" + roles
	}
	good := "  \"111122223333\": arn:aws:iam::111122223333:role/example-certifier-read\n"
	d := mustDelegation(t, "example", pgp(good+"  \"999988887777\": arn:aws-us-gov:iam::999988887777:role/path/x\n"))
	if len(d.KMSReadRoles) != 2 {
		t.Errorf("roles %v", d.KMSReadRoles)
	}
	mustDelegation(t, "example", pgp(good))
	// An empty mapping is allowed and is no role.
	if d := mustDelegation(t, "example", "version: 1\ntype: openpgp-subkey\nroot: acme-release\ncapability: sign\nkms_read_roles: {}\n"); len(d.KMSReadRoles) != 0 {
		t.Errorf("roles %v", d.KMSReadRoles)
	}
	for name, tc := range map[string]struct {
		roles string
		line  int
		words []string
	}{
		"an account that is not quoted":  {"  111122223333: arn:aws:iam::111122223333:role/a\n", 6, []string{"key is not a string", "quotes"}},
		"an account with a leading zero": {"  011122223333: arn:aws:iam::011122223333:role/a\n", 6, []string{"key is not a string", "quotes"}},
		"a short account":                {"  \"11112222333\": arn:aws:iam::11112222333:role/a\n", 6, []string{"12 digits written in quotes"}},
		"a long account":                 {"  \"1111222233334\": arn:aws:iam::1111222233334:role/a\n", 6, []string{"12 digits written in quotes"}},
		"an account with a letter":       {"  \"11112222333a\": arn:aws:iam::111122223333:role/a\n", 6, []string{"12 digits written in quotes"}},
		"an empty account":               {"  \"\": arn:aws:iam::111122223333:role/a\n", 6, []string{"12 digits written in quotes"}},
		"a role in another account":      {"  \"111122223333\": arn:aws:iam::999988887777:role/a\n", 6, []string{"a role in the account it is listed under"}},
		"a user ARN":                     {"  \"111122223333\": arn:aws:iam::111122223333:user/a\n", 6, []string{"role ARN"}},
		"a role ARN with nothing after":  {"  \"111122223333\": arn:aws:iam::111122223333:role/\n", 6, []string{"role ARN"}},
		"a role that is not a string":    {"  \"111122223333\": 5\n", 6, []string{"must be a string"}},
		"a role that is a list":          {"  \"111122223333\": [a]\n", 6, []string{"must be a string"}},
		"a role with a space":            {"  \"111122223333\": \"arn:aws:iam::111122223333:role/a b\"\n", 6, []string{"role ARN"}},
		"a role over 2048 characters":    {"  \"111122223333\": arn:aws:iam::111122223333:role/" + strings.Repeat("a", 2048) + "\n", 6, []string{"role ARN"}},
		"a second bad entry":             {good + "  \"999988887777\": arn:aws:iam::111122223333:role/a\n", 7, []string{"the account it is listed under"}},
		"an account twice":               {good + "  \"111122223333\": arn:aws:iam::111122223333:role/b\n", 7, []string{"appears twice"}},
	} {
		t.Run(name, func(t *testing.T) { _ = refuseDelegation(t, pgp(tc.roles), tc.line, tc.words...) })
	}
	_ = refuseDelegation(t, "version: 1\ntype: openpgp-subkey\nroot: acme-release\ncapability: sign\nkms_read_roles: [a]\n", 5, "kms_read_roles must be a mapping")
	_ = refuseDelegation(t, "version: 1\ntype: openpgp-subkey\nroot: acme-release\ncapability: sign\nkms_read_roles: x\n", 5, "kms_read_roles must be a mapping")
	// The message never holds the ARN.
	e := refuseDelegation(t, pgp("  \"111122223333\": arn:aws:iam::999988887777:role/secret-name\n"), 6)
	if strings.Contains(e.Msg, "secret-name") || strings.Contains(e.Msg, "999988887777") {
		t.Errorf("the message holds the ARN: %s", e.Msg)
	}
}

func TestADelegationNameAndItsRootHaveTheFormOfAName(t *testing.T) {
	s := mustSettings(t, goodSettings)
	for _, name := range []string{"a", "0", "acme-tls", "a-b", "a--b", "a-", strings.Repeat("a", 63), "9acme", "break-glass", "break-glas-x", "xbreak-glass-x"} {
		d, err := wanted.ParseDelegation(name, []byte(goodX509Delegation), s)
		if err != nil || d.Name != name {
			t.Errorf("name %q: %v", name, err)
		}
	}
	for name, bad := range map[string]string{
		"a break-glass name":   "break-glass-x",
		"a break-glass prefix": "break-glass-",
		"upper case":           "Acme",
		"an underscore":        "a_b",
		"a leading hyphen":     "-a",
		"64 characters":        strings.Repeat("a", 64),
		"empty":                "",
		"a period":             "a.b",
		"the extension":        "a.yaml",
		"a slash":              "a/b",
		"a parent":             "..",
		"a space":              "a b",
		"a Cyrillic letter":    "\u0430bc",
		"a temporary leftover": ".rt-abc",
		"a line feed":          "a\nb",
		"a NUL":                "a\x00b",
		"a path out":           "../x",
		"a leading period":     ".a",
		"a trailing space":     "a ",
	} {
		t.Run(name, func(t *testing.T) {
			d, err := wanted.ParseDelegation(bad, []byte(goodX509Delegation), s)
			if d != nil || err == nil {
				t.Fatalf("accepted: %v %v", d, err)
			}
			e := wantFault(t, err, "", -1)
			if !strings.HasPrefix(e.Path, "want/delegations/") {
				t.Errorf("path %q", e.Path)
			}
		})
	}
	_ = refuseDelegation(t, replaceOnce(t, goodX509Delegation, "root: acme-tls", "root: Acme"), 3, "root:")
	for _, bad := range []string{"a.yaml", "-a", strings.Repeat("a", 64), "a_b", "\"\"", "a/b", "1", "true", "[a]"} {
		t.Run("root "+bad, func(t *testing.T) {
			_ = refuseDelegation(t, replaceOnce(t, goodX509Delegation, "root: acme-tls", "root: "+bad), 3, "root")
		})
	}
	// break-glass- is only refused as the name of a delegation; as a root it is a name like any other.
	mustDelegation(t, "example", replaceOnce(t, goodX509Delegation, "root: acme-tls", "root: break-glass-x"))
}

func TestADelegationHasItsVersionAndTypeAndRoot(t *testing.T) {
	for _, tc := range []struct{ drop, word string }{{"version: 1\n", "version"}, {"type: x509-intermediate\n", "type"}, {"root: acme-tls\n", "root"}} {
		_ = refuseDelegation(t, replaceOnce(t, goodX509Delegation, tc.drop, ""), 1, tc.word, "required")
	}
	_ = refuseDelegation(t, replaceOnce(t, goodX509Delegation, "version: 1", "version: 2"), 1, "version must be 1")
	for _, typ := range []string{"x509", "X509-INTERMEDIATE", "openpgp", "ssh", "x509-intermediate ", "\"\"", "1", "[x509-intermediate]"} {
		t.Run("type "+typ, func(t *testing.T) {
			_ = refuseDelegation(t, replaceOnce(t, goodX509Delegation, "type: x509-intermediate", "type: "+quoteIf(typ)), 2, "type")
		})
	}
	for _, extra := range []string{"extra: 1", "kind: x509", "keys: []", "name: x", "policy: {}", "Type: x", "permitted_hosts: [a]"} {
		t.Run(extra, func(t *testing.T) { _ = refuseDelegation(t, goodX509Delegation+extra+"\n", 6, "not known") })
	}
	_ = refuseDelegation(t, "- a\n", 1, "not a mapping")
	_ = refuseDelegation(t, "", 0, "no document")
}

func TestADelegationNeedsSettingsThatTheReaderMade(t *testing.T) {
	for name, s := range map[string]*wanted.Settings{"nil": nil, "zero": {}, "by hand": {Version: 1, Name: "Example", Policy: wanted.Policy{RequireNameConstraints: true}}} {
		t.Run(name, func(t *testing.T) {
			d, err := wanted.ParseDelegation("example", []byte(goodX509Delegation), s)
			if d != nil {
				t.Error("a value")
			}
			_ = wantFault(t, err, delegationPath, 0, "settings of the bundle are needed")
		})
	}
	// The rule that a list has an entry follows the policy of the settings given: the reader holds it when
	// the policy requires name constraints, and a Settings that the reader made always does.
	s := mustSettings(t, goodSettings)
	if !s.Policy.RequireNameConstraints {
		t.Fatal("a Settings that the reader made has no name constraints rule")
	}
}

func TestADelegationHoldsItsBytesAndDigest(t *testing.T) {
	d := mustDelegation(t, "example", goodX509Delegation)
	if d.File.Path != delegationPath || string(d.File.Data) != goodX509Delegation || d.File.SHA256 != sha256hex([]byte(goodX509Delegation)) {
		t.Errorf("file %+v", d.File)
	}
}

func TestADelegationIsNeverMadeByHand(t *testing.T) {
	var zero wanted.Delegation
	var none *wanted.Delegation
	if zero.Valid() || none.Valid() {
		t.Error("a zero or nil Delegation is valid")
	}
	d := mustDelegation(t, "example", goodX509Delegation)
	byHand := wanted.Delegation{Name: d.Name, Type: d.Type, Root: d.Root, PermittedURIHosts: d.PermittedURIHosts}
	if byHand.Valid() {
		t.Error("a Delegation that a caller filled in is valid")
	}
}
