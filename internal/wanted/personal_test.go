package wanted_test

import (
	"errors"
	"io/fs"
	"slices"
	"strings"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/wanted"
)

// The wanted files of a person: the keys and the encryption member of the OpenPGP root, want/openpgp.yaml, the
// member card of a delegation and the check across the files.

const (
	adoptedFP       = "0123456789abcdef0123456789abcdef01234567"
	adoptedLine     = `  - {label: A, role: adopted, fingerprint: "` + adoptedFP + `", valid_until: "2029-11-26"}` + "\n"
	personalOpenPGP = "version: 1\nkind: openpgp\nencryption: true\nrevocation_reasons: [retired]\nkeys:\n" + adoptedLine
	personalCard    = "version: 1\nserial: \"1234\"\nkind: day-to-day\napplications: [openpgp]\n"
	personalSign    = "version: 1\ntype: openpgp-subkey\nroot: openpgp\ncapability: sign\ncard: day-ana\n"
	personalPerson  = `version: 1
kind: personal
person: {name: Ada Example, address: ada@example.com}
policy:
  stores: [openpgp-card, software]
  min_firmware: 5.7.0
  pin_policy: [once]
  require_name_constraints: true
  validity_months: 13
`
)

// personalNow is the clock of these tests, one day before the day the key of the example expires less 36 months.
var personalNow = time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)

func mustPersonal(t testing.TB) *wanted.Settings {
	t.Helper()
	return mustSettings(t, personalPerson)
}

func refuseKeys(t *testing.T, text string, line int, words ...string) {
	t.Helper()
	r, err := wanted.ParseRoot("openpgp", []byte(text))
	if r != nil {
		t.Errorf("a value beside the error %v", err)
	}
	_ = wantFault(t, err, "want/roots/openpgp.yaml", line, words...)
}

func TestAnAdoptedKeyIsRead(t *testing.T) {
	r := mustRoot(t, "openpgp", strings.Replace(personalOpenPGP, adoptedFP, strings.ToUpper(adoptedFP), 1))
	keys := r.Keys()
	if len(keys) != 1 || keys[0].Label != "A" || keys[0].Role != wanted.RoleAdopted || keys[0].Fingerprint != adoptedFP || keys[0].ValidUntil.String() != "2029-11-26" {
		t.Fatalf("keys %+v", keys)
	}
	if v, set := r.Encryption(); !v || !set {
		t.Errorf("encryption %v %v", v, set)
	}
	// The accessors give copies.
	keys[0].Fingerprint = "changed"
	if r.Keys()[0].Fingerprint != adoptedFP {
		t.Error("a change of the copy shows in the root")
	}
	if v, set := mustRoot(t, "openpgp", "version: 1\nkind: openpgp\nencryption: false\n").Encryption(); v || !set {
		t.Errorf("encryption false: %v %v", v, set)
	}
	if _, set := mustRoot(t, "openpgp", "version: 1\nkind: openpgp\n").Encryption(); set {
		t.Error("encryption is set in a file that has none")
	}
	if got := mustRoot(t, "openpgp", "version: 1\nkind: openpgp\n").Keys(); len(got) != 0 {
		t.Errorf("keys %v", got)
	}
}

func TestTheKeysOfARootThatAreNotTheShapeAreRefused(t *testing.T) {
	head := "version: 1\nkind: openpgp\nencryption: true\nkeys:\n"
	key := func(members string) string { return head + "  - {" + members + "}\n" }
	const label, role, fp, until = `label: A`, `role: adopted`, `fingerprint: "` + adoptedFP + `"`, `valid_until: "2029-11-26"`
	ok := strings.Join([]string{label, role, fp, until}, ", ")
	for name, tc := range map[string]struct {
		text  string
		words []string
	}{
		"no entry":                     {head[:len(head)-1] + " []\n", []string{"keys must hold 1 to 8 entries"}},
		"nine entries":                 {head + strings.Repeat("  - {label: A}\n", 9), []string{"1 to 8 entries"}},
		"keys is a mapping":            {"version: 1\nkind: openpgp\nkeys: {a: b}\n", []string{"keys must be a list"}},
		"an entry that is a string":    {head + "  - adopted\n", []string{"keys[1] must be a mapping"}},
		"no label":                     {key(strings.Join([]string{role, fp, until}, ", ")), []string{"keys[1].label is required"}},
		"label a":                      {key(strings.Replace(ok, "label: A", "label: a", 1)), []string{"keys[1].label is one letter from A to Z"}},
		"label AB":                     {key(strings.Replace(ok, "label: A", "label: AB", 1)), []string{"keys[1].label is one letter"}},
		"label a digit":                {key(strings.Replace(ok, "label: A", `label: "1"`, 1)), []string{"keys[1].label is one letter"}},
		"no role":                      {key(strings.Join([]string{label, fp, until}, ", ")), []string{"keys[1].role is required"}},
		"role published":               {key(strings.Replace(ok, "adopted", "published", 1)), []string{"role published is reserved for stage two", "not built yet"}},
		"role standby":                 {key(strings.Replace(ok, "adopted", "standby", 1)), []string{"role standby is reserved for stage two", "not built yet"}},
		"another role":                 {key(strings.Replace(ok, "adopted", "primary", 1)), []string{"keys[1].role must be adopted", "stage two"}},
		"a hostile role":               {key(strings.Replace(ok, "adopted", `"a\u202eb"`, 1)), []string{"keys[1].role must be adopted"}},
		"member card":                  {key(ok + ", card: day-ana"), []string{"the member card is reserved for stage two, which is not built yet"}},
		"member replaces":              {key(ok + ", replaces: B"), []string{"the member replaces is reserved for stage two"}},
		"member overlap_until":         {key(ok + `, overlap_until: "2029-01-01"`), []string{"the member overlap_until is reserved for stage two"}},
		"member retire_on":             {key(ok + `, retire_on: "2029-01-01"`), []string{"the member retire_on is reserved for stage two"}},
		"member retire_reason":         {key(ok + ", retire_reason: x"), []string{"the member retire_reason is reserved for stage two"}},
		"a reserved member, bad value": {key(ok + ", card: [1, 2]"), []string{"the member card is reserved for stage two"}},
		"an unknown member":            {key(ok + ", colour: red"), []string{"keys[1]: the member \"colour\" is not known"}},
		"no fingerprint":               {key(strings.Join([]string{label, role, until}, ", ")), []string{"keys[1].fingerprint is required for the role adopted"}},
		"no valid_until":               {key(strings.Join([]string{label, role, fp}, ", ")), []string{"keys[1].valid_until is required for the role adopted"}},
		"a fingerprint of 39 digits":   {key(strings.Replace(ok, adoptedFP, adoptedFP[1:], 1)), []string{"40 hexadecimal digits"}},
		"a fingerprint of 41 digits":   {key(strings.Replace(ok, adoptedFP, adoptedFP+"0", 1)), []string{"40 hexadecimal digits"}},
		"a fingerprint with a g":       {key(strings.Replace(ok, adoptedFP, "g"+adoptedFP[1:], 1)), []string{"40 hexadecimal digits"}},
		"a fingerprint with a space":   {key(strings.Replace(ok, adoptedFP, " "+adoptedFP[1:], 1)), []string{"40 hexadecimal digits"}},
		"an unquoted fingerprint":      {key(strings.Replace(ok, `"`+adoptedFP+`"`, strings.Repeat("1", 40), 1)), []string{"must be a string: write it in quotes"}},
		"the placeholder":              {key(strings.Replace(ok, adoptedFP, wanted.PlaceholderFingerprint, 1)), []string{"replace the placeholder with the fingerprint of your key"}},
		"an unquoted date":             {key(strings.Replace(ok, `"2029-11-26"`, "2029-11-26", 1)), []string{"valid_until must be a string: write it in quotes"}},
		"a date with a slash":          {key(strings.Replace(ok, "2029-11-26", "2029/11/26", 1)), []string{"keys[1].valid_until is a date written \"YYYY-MM-DD\""}},
		"a date without zeros":         {key(strings.Replace(ok, "2029-11-26", "2029-1-26", 1)), []string{"is a date written"}},
		"a date with a time":           {key(strings.Replace(ok, "2029-11-26", "2029-11-26T00:00:00Z", 1)), []string{"is a date written"}},
		"a date of letters":            {key(strings.Replace(ok, "2029-11-26", "abcd-ef-gh", 1)), []string{"is a date written"}},
		"the year 1999":                {key(strings.Replace(ok, "2029-11-26", "1999-12-31", 1)), []string{"has a year from 2000 to 2105"}},
		"the year 2106":                {key(strings.Replace(ok, "2029-11-26", "2106-01-01", 1)), []string{"has a year from 2000 to 2105"}},
		"the 30th of February":         {key(strings.Replace(ok, "2029-11-26", "2029-02-30", 1)), []string{"is not a day of the calendar"}},
		"month 13":                     {key(strings.Replace(ok, "2029-11-26", "2029-13-01", 1)), []string{"is not a day of the calendar"}},
		"a label twice":                {head + "  - {" + ok + "}\n  - {" + strings.Replace(ok, adoptedFP, adoptedFP[:39]+"8", 1) + "}\n", []string{"keys[2].label is used twice"}},
		"a fingerprint twice":          {head + "  - {" + ok + "}\n  - {" + strings.Replace(strings.Replace(ok, "label: A", "label: B", 1), adoptedFP, strings.ToUpper(adoptedFP), 1) + "}\n", []string{"keys[2].fingerprint is the fingerprint of an earlier key"}},
		"a role twice":                 {head + "  - {" + ok + "}\n  - {" + strings.Replace(strings.Replace(ok, "label: A", "label: B", 1), adoptedFP, adoptedFP[:39]+"8", 1) + "}\n", []string{"keys[2].role adopted is used twice"}},
		"encryption a string":          {"version: 1\nkind: openpgp\nencryption: \"true\"\n", []string{"encryption must be true or false"}},
		"encryption yes":               {"version: 1\nkind: openpgp\nencryption: yes\n", []string{"encryption must be true or false"}},
	} {
		t.Run(name, func(t *testing.T) { refuseKeys(t, tc.text, -1, tc.words...) })
	}
	// The value of a key that is refused is never echoed.
	for _, bad := range []string{"a\\u202eb", strings.Repeat("x", 300)} {
		_, err := wanted.ParseRoot("openpgp", []byte(key(strings.Replace(ok, "adopted", `"`+bad+`"`, 1))))
		if err == nil || strings.Contains(err.Error(), "xxxxxxxxxx") || strings.Contains(err.Error(), "202e") {
			t.Errorf("the error echoes the role: %v", err)
		}
	}
}

func TestTheDayAKeyExpires(t *testing.T) {
	key := func(day string) wanted.Key {
		text := strings.Replace(personalOpenPGP, "2029-11-26", day, 1)
		return mustRoot(t, "openpgp", text).Keys()[0]
	}
	for name, tc := range map[string]struct {
		day   string
		now   time.Time
		words string // "" for a day that is accepted
	}{
		"tomorrow":                      {"2026-11-27", personalNow, ""},
		"today":                         {"2026-11-26", personalNow, "not after now"},
		"today, at midnight":            {"2026-11-26", time.Date(2026, 11, 26, 0, 0, 0, 0, time.UTC), "not after now"},
		"yesterday":                     {"2026-11-25", personalNow, "not after now"},
		"36 months to the day":          {"2029-11-26", personalNow, ""},
		"a day more":                    {"2029-11-27", personalNow, "more than 36 months from now: the latest day is 2029-11-26"},
		"the last day of a short month": {"2027-02-28", time.Date(2024, 2, 29, 12, 0, 0, 0, time.UTC), ""},
		"the day after it":              {"2027-03-01", time.Date(2024, 2, 29, 12, 0, 0, 0, time.UTC), "the latest day is 2027-02-28"},
		"a clock in another zone":       {"2029-11-27", time.Date(2026, 11, 26, 23, 30, 0, 0, time.FixedZone("x", -5*3600)), ""},
	} {
		t.Run(name, func(t *testing.T) {
			got := key(tc.day).ExpiryProblem(tc.now)
			if (tc.words == "") != (got == "") || !strings.Contains(got, tc.words) {
				t.Errorf("ExpiryProblem = %q, want %q", got, tc.words)
			}
		})
	}
	if got := (wanted.Key{}).ExpiryProblem(personalNow); got == "" {
		t.Error("a key with no date is accepted")
	}
	if got := key("2029-11-26").ExpiryProblem(time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)); got == "" {
		t.Error("a clock outside the years is accepted")
	}
}

func TestTheUserIDsOfAPerson(t *testing.T) {
	const head = "version: 1\nuser_ids:\n"
	ids, err := wanted.ParseUserIDs([]byte(head + "  - {name: Ada Example, address: ada@example.org}\n  - {name: Ada Old, address: ada@old.example.com, retire: true}\n"))
	if err != nil || !ids.Valid() || ids.File.Path != wanted.UserIDsPath {
		t.Fatalf("%v %+v", err, ids)
	}
	got := ids.Entries()
	if len(got) != 2 || got[0].Retire || !got[1].Retire || got[1].Address != "ada@old.example.com" {
		t.Fatalf("entries %+v", got)
	}
	got[0].Name = "changed"
	if ids.Entries()[0].Name != "Ada Example" {
		t.Error("a change of the copy shows in the file")
	}
	if ids, err := wanted.ParseUserIDs([]byte("version: 1\nuser_ids: []\n")); err != nil || len(ids.Entries()) != 0 {
		t.Errorf("an empty list: %v", err)
	}
	if ids, err := wanted.ParseUserIDs([]byte("version: 1\n")); err != nil || len(ids.Entries()) != 0 {
		t.Errorf("no member: %v", err)
	}
	one := func(entry string) string { return head + "  - " + entry + "\n" }
	many := func(n int, retire bool) string {
		var b strings.Builder
		b.WriteString(head)
		for i := range n {
			b.WriteString("  - {name: Ada, address: \"a" + strings.Repeat("b", i) + "@example.org\"")
			if retire {
				b.WriteString(", retire: true")
			}
			b.WriteString("}\n")
		}
		return b.String()
	}
	for name, tc := range map[string]struct {
		text  string
		words []string
	}{
		"no version":                     {"user_ids: []\n", []string{"version", "required"}},
		"another member":                 {"version: 1\nprimary: x\n", []string{"the member \"primary\" is not known"}},
		"a member primary":               {one("{name: Ada, address: a@example.org, primary: true}"), []string{"user_ids[1]: the member \"primary\" is not known"}},
		"not a list":                     {"version: 1\nuser_ids: x\n", []string{"user_ids must be a list"}},
		"no name":                        {one("{address: a@example.org}"), []string{"user_ids[1].name", "required"}},
		"no address":                     {one("{name: Ada}"), []string{"user_ids[1].address", "required"}},
		"a name with a newline":          {one(`{name: "Ada\nB", address: a@example.org}`), []string{"user_ids[1].name has 1 to 64 characters"}},
		"a name with a bidi":             {one(`{name: "Ada\u202eB", address: a@example.org}`), []string{"user_ids[1].name has 1 to 64 characters"}},
		"a name with a control":          {one(`{name: "Ada\u0007B", address: a@example.org}`), []string{"user_ids[1].name has 1 to 64 characters"}},
		"a name that is not ASCII":       {one(`{name: "Adá", address: a@example.org}`), []string{"user_ids[1].name has 1 to 64 characters"}},
		"a name with an angle":           {one(`{name: "Ada <b>", address: a@example.org}`), []string{"user_ids[1].name has 1 to 64 characters"}},
		"a name of 65 characters":        {one("{name: " + strings.Repeat("a", 65) + ", address: a@example.org}"), []string{"user_ids[1].name has 1 to 64 characters"}},
		"a trailing space":               {one(`{name: "Ada ", address: a@example.org}`), []string{"user_ids[1].name has no space at the end"}},
		"two spaces":                     {one(`{name: "Ada  B", address: a@example.org}`), []string{"user_ids[1].name has no two spaces in a row"}},
		"an address with an angle":       {one(`{name: Ada, address: "<a@example.org>"}`), []string{"user_ids[1].address is one bare address"}},
		"an address with a space":        {one(`{name: Ada, address: "a b@example.org"}`), []string{"user_ids[1].address is printable ASCII"}},
		"an address not ASCII":           {one(`{name: Ada, address: "a@examplé.org"}`), []string{"user_ids[1].address is printable ASCII"}},
		"an address with a bidi":         {one(`{name: Ada, address: "a@example.org\u202e"}`), []string{"user_ids[1].address is printable ASCII"}},
		"an address with a newline":      {one(`{name: Ada, address: "a@example.org\n"}`), []string{"user_ids[1].address is printable ASCII"}},
		"a second at sign":               {one(`{name: Ada, address: "\"a@b\"@example.org"}`), []string{"user_ids[1].address"}},
		"no at sign":                     {one("{name: Ada, address: example.org}"), []string{"user_ids[1].address"}},
		"an address of 255":              {one("{name: Ada, address: " + strings.Repeat("a", 243) + "@example.org}"), []string{"user_ids[1].address has 1 to 254 characters"}},
		"retire as a string":             {one(`{name: Ada, address: a@example.org, retire: "true"}`), []string{"retire must be true or false"}},
		"a user ID twice":                {head + "  - {name: Ada, address: a@example.org}\n  - {name: Ada, address: A@Example.ORG, retire: true}\n", []string{"user_ids[2] is a user ID that an earlier entry has"}},
		"17 entries":                     {many(17, true), []string{"user_ids must hold at most 16 entries"}},
		"9 entries that are not retired": {many(9, false), []string{"more than 8 user IDs that are not retired"}},
	} {
		t.Run(name, func(t *testing.T) {
			u, err := wanted.ParseUserIDs([]byte(tc.text))
			if u != nil {
				t.Errorf("a value beside the error %v", err)
			}
			_ = wantFault(t, err, wanted.UserIDsPath, -1, tc.words...)
		})
	}
	// 16 entries that retire, and 8 that do not, pass; a different name is a different user ID.
	for name, text := range map[string]string{
		"16 that retire":       many(16, true),
		"8 that do not":        many(8, false),
		"the same address":     head + "  - {name: Ada, address: a@example.org}\n  - {name: Ada B, address: a@example.org}\n",
		"the same name, other": head + "  - {name: Ada, address: a@example.org}\n  - {name: Ada, address: b@example.org}\n",
	} {
		if _, err := wanted.ParseUserIDs([]byte(text)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestTheUserIDsFileIsOptionalOnTheDisk(t *testing.T) {
	_, fsys := bundleDir(t, map[string]string{"want/openpgp.yaml": "version: 1\nuser_ids: []\n"})
	if u, err := wanted.LoadUserIDs(fsys); err != nil || !u.Valid() {
		t.Fatalf("%v", err)
	}
	_, none := bundleDir(t, map[string]string{"ritueel.yaml": personalPerson})
	if _, err := wanted.LoadUserIDs(none); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("a missing file: %v", err)
	}
}

func TestACardOfAPersonalDelegation(t *testing.T) {
	personal := mustPersonal(t)
	d, err := wanted.ParseDelegation("daily", []byte(personalSign), personal)
	if err != nil || d.Card != "day-ana" {
		t.Fatalf("%v %+v", err, d)
	}
	refuse := func(s *wanted.Settings, text string, words ...string) {
		t.Helper()
		d, err := wanted.ParseDelegation("daily", []byte(text), s)
		if d != nil {
			t.Errorf("a value beside the error %v", err)
		}
		_ = wantFault(t, err, "want/delegations/daily.yaml", -1, words...)
	}
	refuse(personal, strings.Replace(personalSign, "card: day-ana\n", "", 1), "needs the member card")
	refuse(personal, strings.Replace(personalSign, "day-ana", "Day_Ana", 1), "card: a name has lower-case letters")
	refuse(personal, strings.Replace(personalSign, "day-ana", "[a]", 1), "card must be a string")
	company := mustSettings(t, goodSettings)
	refuse(company, personalSign, "card is a member of an openpgp-subkey delegation of a personal bundle only")
	refuse(company, goodX509Delegation+"card: day-ana\n", "card is not a member of a delegation of the type x509-intermediate")
	refuse(company, goodSSHDelegation+"card: day-ana\n", "card is not a member of a delegation of the type ssh-ca-key")
	if _, err := wanted.ParseDelegation("daily", []byte(goodOpenPGPDelegation), company); err != nil {
		t.Errorf("a company delegation without a card: %v", err)
	}
}

func TestThePersonalRefusalsOfRitueelYaml(t *testing.T) {
	_ = refuseSettings(t, personalPerson+"aws_kms:\n  account: \"111122223333\"\n  region: eu-west-1\n  replica_region: eu-central-1\n  admin_role: arn:aws:iam::111122223333:role/a\n  ceremony_role: arn:aws:iam::111122223333:role/b\n", 10, "aws_kms is not allowed in a personal bundle")
	_ = refuseSettings(t, personalPerson+"keyring:\n  license: CC0-1.0\n", 10, "keyring is not allowed in a personal bundle")
	_ = refuseSettings(t, strings.Replace(personalPerson, "Ada Example", `"Ada Example "`, 1), 3, "person.name has no space at the end")
	_ = refuseSettings(t, strings.Replace(personalPerson, "Ada Example", `"Ada  Example"`, 1), 3, "person.name has no two spaces in a row")
}

// personalFiles is a bundle whose files pass their readers: the person, the root, one card and two delegations.
type personalFiles struct {
	root, person, card string
	delegations        map[string]string
	userIDs            string
}

func newPersonalFiles() personalFiles {
	return personalFiles{
		root: personalOpenPGP, person: personalPerson, card: personalCard,
		delegations: map[string]string{
			"daily": personalSign,
			"ssh":   strings.Replace(personalSign, "capability: sign", "capability: authenticate", 1),
		},
	}
}

// check reads the files with their readers and runs CheckPersonal on them.
func (f personalFiles) check(t *testing.T, now time.Time) error {
	t.Helper()
	s := mustSettings(t, f.person)
	var roots []*wanted.Root
	if f.root != "" {
		roots = append(roots, mustRoot(t, "openpgp", f.root))
	}
	var ds []*wanted.Delegation
	for _, name := range slices.Sorted(func(yield func(string) bool) {
		for k := range f.delegations {
			if !yield(k) {
				return
			}
		}
	}) {
		d, err := wanted.ParseDelegation(name, []byte(f.delegations[name]), s)
		if err != nil {
			t.Fatalf("delegation %s: %v", name, err)
		}
		ds = append(ds, d)
	}
	var cards []*wanted.Card
	if f.card != "" {
		cards = append(cards, mustCard(t, "day-ana", f.card))
	}
	var ids *wanted.UserIDs
	if f.userIDs != "" {
		var err error
		if ids, err = wanted.ParseUserIDs([]byte(f.userIDs)); err != nil {
			t.Fatal(err)
		}
	}
	return wanted.CheckPersonal(s, roots, ds, cards, ids, now)
}

func TestTheFilesOfAPersonAreJudgedAgainstEachOther(t *testing.T) {
	if err := newPersonalFiles().check(t, personalNow); err != nil {
		t.Fatalf("the files of the example: %v", err)
	}
	type edit = func(*personalFiles)
	for name, tc := range map[string]struct {
		path  string
		words []string
		edit  edit
	}{
		"no root":         {"want/roots", []string{"needs one root file of the kind openpgp"}, func(f *personalFiles) { f.root = "" }},
		"no encryption":   {"want/roots/openpgp.yaml", []string{"needs the member encryption"}, func(f *personalFiles) { f.root = strings.Replace(f.root, "encryption: true\n", "", 1) }},
		"no keys":         {"want/roots/openpgp.yaml", []string{"needs the member keys"}, func(f *personalFiles) { f.root = "version: 1\nkind: openpgp\nencryption: true\n" }},
		"a key that ends": {"want/roots/openpgp.yaml", []string{"keys[1]", "not after now"}, func(f *personalFiles) { f.root = strings.Replace(f.root, "2029-11-26", "2026-11-26", 1) }},
		"a key too long":  {"want/roots/openpgp.yaml", []string{"keys[1]", "more than 36 months"}, func(f *personalFiles) { f.root = strings.Replace(f.root, "2029-11-26", "2030-01-01", 1) }},
		"an x509 root":    {"want/roots/openpgp.yaml", []string{"no root of the kind x509"}, func(f *personalFiles) { f.root = "version: 1\nkind: x509\n" }},
		"an ssh root":     {"want/roots/openpgp.yaml", []string{"no root of the kind ssh"}, func(f *personalFiles) { f.root = "version: 1\nkind: ssh\n" }},
		"a delegation under another root": {"want/delegations/daily.yaml", []string{"under the root other"}, func(f *personalFiles) {
			f.delegations["daily"] = strings.Replace(personalSign, "root: openpgp", "root: other", 1)
		}},
		"an unknown card": {"want/delegations/daily.yaml", []string{"the card day-bob has no card file"}, func(f *personalFiles) {
			f.delegations["daily"] = strings.Replace(personalSign, "day-ana", "day-bob", 1)
		}},
		"a card of the wrong kind": {"want/delegations/daily.yaml", []string{"is of the kind root"}, func(f *personalFiles) { f.card = strings.Replace(f.card, "day-to-day", "root", 1) }},
		"a server card":            {"want/delegations/daily.yaml", []string{"is of the kind server"}, func(f *personalFiles) { f.card = strings.Replace(f.card, "day-to-day", "server", 1) }},
		"a rehearsal card, no test root": {"want/delegations/daily.yaml", []string{"is of the kind rehearsal", "only for a test root"}, func(f *personalFiles) {
			f.card = strings.Replace(f.card, "day-to-day", "rehearsal", 1)
		}},
		"a card without openpgp": {"want/delegations/daily.yaml", []string{"does not list the application openpgp"}, func(f *personalFiles) { f.card = strings.Replace(f.card, "[openpgp]", "[piv, fido2]", 1) }},
		"the pair twice": {"want/delegations/ssh.yaml", []string{"the capability sign in the delegation daily already"}, func(f *personalFiles) {
			f.delegations["ssh"] = personalSign
		}},
		"the person written again": {"want/openpgp.yaml", []string{"user_ids[1]", "always the primary user ID"}, func(f *personalFiles) {
			f.userIDs = "version: 1\nuser_ids:\n  - {name: Ada Example, address: ADA@example.com}\n"
		}},
		"the person retired": {"want/openpgp.yaml", []string{"user_ids[2]", "cannot be retired here"}, func(f *personalFiles) {
			f.userIDs = "version: 1\nuser_ids:\n  - {name: Ada, address: ada@example.com}\n  - {name: Ada Example, address: ada@example.com, retire: true}\n"
		}},
	} {
		t.Run(name, func(t *testing.T) {
			f := newPersonalFiles()
			tc.edit(&f)
			_ = wantFault(t, f.check(t, personalNow), tc.path, -1, tc.words...)
		})
	}
	// What is accepted: a rehearsal card for a test root, a further user ID, no delegation, the same card for two
	// capabilities, and a card that no delegation names.
	for name, edit := range map[string]func(*personalFiles){
		"a rehearsal card of a test root": func(f *personalFiles) {
			f.card = strings.Replace(f.card, "day-to-day", "rehearsal", 1)
			f.root = strings.Replace(f.root, "kind: openpgp\n", "kind: openpgp\ntest: true\n", 1)
		},
		"user IDs": func(f *personalFiles) {
			f.userIDs = "version: 1\nuser_ids:\n  - {name: Ada Example, address: ada@example.org}\n"
		},
		"no delegation": func(f *personalFiles) { f.delegations = nil },
		"no card":       func(f *personalFiles) { f.card, f.delegations = "", nil },
	} {
		f := newPersonalFiles()
		edit(&f)
		if err := f.check(t, personalNow); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Two roots, and more than 16 delegations.
	s := mustPersonal(t)
	a, b := mustRoot(t, "openpgp", personalOpenPGP), mustRoot(t, "other", personalOpenPGP)
	_ = wantFault(t, wanted.CheckPersonal(s, []*wanted.Root{a, b}, nil, nil, nil, personalNow), "want/roots/other.yaml", -1, "has one root", "second root file")
	var many []*wanted.Delegation
	for range wanted.MaxPersonalDelegations + 1 {
		many = append(many, mustDelegationFor(t, s))
	}
	_ = wantFault(t, wanted.CheckPersonal(s, []*wanted.Root{a}, many, nil, nil, personalNow), "want/delegations", -1, "at most 16 delegation files")
	// A value that a reader did not make is refused.
	_ = wantFault(t, wanted.CheckPersonal(mustSettings(t, goodSettings), []*wanted.Root{a}, nil, nil, nil, personalNow), "ritueel.yaml", -1, "personal bundle")
	_ = wantFault(t, wanted.CheckPersonal(s, []*wanted.Root{{}}, nil, nil, nil, personalNow), "want/roots", -1, "not made by the reader")
	// A delegation of another type, built by the reader without its root, is refused.
	x509 := mustDelegation(t, "x", goodX509Delegation)
	_ = wantFault(t, wanted.CheckPersonal(s, []*wanted.Root{a}, []*wanted.Delegation{x509}, nil, nil, personalNow), "want/delegations/x.yaml", -1, "delegations of the type openpgp-subkey only")
}

func mustDelegationFor(t testing.TB, s *wanted.Settings) *wanted.Delegation {
	t.Helper()
	d, err := wanted.ParseDelegation("daily", []byte(personalSign), s)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestTheKeysAndTheEncryptionOfAPersonAreNotACompanysRoot(t *testing.T) {
	company := mustRoot(t, "openpgp", "version: 1\nkind: openpgp\nrevocation_reasons: [retired]\n")
	if err := wanted.CheckCompanyRoots([]*wanted.Root{company, mustRoot(t, "x509", goodRoot)}); err != nil {
		t.Errorf("a company root: %v", err)
	}
	_ = wantFault(t, wanted.CheckCompanyRoots([]*wanted.Root{mustRoot(t, "openpgp", personalOpenPGP)}), "want/roots/openpgp.yaml", -1, "personal bundle")
	_ = wantFault(t, wanted.CheckCompanyRoots([]*wanted.Root{mustRoot(t, "openpgp", "version: 1\nkind: openpgp\nencryption: false\n")}), "want/roots/openpgp.yaml", -1, "personal bundle")
}
