package wanted_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/wanted"
)

// One table for each kind of file of a person. A row is the smallest edit of a file that passes its reader that
// breaks exactly one rule, the file, the line and the words of the problem it names, and the neighbour: the same
// edit that keeps the rule, which must pass. A hostile value is written as a YAML escape and must never reach a
// message as anything but printable ASCII.

const (
	rootFile = "want/roots/openpgp.yaml"
	keyLine  = 6
	idsHead  = "version: 1\nuser_ids:\n"
	idsBase  = idsHead + "  - {name: Ada Example, address: ada@example.org}\n"
)

// swap changes the first occurrence of old in base and fails the test when there is none, so that a row cannot
// quietly stop changing anything.
func swap(t testing.TB, base, old, repl string) string {
	t.Helper()
	if !strings.Contains(base, old) {
		t.Fatalf("the text %q is not in the starting file", old)
	}
	return strings.Replace(base, old, repl, 1)
}

// addressOf is an address of n characters: a local part of letters, an at sign and example.org.
func addressOf(n int) string { return strings.Repeat("a", n-len("@example.org")) + "@example.org" }

type refusalRow struct {
	name  string
	bad   string // the text that breaks exactly one rule
	good  string // the same text with the rule kept; "" when no neighbour applies
	line  int
	words []string
}

func runRefusals(t *testing.T, path string, parse func(string) error, rows []refusalRow) {
	t.Helper()
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			err := parse(r.bad)
			_ = wantFault(t, err, path, r.line, r.words...)
			if r.good != "" {
				if err := parse(r.good); err != nil {
					t.Errorf("the neighbour of the row is refused: %v", err)
				}
			}
		})
	}
}

func parseRoot(text string) error {
	r, err := wanted.ParseRoot("openpgp", []byte(text))
	if (r == nil) == (err == nil) {
		return fmt.Errorf("a value and an error together or neither: %v %v", r, err)
	}
	return err
}

func parseIDs(text string) error {
	u, err := wanted.ParseUserIDs([]byte(text))
	if (u == nil) == (err == nil) {
		return fmt.Errorf("a value and an error together or neither: %v %v", u, err)
	}
	return err
}

func TestTheRulesOfTheKeysOfARootEachBreakAlone(t *testing.T) {
	const fp = adoptedFP
	rep := func(old, repl string) string { return swap(t, personalOpenPGP, old, repl) }
	keyList := func(entries ...string) string {
		return "version: 1\nkind: openpgp\nencryption: true\nkeys:\n" + strings.Join(entries, "")
	}
	entry := func(label, fingerprint string) string {
		return "  - {label: " + label + ", role: adopted, fingerprint: \"" + fingerprint + "\", valid_until: \"2029-11-26\"}\n"
	}
	rows := []refusalRow{
		// The count of the entries is judged before the first entry is read.
		{"keys with no value", rep(adoptedLine, ""), "", 5, []string{"a null or an empty value"}},
		{"no entry", rep("keys:\n"+adoptedLine, "keys: []\n"), "", 5, []string{"keys must hold 1 to 8 entries"}},
		{"nine entries that are each no key", keyList(strings.Repeat("  - {label: a}\n", 9)), keyList(entry("A", fp)), 5, []string{"keys must hold 1 to 8 entries"}},
		// The reading of the first entry: 8 entries is no count fault, and the first entry's fault is named.
		{"eight entries, the first is no key", keyList(strings.Repeat("  - {label: a}\n", 8)), "", 5, []string{"keys[1].role is required"}},
		// The label.
		{"label a", rep("label: A", "label: a"), rep("label: A", "label: Z"), keyLine, []string{"keys[1].label is one letter from A to Z"}},
		{"label AB", rep("label: A", "label: AB"), "", keyLine, []string{"keys[1].label is one letter from A to Z"}},
		{"label empty", rep("label: A", `label: ""`), "", keyLine, []string{"keys[1].label is one letter from A to Z"}},
		{"label the character after Z", rep("label: A", `label: "["`), "", keyLine, []string{"keys[1].label is one letter from A to Z"}},
		{"label the character before A", rep("label: A", `label: "@"`), "", keyLine, []string{"keys[1].label is one letter from A to Z"}},
		{"label a full-width A", rep("label: A", `label: "Ａ"`), "", keyLine, []string{"keys[1].label is one letter from A to Z"}},
		{"label with a space", rep("label: A", `label: "A "`), "", keyLine, []string{"keys[1].label is one letter from A to Z"}},
		{"label a number", rep("label: A", "label: 1"), "", keyLine, []string{"keys[1].label must be a string"}},
		// The role.
		{"role Adopted", rep("role: adopted", "role: Adopted"), "", keyLine, []string{"keys[1].role must be adopted"}},
		{"role ADOPTED", rep("role: adopted", "role: ADOPTED"), "", keyLine, []string{"keys[1].role must be adopted"}},
		{"role with a space", rep("role: adopted", `role: "adopted "`), "", keyLine, []string{"keys[1].role must be adopted"}},
		{"role empty", rep("role: adopted", `role: ""`), "", keyLine, []string{"keys[1].role must be adopted"}},
		{"role published", rep("role: adopted", "role: published"), "", keyLine, []string{"keys[1].role published is reserved for stage two, which is not built yet"}},
		{"role standby", rep("role: adopted", "role: standby"), "", keyLine, []string{"keys[1].role standby is reserved for stage two, which is not built yet"}},
		{"role a boolean", rep("role: adopted", "role: true"), "", keyLine, []string{"keys[1].role must be a string"}},
		// The fingerprint.
		{"fingerprint of 39", rep(fp, fp[1:]), "", keyLine, []string{"keys[1].fingerprint is 40 hexadecimal digits"}},
		{"fingerprint of 41", rep(fp, fp+"a"), "", keyLine, []string{"keys[1].fingerprint is 40 hexadecimal digits"}},
		{"fingerprint empty", rep(`"`+fp+`"`, `""`), "", keyLine, []string{"keys[1].fingerprint is 40 hexadecimal digits"}},
		{"fingerprint with 0x", rep(fp, "0x"+fp[2:]), "", keyLine, []string{"keys[1].fingerprint is 40 hexadecimal digits"}},
		{"fingerprint with a colon", rep(fp, fp[:38]+":a"), "", keyLine, []string{"keys[1].fingerprint is 40 hexadecimal digits"}},
		{"fingerprint with a trailing space", rep(fp, fp[:39]+" "), "", keyLine, []string{"keys[1].fingerprint is 40 hexadecimal digits"}},
		{"fingerprint of full-width digits", rep(fp, strings.Repeat("１", 40)), "", keyLine, []string{"keys[1].fingerprint is 40 hexadecimal digits"}},
		{"fingerprint of digits only, unquoted", rep(`"`+fp+`"`, strings.Repeat("1", 40)), rep(`"`+fp+`"`, `"`+strings.Repeat("1", 40)+`"`), keyLine, []string{"keys[1].fingerprint must be a string: write it in quotes"}},
		{"fingerprint of a short number, unquoted", rep(`"`+fp+`"`, "1234"), "", keyLine, []string{"keys[1].fingerprint must be a string: write it in quotes"}},
		{"the placeholder", rep(fp, wanted.PlaceholderFingerprint), "", keyLine, []string{"replace the placeholder with the fingerprint of your key"}},
		{"the fingerprint of the examples", rep(fp, wanted.ExampleFingerprint), "", keyLine, []string{"is the fingerprint of the examples: replace it with the fingerprint of your key"}},
		{"the fingerprint of the examples in upper case", rep(fp, strings.ToUpper(wanted.ExampleFingerprint)), rep(fp, strings.ToUpper(fp)), keyLine, []string{"is the fingerprint of the examples"}},
		// The day.
		{"valid_until unquoted", rep(`"2029-11-26"`, "2029-11-26"), rep(`"2029-11-26"`, `"2029-11-26"`), keyLine, []string{"keys[1].valid_until must be a string: write it in quotes"}},
		{"valid_until an integer", rep(`"2029-11-26"`, "20291126"), "", keyLine, []string{"keys[1].valid_until must be a string: write it in quotes"}},
		{"valid_until with a time", rep("2029-11-26", "2029-11-26T00:00:00Z"), "", keyLine, []string{"keys[1].valid_until is a date written"}},
		{"valid_until with a trailing space", rep("2029-11-26", "2029-11-26 "), "", keyLine, []string{"keys[1].valid_until is a date written"}},
		{"valid_until with a sign", rep("2029-11-26", "+029-11-26"), "", keyLine, []string{"keys[1].valid_until is a date written"}},
		{"valid_until with dots", rep("2029-11-26", "2029.11.26"), "", keyLine, []string{"keys[1].valid_until is a date written"}},
		{"valid_until of full-width digits", rep("2029-11-26", "２０２９-11-26"), "", keyLine, []string{"keys[1].valid_until is a date written"}},
		{"year 1999", rep("2029-11-26", "1999-12-31"), rep("2029-11-26", "2000-01-01"), keyLine, []string{"keys[1].valid_until has a year from 2000 to 2105"}},
		{"year 2106", rep("2029-11-26", "2106-01-01"), rep("2029-11-26", "2105-12-31"), keyLine, []string{"keys[1].valid_until has a year from 2000 to 2105"}},
		{"month 00", rep("2029-11-26", "2029-00-26"), "", keyLine, []string{"keys[1].valid_until is not a day of the calendar"}},
		{"month 13", rep("2029-11-26", "2029-13-26"), "", keyLine, []string{"keys[1].valid_until is not a day of the calendar"}},
		{"day 00", rep("2029-11-26", "2029-11-00"), "", keyLine, []string{"keys[1].valid_until is not a day of the calendar"}},
		{"day 31 of November", rep("2029-11-26", "2029-11-31"), rep("2029-11-26", "2029-11-30"), keyLine, []string{"keys[1].valid_until is not a day of the calendar"}},
		{"the 29th of February in a year that is not a leap year", rep("2029-11-26", "2029-02-29"), rep("2029-11-26", "2028-02-29"), keyLine, []string{"keys[1].valid_until is not a day of the calendar"}},
		{"the 29th of February in 2100", rep("2029-11-26", "2100-02-29"), rep("2029-11-26", "2000-02-29"), keyLine, []string{"keys[1].valid_until is not a day of the calendar"}},
		// The members of a key.
		{"no label", rep("label: A, ", ""), "", keyLine, []string{"the member keys[1].label"}},
		{"an unknown member", rep("role: adopted", "role: adopted, colour: red"), "", keyLine, []string{`keys[1]: the member "colour" is not known`}},
		{"a reserved member in another case", rep("role: adopted", "role: adopted, Card: day-ana"), "", keyLine, []string{`keys[1]: the member "Card" is not known`}},
		{"a reserved word as the key of a nested map", rep(`valid_until: "2029-11-26"`, `valid_until: {card: x}`), "", keyLine, []string{"keys[1].valid_until must be a string"}},
		{"a reserved word as the key of a nested map of the label", rep("label: A", "label: {replaces: x}"), "", keyLine, []string{"keys[1].label must be a string"}},
		{"a reserved word as the key of a nested map of keys", rep("keys:\n"+adoptedLine, "keys: {card: x}\n"), "", 5, []string{"keys must be a list"}},
		{"an entry that is a list", rep(adoptedLine, "  - [A, adopted]\n"), "", keyLine, []string{"keys[1] must be a mapping"}},
		// Two keys.
		{"a label twice", keyList(entry("A", fp), entry("A", fp[:39]+"9")), keyList(entry("A", fp)), 6, []string{"keys[2].label is used twice"}},
		{"a fingerprint twice, in another case", keyList(entry("A", fp), entry("B", strings.ToUpper(fp))), "", 6, []string{"keys[2].fingerprint is the fingerprint of an earlier key"}},
		{"the role adopted twice", keyList(entry("A", fp), entry("B", fp[:39]+"9")), "", 6, []string{"keys[2].role adopted is used twice"}},
		{"a second key that is reserved is named by its role", keyList(entry("A", fp), "  - {label: B, role: standby}\n"), "", 6, []string{"keys[2].role standby is reserved for stage two"}},
	}
	// Every reserved member of a key is refused by name, whatever its value, and its value is not read.
	for _, member := range []string{"card", "replaces", "overlap_until", "retire_on", "retire_reason"} {
		for _, value := range []string{"x", "[1, 2]", "{a: b}", `"a\U0000202eb"`, "2029-01-01", "true"} {
			rows = append(rows, refusalRow{
				"the member " + member + ": " + value,
				rep("role: adopted", "role: adopted, "+member+": "+value), "", keyLine,
				[]string{"keys[1]: the member " + member + " is reserved for stage two, which is not built yet; remove it"},
			})
		}
	}
	runRefusals(t, rootFile, parseRoot, rows)
}

func TestTheOtherMembersOfAPersonsRootEachBreakAlone(t *testing.T) {
	rep := func(old, repl string) string { return swap(t, personalOpenPGP, old, repl) }
	rows := []refusalRow{
		{"encryption a string", rep("encryption: true", `encryption: "true"`), rep("encryption: true", "encryption: false"), 3, []string{"encryption must be true or false"}},
		{"encryption yes", rep("encryption: true", "encryption: yes"), "", 3, []string{"encryption must be true or false"}},
		{"encryption on", rep("encryption: true", "encryption: on"), "", 3, []string{"encryption must be true or false"}},
		{"encryption True", rep("encryption: true", "encryption: True"), "", 3, []string{"encryption must be true or false"}},
		{"encryption TRUE", rep("encryption: true", "encryption: TRUE"), "", 3, []string{"encryption must be true or false"}},
		{"encryption 1", rep("encryption: true", "encryption: 1"), "", 3, []string{"encryption must be true or false"}},
		{"encryption a list", rep("encryption: true", "encryption: [true]"), "", 3, []string{"encryption must be true or false"}},
		{"encryption a map", rep("encryption: true", "encryption: {a: true}"), "", 3, []string{"encryption must be true or false"}},
		{"encryption null", rep("encryption: true", "encryption: null"), "", 3, []string{"null"}},
		{"encryption empty", rep("encryption: true", "encryption:"), "", 3, []string{"null"}},
		{"Encryption in another case", rep("encryption: true", "Encryption: true"), "", 3, []string{`the member "Encryption" is not read yet`}},
		{"Keys in another case", rep("keys:", "Keys:"), "", 5, []string{`the member "Keys" is not read yet`}},
		{"a reserved word at the top", rep("keys:", "card: x\nkeys:"), "", 5, []string{`the member "card" is not read yet`}},
		{"a reserved word at the top, in a nested map", rep("revocation_reasons: [retired]", "revocation_reasons: {card: x}"), "", 4, []string{"revocation_reasons must be a list"}},
		{"five reasons", rep("[retired]", "[compromised, superseded, retired, no-reason, retired]"), rep("[retired]", "[compromised, superseded, retired, no-reason]"), 4, []string{"revocation_reasons holds more than 4 words"}},
		{"a reason that is no reason", rep("[retired]", "[lost]"), "", 4, []string{"revocation_reasons entry 1 is \"lost\", and it must be one of"}},
		{"a reason in another case", rep("[retired]", "[Retired]"), "", 4, []string{"revocation_reasons entry 1"}},
		{"a reason twice", rep("[retired]", "[retired, retired]"), "", 4, []string{"revocation_reasons entry 2 repeats an earlier entry"}},
		{"a reason that is a number", rep("[retired]", "[1]"), "", 4, []string{"revocation_reasons entry 1 must be a string"}},
		{"a reason that is a map", rep("[retired]", "[{a: b}]"), "", 4, []string{"revocation_reasons entry 1 must be a string"}},
		{"reasons not a list", rep("[retired]", "retired"), rep("[retired]", "[retired]"), 4, []string{"revocation_reasons must be a list"}},
		{"keys in a file of the kind x509", "version: 1\nkind: x509\n" + swap(t, personalOpenPGP, "version: 1\nkind: openpgp\n", ""), "", 4, []string{"the member revocation_reasons is for the OpenPGP root file (kind: openpgp) only"}},
		{"keys in a file of the kind ssh", "version: 1\nkind: ssh\nkeys: []\n", "", 3, []string{"the member keys is for the OpenPGP root file (kind: openpgp) only"}},
		{"the kind in upper case", rep("kind: openpgp", "kind: OpenPGP"), "", 2, []string{"kind must be one of x509, openpgp, ssh"}},
	}
	runRefusals(t, rootFile, parseRoot, rows)
}

func TestTheRulesOfTheFurtherUserIDsEachBreakAlone(t *testing.T) {
	rep := func(old, repl string) string { return swap(t, idsBase, old, repl) }
	manyEntries := func(n int, retire bool) string {
		var b strings.Builder
		b.WriteString(idsHead)
		for i := range n {
			fmt.Fprintf(&b, "  - {name: Ada, address: u%d@example.org, retire: %v}\n", i, retire)
		}
		return b.String()
	}
	mixed := func(active, retired int) string {
		var b strings.Builder
		b.WriteString(idsHead)
		for i := range active + retired {
			fmt.Fprintf(&b, "  - {name: Ada, address: u%d@example.org, retire: %v}\n", i, i >= active)
		}
		return b.String()
	}
	rows := []refusalRow{
		// The name.
		{"name of 65 characters", rep("Ada Example", strings.Repeat("a", 65)), rep("Ada Example", strings.Repeat("a", 64)), 3, []string{"user_ids[1].name has 1 to 64 characters"}},
		{"name empty", rep("Ada Example", `""`), "", 3, []string{"user_ids[1].name has 1 to 64 characters"}},
		{"name starts with a space", rep("Ada Example", `" Ada"`), "", 3, []string{"user_ids[1].name has 1 to 64 characters"}},
		{"name starts with a hyphen", rep("Ada Example", "-Ada"), rep("Ada Example", "A-da"), 3, []string{"user_ids[1].name has 1 to 64 characters"}},
		{"name ends with a space", rep("Ada Example", `"Ada "`), "", 3, []string{"user_ids[1].name has no space at the end"}},
		{"name with two spaces", rep("Ada Example", `"Ada  B"`), rep("Ada Example", `"Ada B"`), 3, []string{"user_ids[1].name has no two spaces in a row"}},
		{"name with a comma", rep("Ada Example", `"Ada, B"`), "", 3, []string{"user_ids[1].name has 1 to 64 characters"}},
		{"name with an angle bracket", rep("Ada Example", `"Ada <B"`), "", 3, []string{"user_ids[1].name has 1 to 64 characters"}},
		{"name with a parenthesis", rep("Ada Example", `"Ada (B)"`), "", 3, []string{"user_ids[1].name has 1 to 64 characters"}},
		{"name with a quote", rep("Ada Example", `"Ada \"B\""`), "", 3, []string{"user_ids[1].name has 1 to 64 characters"}},
		{"name with an at sign", rep("Ada Example", `"a@b"`), "", 3, []string{"user_ids[1].name has 1 to 64 characters"}},
		{"name with a non-ASCII letter", rep("Ada Example", `"Ad\U000000e1"`), "", 3, []string{"user_ids[1].name has 1 to 64 characters"}},
		{"name that is a number", rep("Ada Example", "1234"), rep("Ada Example", `"1234"`), 3, []string{"user_ids[1].name must be a string"}},
		{"name that is a boolean", rep("Ada Example", "true"), "", 3, []string{"user_ids[1].name must be a string"}},
		{"name that is a list", rep("Ada Example", "[Ada]"), "", 3, []string{"user_ids[1].name must be a string"}},
		// The address: the one rule of every address.
		{"address of 255", rep("ada@example.org", addressOf(255)), rep("ada@example.org", addressOf(254)), 3, []string{"user_ids[1].address has 1 to 254 characters"}},
		{"address empty", rep("ada@example.org", `""`), "", 3, []string{"user_ids[1].address has 1 to 254 characters"}},
		{"address with two at signs", rep("ada@example.org", `"\"a@b\"@example.org"`), "", 3, []string{"user_ids[1].address is one bare address"}},
		{"address with no at sign", rep("ada@example.org", "example.org"), "", 3, []string{"user_ids[1].address is one bare address"}},
		{"address with an open bracket", rep("ada@example.org", `"ada@[127.0.0.1"`), "", 3, []string{"user_ids[1].address is one bare address"}},
		{"address with a close bracket", rep("ada@example.org", `"ada]@example.org"`), "", 3, []string{"user_ids[1].address is one bare address"}},
		{"address that is a domain literal", rep("ada@example.org", `"ada@[127.0.0.1]"`), "", 3, []string{"user_ids[1].address is one bare address"}},
		{"address with an angle bracket", rep("ada@example.org", `"ada@example.org>"`), "", 3, []string{"user_ids[1].address is one bare address"}},
		{"address with a display name", rep("ada@example.org", `"Ada<ada@example.org>"`), "", 3, []string{"user_ids[1].address is one bare address"}},
		{"address with a space", rep("ada@example.org", `"a da@example.org"`), "", 3, []string{"user_ids[1].address is printable ASCII with no space"}},
		{"address with a non-ASCII letter", rep("ada@example.org", `"ada@exampl\U000000e9.org"`), "", 3, []string{"user_ids[1].address is printable ASCII with no space"}},
		{"address that is a number", rep("ada@example.org", "1234"), "", 3, []string{"user_ids[1].address must be a string"}},
		// The members.
		{"retire as a string", rep("address: ada@example.org", `address: ada@example.org, retire: "true"`), rep("address: ada@example.org", "address: ada@example.org, retire: true"), 3, []string{"retire must be true or false"}},
		{"retire yes", rep("address: ada@example.org", "address: ada@example.org, retire: yes"), "", 3, []string{"retire must be true or false"}},
		{"a member primary", rep("address: ada@example.org", "address: ada@example.org, primary: true"), "", 3, []string{`user_ids[1]: the member "primary" is not known`}},
		{"a member Retire in another case", rep("address: ada@example.org", "address: ada@example.org, Retire: true"), "", 3, []string{`user_ids[1]: the member "Retire" is not known`}},
		{"user_ids in another case", rep("user_ids:", "User_IDs:"), "", 2, []string{`the member "User_IDs" is not known`}},
		{"no version", rep("version: 1\n", ""), "", -1, []string{"version", "required"}},
		{"version 2", rep("version: 1", "version: 2"), "", 1, []string{"version must be 1"}},
		{"version in quotes", rep("version: 1", `version: "1"`), "", 1, []string{"version must be an integer"}},
		{"a reserved word as the key of a nested map", rep("{name: Ada Example, address: ada@example.org}", "{name: {card: x}, address: ada@example.org}"), "", 3, []string{"user_ids[1].name must be a string"}},
		// Counts and sameness.
		{"17 entries", manyEntries(17, true), manyEntries(16, true), 3, []string{"user_ids must hold at most 16 entries"}},
		{"17 entries that are no entry", idsHead + strings.Repeat("  - x\n", 17), "", 3, []string{"user_ids must hold at most 16 entries"}},
		{"9 entries that are not retired", manyEntries(9, false), manyEntries(8, false), 11, []string{"user_ids holds more than 8 user IDs that are not retired"}},
		{"9 not retired among 16", mixed(9, 7), mixed(8, 8), 11, []string{"user_ids holds more than 8 user IDs that are not retired"}},
		{"a user ID twice", idsBase + "  - {name: Ada Example, address: ada@example.org, retire: true}\n", idsBase + "  - {name: Ada Example, address: ada2@example.org}\n", 4, []string{"user_ids[2] is a user ID that an earlier entry has"}},
		{"a user ID twice, the name in another case", idsBase + "  - {name: ADA EXAMPLE, address: ada@example.org}\n", "", 4, []string{"user_ids[2] is a user ID that an earlier entry has"}},
		{"a user ID twice, the address in another case", idsBase + "  - {name: Ada Example, address: ADA@EXAMPLE.ORG}\n", "", 4, []string{"user_ids[2] is a user ID that an earlier entry has"}},
		{"user_ids a map", rep(idsBase[len(idsHead):], "  a: b\n"), "", 3, []string{"user_ids must be a list"}},
	}
	runRefusals(t, wanted.UserIDsPath, parseIDs, rows)
}

func TestTheEdgesThatPass(t *testing.T) {
	// Sixteen user IDs with eight active, the longest name and the longest address.
	var b strings.Builder
	b.WriteString(idsHead)
	for i := range wanted.MaxUserIDs {
		fmt.Fprintf(&b, "  - {name: Ada, address: u%d@example.org, retire: %v}\n", i, i >= wanted.MaxActiveUserIDs)
	}
	ids, err := wanted.ParseUserIDs([]byte(b.String()))
	if err != nil {
		t.Fatalf("16 entries, 8 active: %v", err)
	}
	if got := ids.Entries(); len(got) != 16 || got[7].Retire || !got[8].Retire {
		t.Errorf("entries %+v", got)
	}
	long := idsHead + "  - {name: " + strings.Repeat("N", 64) + ", address: " + addressOf(254) + "}\n"
	ids, err = wanted.ParseUserIDs([]byte(long))
	if err != nil {
		t.Fatalf("a name of 64 and an address of 254: %v", err)
	}
	if e := ids.Entries()[0]; len(e.Name) != 64 || len(e.Address) != 254 || len(e.Name)+len(e.Address)+3 > 1024 {
		t.Errorf("entry %+v", e)
	}
	// The person of ritueel.yaml has the same limits.
	person := swap(t, swap(t, personalPerson, "Ben Example", strings.Repeat("N", 64)), "ben@example.com", addressOf(254))
	if s := mustSettings(t, person); len(s.Person.Name) != 64 || len(s.Person.Address) != 254 {
		t.Errorf("person %+v", s.Person)
	}
	_ = refuseSettings(t, swap(t, personalPerson, "Ben Example", strings.Repeat("N", 65)), 3, "person.name has 1 to 64 characters")
	_ = refuseSettings(t, swap(t, personalPerson, "ben@example.com", addressOf(255)), 3, "person.address has 1 to 254 characters")
	// Keys: the label Z, the label A, a day at each edge of the years.
	for _, label := range []string{"A", "Z"} {
		for _, day := range []string{"2000-01-01", "2105-12-31", "2029-11-26"} {
			r := mustRoot(t, "openpgp", swap(t, swap(t, personalOpenPGP, "label: A", "label: "+label), "2029-11-26", day))
			if k := r.Keys(); len(k) != 1 || k[0].Label != label || k[0].ValidUntil.String() != day {
				t.Errorf("keys %+v", k)
			}
		}
	}
	// A fingerprint in either case is read, and kept in lower case.
	for _, fp := range []string{strings.ToUpper(adoptedFP), adoptedFP[:20] + strings.ToUpper(adoptedFP[20:])} {
		if k := mustRoot(t, "openpgp", swap(t, personalOpenPGP, adoptedFP, fp)).Keys()[0]; k.Fingerprint != adoptedFP {
			t.Errorf("fingerprint %q", k.Fingerprint)
		}
	}
	// Every spelling of the reasons that the page lists, and the list of all four.
	for _, reasons := range []string{"[]", "[no-reason]", "[compromised, superseded, retired, no-reason]"} {
		mustRoot(t, "openpgp", swap(t, personalOpenPGP, "[retired]", reasons))
	}
}

// The text of an error holds only printable ASCII, whatever the file held, and a long value is cut.
func TestAHostileValueIsNeverEchoedRaw(t *testing.T) {
	hostile := map[string]string{
		"a right-to-left override": `a\U0000202eb`, "an escape": `a\x1bb`, "a left-to-right isolate": `a\U00002066b`,
		"a zero-width space": `a\U0000200bb`, "a byte order mark": `a\U0000feffb`, "a tab": `a\tb`, "a newline": `a\nb`,
		"a carriage return": `a\rb`, "a next line": `a\U00000085b`, "a line separator": `a\U00002028b`, "a nul": `a\x00b`,
		"a delete": `a\x7fb`, "an accented letter": `a\U000000e9b`, "a bell": `a\ab`, "an astral character": `a\U0001F600b`,
		"a long value with a control": strings.Repeat("x", 300) + `\U0000202e`,
	}
	type carrier struct {
		name  string
		build func(v string) string
		parse func(text string) error
	}
	settings := func(text string) error { _, err := wanted.ParseSettings(wanted.SettingsPath, []byte(text)); return err }
	delegation := func(text string) error {
		_, err := wanted.ParseDelegation("daily", []byte(text), mustPersonal(t))
		return err
	}
	quoted := func(v string) string { return `"` + v + `"` }
	carriers := []carrier{
		{"person.name", func(v string) string { return swap(t, personalPerson, "Ben Example", quoted(v)) }, settings},
		{"person.address", func(v string) string { return swap(t, personalPerson, "ben@example.com", quoted(v)) }, settings},
		{"a store", func(v string) string { return swap(t, personalPerson, "[openpgp-card, software]", "["+quoted(v)+"]") }, settings},
		{"the kind of ritueel.yaml", func(v string) string { return swap(t, personalPerson, "kind: personal", "kind: "+quoted(v)) }, settings},
		{"a member of ritueel.yaml", func(v string) string { return personalPerson + quoted(v) + ": x\n" }, settings},
		{"release_address", func(v string) string { return swap(t, goodSettings, "release@example.org", quoted(v)) }, settings},
		{"the root kind", func(v string) string { return swap(t, personalOpenPGP, "kind: openpgp", "kind: "+quoted(v)) }, parseRoot},
		{"a reason", func(v string) string { return swap(t, personalOpenPGP, "[retired]", "["+quoted(v)+"]") }, parseRoot},
		{"a label", func(v string) string { return swap(t, personalOpenPGP, "label: A", "label: "+quoted(v)) }, parseRoot},
		{"a role", func(v string) string { return swap(t, personalOpenPGP, "role: adopted", "role: "+quoted(v)) }, parseRoot},
		{"a fingerprint", func(v string) string { return swap(t, personalOpenPGP, adoptedFP, v) }, parseRoot},
		{"a day", func(v string) string { return swap(t, personalOpenPGP, "2029-11-26", v) }, parseRoot},
		{"a member of a key", func(v string) string {
			return swap(t, personalOpenPGP, "role: adopted", "role: adopted, "+quoted(v)+": x")
		}, parseRoot},
		{"the value of a reserved member", func(v string) string {
			return swap(t, personalOpenPGP, "role: adopted", "role: adopted, card: "+quoted(v))
		}, parseRoot},
		{"a member of a root", func(v string) string { return personalOpenPGP + quoted(v) + ": x\n" }, parseRoot},
		{"a user ID name", func(v string) string { return swap(t, idsBase, "Ada Example", quoted(v)) }, parseIDs},
		{"a user ID address", func(v string) string { return swap(t, idsBase, "ada@example.org", quoted(v)) }, parseIDs},
		{"a member of a user ID", func(v string) string {
			return swap(t, idsBase, "address: ada@example.org", "address: ada@example.org, "+quoted(v)+": x")
		}, parseIDs},
		{"a member of the user IDs file", func(v string) string { return idsBase + quoted(v) + ": x\n" }, parseIDs},
		{"the card of a delegation", func(v string) string { return swap(t, personalSign, "day-ana", quoted(v)) }, delegation},
		{"the root of a delegation", func(v string) string { return swap(t, personalSign, "root: openpgp", "root: "+quoted(v)) }, delegation},
		{"the capability of a delegation", func(v string) string { return swap(t, personalSign, "sign", quoted(v)) }, delegation},
		{"the type of a delegation", func(v string) string { return swap(t, personalSign, "openpgp-subkey", quoted(v)) }, delegation},
		{"a member of a delegation", func(v string) string { return personalSign + quoted(v) + ": x\n" }, delegation},
	}
	for _, c := range carriers {
		for hname, v := range hostile {
			t.Run(c.name+" with "+hname, func(t *testing.T) {
				err := c.parse(c.build(v))
				if err == nil {
					t.Fatalf("a file with %s is accepted", hname)
				}
				if !printable(err.Error()) {
					t.Errorf("the text of the error is not printable ASCII: %+q", err.Error())
				}
				if strings.Contains(err.Error(), strings.Repeat("x", 60)) {
					t.Errorf("the error holds a long value uncut: %q", err.Error())
				}
				var e *wanted.Error
				if !errors.As(err, &e) || e.Msg == "" {
					t.Errorf("the error is %T %v", err, err)
				}
			})
		}
	}
}
