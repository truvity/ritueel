package wanted_test

import (
	"testing"

	"ritueel.id/ritueel/internal/wanted"
)

// The tricks of YAML, through the strict reader, into the members that a person's files added: the keys and the
// encryption switch of the root, the user IDs, the card of a delegation and the person of ritueel.yaml. Each is
// refused, and the words name the problem.

func parseDeleg(text string) error {
	d, err := wanted.ParseDelegation("daily", []byte(text), mustPersonalForTricks())
	if (d == nil) == (err == nil) {
		return errBoth
	}
	return err
}

func parsePerson(text string) error {
	s, err := wanted.ParseSettings(wanted.SettingsPath, []byte(text))
	if (s == nil) == (err == nil) {
		return errBoth
	}
	return err
}

type bothError struct{}

func (bothError) Error() string { return "a value and an error together, or neither" }

var errBoth error = bothError{}

func mustPersonalForTricks() *wanted.Settings {
	s, err := wanted.ParseSettings(wanted.SettingsPath, []byte(personalPerson))
	if err != nil {
		panic(err)
	}
	return s
}

func TestYAMLTricksInTheRootFileOfAPerson(t *testing.T) {
	rep := func(old, repl string) string { return swap(t, personalOpenPGP, old, repl) }
	const key = `{label: A, role: adopted, fingerprint: "` + adoptedFP + `", valid_until: "2029-11-26"}`
	rows := []refusalRow{
		// An anchor, an alias.
		{"an anchor on the list of keys", rep("keys:\n", "keys: &k\n"), "", 5, []string{"an anchor: a file has none"}},
		{"an anchor on an entry", rep("  - {", "  - &e {"), "", 6, []string{"an anchor"}},
		{"an anchor on the switch", rep("encryption: true", "encryption: &e true"), "", 3, []string{"an anchor"}},
		{"an anchor on a label and an alias of it", rep("label: A", "label: &l A, other: *l"), "", 6, []string{"an anchor"}},
		{"an alias with no anchor", rep("encryption: true", "encryption: *e"), "", -1, []string{"not valid YAML"}},
		{"an alias of a whole entry", "version: 1\nkind: openpgp\nencryption: true\nkeys:\n  - &k " + key + "\n  - *k\n", "", 5, []string{"an anchor"}},
		// A merge key.
		{"a merge key in an entry", rep("  - {", "  - {<<: {label: B}, "), "", 6, []string{"a merge key: a file has none"}},
		{"a merge key at the top", rep("keys:", "<<: {encryption: false}\nkeys:"), "", 5, []string{"a merge key"}},
		{"a merge of an alias", "version: 1\nkind: openpgp\nbase: &b {encryption: true}\n<<: *b\n", "", -1, []string{"anchor"}},
		// A duplicate member.
		{"encryption twice", rep("encryption: true", "encryption: true\nencryption: false"), "", 4, []string{`the key "encryption" appears twice in one mapping`}},
		{"keys twice", personalOpenPGP + "keys:\n" + adoptedLine, "", 7, []string{`the key "keys" appears twice`}},
		{"a label twice in an entry", rep("label: A", "label: A, label: B"), "", 6, []string{`the key "label" appears twice`}},
		{"a fingerprint twice in an entry", rep("role: adopted", "role: adopted, fingerprint: x"), "", 6, []string{`the key "fingerprint" appears twice`}},
		{"a reserved member twice in an entry", rep("role: adopted", "role: adopted, card: x, card: y"), "", 6, []string{`the key "card" appears twice`}},
		{"a duplicate that differs in case is two members", rep("encryption: true", "encryption: true\nEncryption: false"), "", 4, []string{`the member "Encryption" is not read yet`}},
		// A tag.
		{"a tag on the switch", rep("encryption: true", "encryption: !!bool true"), "", 3, []string{"a tag: a file has none"}},
		{"a tag on a label", rep("label: A", "label: !!str A"), "", 6, []string{"a tag"}},
		{"a tag on a fingerprint", rep(`"`+adoptedFP+`"`, "!!binary "+adoptedFP), "", 6, []string{"a tag"}},
		{"a tag on a day", rep(`"2029-11-26"`, "!!timestamp 2029-11-26"), "", 6, []string{"a tag"}},
		{"a tag on the list", rep("keys:\n", "keys: !!seq\n"), "", 5, []string{"a tag"}},
		{"a bare exclamation mark on a role", rep("role: adopted", "role: ! adopted"), "", 6, []string{"a tag"}},
		{"a local tag on a role", rep("role: adopted", "role: !adopted adopted"), "", 6, []string{"a tag"}},
		{"a tag on a reason", rep("[retired]", "[!!str retired]"), "", 4, []string{"a tag"}},
		{"a tag on an entry", rep("  - {", "  - !!map {"), "", 6, []string{"a tag"}},
		// A map or a list where a scalar is expected.
		{"a map for the label", rep("label: A", "label: {a: b}"), "", 6, []string{"keys[1].label must be a string"}},
		{"a list for the label", rep("label: A", "label: [A]"), "", 6, []string{"keys[1].label must be a string"}},
		{"a map for the role", rep("role: adopted", "role: {adopted: true}"), "", 6, []string{"keys[1].role must be a string"}},
		{"a list for the role", rep("role: adopted", "role: [adopted]"), "", 6, []string{"keys[1].role must be a string"}},
		{"a map for the fingerprint", rep(`"`+adoptedFP+`"`, "{a: b}"), "", 6, []string{"keys[1].fingerprint must be a string"}},
		{"a list for the fingerprint", rep(`"`+adoptedFP+`"`, `["`+adoptedFP+`"]`), "", 6, []string{"keys[1].fingerprint must be a string"}},
		{"a map for the day", rep(`"2029-11-26"`, "{a: b}"), "", 6, []string{"keys[1].valid_until must be a string"}},
		{"a list for the day", rep(`"2029-11-26"`, `["2029-11-26"]`), "", 6, []string{"keys[1].valid_until must be a string"}},
		{"a list for the switch", rep("encryption: true", "encryption: [true]"), "", 3, []string{"encryption must be true or false"}},
		{"a map for the switch", rep("encryption: true", "encryption: {a: true}"), "", 3, []string{"encryption must be true or false"}},
		{"a map for the kind", rep("kind: openpgp", "kind: {a: openpgp}"), "", 2, []string{"kind must be a string"}},
		{"a map for the list of keys", rep("keys:\n"+adoptedLine, "keys: {A: x}\n"), "", 5, []string{"keys must be a list"}},
		{"a string for the list of keys", rep("keys:\n"+adoptedLine, "keys: A\n"), "", 5, []string{"keys must be a list"}},
		{"a list in a list of keys", rep(adoptedLine, "  - [[A]]\n"), "", 6, []string{"keys[1] must be a mapping"}},
		// A number or a boolean where a string is expected.
		{"a number for the label", rep("label: A", "label: 1"), "", 6, []string{"keys[1].label must be a string"}},
		{"a boolean for the label", rep("label: A", "label: true"), "", 6, []string{"keys[1].label must be a string"}},
		{"yes for the role", rep("role: adopted", "role: yes"), "", 6, []string{"keys[1].role must be"}},
		{"a number for the fingerprint, 40 digits", rep(`"`+adoptedFP+`"`, "1234567890123456789012345678901234567890"), "", 6, []string{"keys[1].fingerprint must be a string: write it in quotes"}},
		{"a float for the fingerprint", rep(`"`+adoptedFP+`"`, "1.5e39"), "", 6, []string{"keys[1].fingerprint must be a string: write it in quotes"}},
		{"a hexadecimal number for the fingerprint", rep(`"`+adoptedFP+`"`, "0x"+adoptedFP), "", 6, []string{"keys[1].fingerprint"}},
		{"an unquoted date", rep(`"2029-11-26"`, "2029-11-26"), "", 6, []string{"keys[1].valid_until must be a string: write it in quotes when it looks like a number, a boolean or a date"}},
		{"an unquoted date with a time", rep(`"2029-11-26"`, "2029-11-26T00:00:00Z"), "", 6, []string{"keys[1].valid_until must be a string"}},
		{"a number for the day", rep(`"2029-11-26"`, "2029"), "", 6, []string{"keys[1].valid_until must be a string"}},
		{"encryption in quotes", rep("encryption: true", `encryption: "true"`), "", 3, []string{"encryption must be true or false"}},
		{"encryption yes", rep("encryption: true", "encryption: yes"), "", 3, []string{"encryption must be true or false"}},
		{"encryption Yes", rep("encryption: true", "encryption: Yes"), "", 3, []string{"encryption must be true or false"}},
		{"encryption y", rep("encryption: true", "encryption: y"), "", 3, []string{"encryption must be true or false"}},
		{"encryption off", rep("encryption: true", "encryption: off"), "", 3, []string{"encryption must be true or false"}},
		{"encryption 0", rep("encryption: true", "encryption: 0"), "", 3, []string{"encryption must be true or false"}},
		{"encryption as a float", rep("encryption: true", "encryption: 1.0"), "", 3, []string{"encryption must be true or false"}},
		{"a string for the version", rep("version: 1", `version: "1"`), "", 1, []string{"version must be an integer"}},
		{"a float for the version", rep("version: 1", "version: 1.0"), "", 1, []string{"version must be an integer"}},
		{"a reason that is a boolean", rep("[retired]", "[true]"), "", 4, []string{"revocation_reasons entry 1 must be a string"}},
		// A reserved word or a member in another case, and the same word as the key of a nested map.
		{"Card in an entry", rep("role: adopted", "role: adopted, Card: x"), "", 6, []string{`the member "Card" is not known`}},
		{"REPLACES in an entry", rep("role: adopted", "role: adopted, REPLACES: x"), "", 6, []string{`the member "REPLACES" is not known`}},
		{"Retire_on in an entry", rep("role: adopted", "role: adopted, Retire_On: x"), "", 6, []string{"is not known"}},
		{"Label in an entry", rep("label: A", "Label: A"), "", 6, []string{`the member "Label" is not known`}},
		{"Role in an entry", rep("role:", "Role:"), "", 6, []string{`the member "Role" is not known`}},
		{"a reserved name with a space", rep("role: adopted", `role: adopted, "card ": x`), "", 6, []string{"is not known"}},
		{"Adopted", rep("role: adopted", "role: Adopted"), "", 6, []string{"keys[1].role must be adopted"}},
		{"a role with a trailing space", rep("role: adopted", `role: "adopted "`), "", 6, []string{"keys[1].role must be adopted"}},
		{"a reserved role in another case", rep("role: adopted", "role: Published"), "", 6, []string{"keys[1].role must be adopted"}},
		{"a reserved word as a key of a map for the role", rep("role: adopted", "role: {published: x}"), "", 6, []string{"keys[1].role must be a string"}},
		{"a reserved word as a key of the reasons", rep("[retired]", "{standby: x}"), "", 4, []string{"revocation_reasons must be a list"}},
		{"a reserved word as a list of keys", rep("keys:\n"+adoptedLine, "keys: [card, replaces]\n"), "", 5, []string{"keys[1] must be a mapping"}},
		{"a null for a reserved member", rep("role: adopted", "role: adopted, card: null"), "", 6, []string{"a null or an empty value"}},
		{"a key that is not a string", rep("role: adopted", "role: adopted, 1: x"), "", 6, []string{"the key is not a string"}},
		{"a complex key", rep("keys:", "? keys\n:"), "", 5, []string{"a complex key"}},
		{"a document marker after the content", personalOpenPGP + "---\nversion: 1\n", "", 7, []string{"a second document"}},
		{"a list as the whole document", "- version: 1\n", "", 1, []string{"the document is not a mapping"}},
	}
	runRefusals(t, rootFile, parseRoot, rows)
}

func TestYAMLTricksInTheFurtherUserIDs(t *testing.T) {
	rep := func(old, repl string) string { return swap(t, idsBase, old, repl) }
	rows := []refusalRow{
		{"an anchor on the list", rep("user_ids:\n", "user_ids: &u\n"), "", 2, []string{"an anchor"}},
		{"an anchor on a name", rep("name: Ada Example", "name: &n Ada"), "", 3, []string{"an anchor"}},
		{"an alias of a whole entry", idsBase + "  - *e\n", "", -1, []string{"not valid YAML"}},
		{"an anchored entry and its alias", idsHead + "  - &e {name: Ada, address: ada@example.org}\n  - *e\n", "", 3, []string{"an anchor"}},
		{"a merge key", rep("{name:", "{<<: {name: Ada}, name:"), "", 3, []string{"a merge key"}},
		{"a name twice", rep("name: Ada Example", "name: Ada Example, name: Ada"), "", 3, []string{`the key "name" appears twice`}},
		{"retire twice", rep("address: ada@example.org", "address: ada@example.org, retire: true, retire: false"), "", 3, []string{`the key "retire" appears twice`}},
		{"user_ids twice", idsBase + "user_ids: []\n", "", 4, []string{`the key "user_ids" appears twice`}},
		{"a tag on a name", rep("name: Ada Example", "name: !!str Ada"), "", 3, []string{"a tag"}},
		{"a tag on retire", rep("address: ada@example.org", "address: ada@example.org, retire: !!bool true"), "", 3, []string{"a tag"}},
		{"a tag on the list", rep("user_ids:\n", "user_ids: !!seq\n"), "", 2, []string{"a tag"}},
		{"a map for a name", rep("name: Ada Example", "name: {a: b}"), "", 3, []string{"user_ids[1].name must be a string"}},
		{"a list for a name", rep("name: Ada Example", "name: [Ada]"), "", 3, []string{"user_ids[1].name must be a string"}},
		{"a map for an address", rep("address: ada@example.org", "address: {a: b}"), "", 3, []string{"user_ids[1].address must be a string"}},
		{"a list for an address", rep("address: ada@example.org", "address: [ada@example.org]"), "", 3, []string{"user_ids[1].address must be a string"}},
		{"a map for retire", rep("address: ada@example.org", "address: ada@example.org, retire: {a: true}"), "", 3, []string{"retire must be true or false"}},
		{"a list for retire", rep("address: ada@example.org", "address: ada@example.org, retire: [true]"), "", 3, []string{"retire must be true or false"}},
		{"a number for a name", rep("name: Ada Example", "name: 2024"), "", 3, []string{"user_ids[1].name must be a string: write it in quotes"}},
		{"a boolean for a name", rep("name: Ada Example", "name: false"), "", 3, []string{"user_ids[1].name must be a string"}},
		{"a date for a name", rep("name: Ada Example", "name: 2024-01-02"), "", 3, []string{"user_ids[1].name must be a string"}},
		{"a number for an address", rep("address: ada@example.org", "address: 2024"), "", 3, []string{"user_ids[1].address must be a string"}},
		{"retire in quotes", rep("address: ada@example.org", `address: ada@example.org, retire: "false"`), "", 3, []string{"retire must be true or false"}},
		{"retire no", rep("address: ada@example.org", "address: ada@example.org, retire: no"), "", 3, []string{"retire must be true or false"}},
		{"retire 0", rep("address: ada@example.org", "address: ada@example.org, retire: 0"), "", 3, []string{"retire must be true or false"}},
		{"retire True", rep("address: ada@example.org", "address: ada@example.org, retire: True"), "", 3, []string{"retire must be true or false"}},
		{"retire null", rep("address: ada@example.org", "address: ada@example.org, retire: null"), "", 3, []string{"null"}},
		{"Retire in another case", rep("address: ada@example.org", "address: ada@example.org, RETIRE: true"), "", 3, []string{`user_ids[1]: the member "RETIRE" is not known`}},
		{"Name in another case", rep("{name:", "{Name:"), "", 3, []string{`user_ids[1]: the member "Name" is not known`}},
		{"a reserved word as a key of a nested map", rep("name: Ada Example", "name: {card: x}"), "", 3, []string{"user_ids[1].name must be a string"}},
		{"a reserved word as the member of an entry", rep("address: ada@example.org", "address: ada@example.org, card: x"), "", 3, []string{`user_ids[1]: the member "card" is not known`}},
		{"an entry that is a string", rep("{name: Ada Example, address: ada@example.org}", "Ada"), "", 3, []string{"user_ids[1] must be a mapping"}},
		{"an entry that is a list", rep("{name: Ada Example, address: ada@example.org}", "[Ada, ada@example.org]"), "", 3, []string{"user_ids[1] must be a mapping"}},
		{"a null entry", rep("{name: Ada Example, address: ada@example.org}", "null"), "", 3, []string{"null"}},
		{"user_ids a string", rep("user_ids:\n  - {name: Ada Example, address: ada@example.org}\n", "user_ids: ada\n"), "", 2, []string{"user_ids must be a list"}},
		{"user_ids null", rep("user_ids:\n  - {name: Ada Example, address: ada@example.org}\n", "user_ids:\n"), "", 2, []string{"null"}},
		{"user_ids a map of entries", rep("user_ids:\n  - {name: Ada Example, address: ada@example.org}\n", "user_ids: {a: {name: Ada, address: a@example.org}}\n"), "", 2, []string{"user_ids must be a list"}},
	}
	runRefusals(t, wanted.UserIDsPath, parseIDs, rows)
}

func TestYAMLTricksInTheCardOfADelegationAndThePerson(t *testing.T) {
	rep := func(old, repl string) string { return swap(t, personalSign, old, repl) }
	rows := []refusalRow{
		{"an anchor on the card", rep("card: day-ana", "card: &c day-ana"), "", 5, []string{"an anchor"}},
		{"an alias of the root for the card", rep("root: openpgp\n", "root: &r openpgp\n") + "x: *r\n", "", 3, []string{"an anchor"}},
		{"a merge key", rep("version: 1", "<<: {card: day-ana}\nversion: 1"), "", 1, []string{"a merge key"}},
		{"the card twice", rep("card: day-ana", "card: day-ana\ncard: day-bob"), "", 6, []string{`the key "card" appears twice`}},
		{"a tag on the card", rep("card: day-ana", "card: !!str day-ana"), "", 5, []string{"a tag"}},
		{"a map for the card", rep("card: day-ana", "card: {a: day-ana}"), "", 5, []string{"card must be a string"}},
		{"a list for the card", rep("card: day-ana", "card: [day-ana]"), "", 5, []string{"card must be a string"}},
		{"a number for the card", rep("card: day-ana", "card: 123"), "", 5, []string{"card must be a string: write it in quotes"}},
		{"a boolean for the card", rep("card: day-ana", "card: true"), "", 5, []string{"card must be a string"}},
		{"a null for the card", rep("card: day-ana", "card: null"), "", 5, []string{"null"}},
		{"an empty card", rep("card: day-ana", `card: ""`), "", 5, []string{"card: a name has 1 to 63 characters"}},
		{"Card in another case", rep("card: day-ana", "Card: day-ana"), "", 5, []string{`the member "Card" is not known`}},
		{"a card name in upper case", rep("day-ana", "Day-Ana"), "", 5, []string{"card: a name has lower-case letters"}},
		{"a card name of 64 characters", rep("day-ana", "a"+stringsRepeat("b", 63)), "", 5, []string{"card: a name has 1 to 63 characters"}},
		{"a card name with a path", rep("day-ana", "../day-ana"), "", 5, []string{"card: a name has lower-case letters"}},
		{"a card name with .yaml", rep("day-ana", "day-ana.yaml"), "", 5, []string{"card: a name has lower-case letters"}},
		{"a capability in upper case", rep("sign", "Sign"), "", 4, []string{"capability must be one of sign, authenticate"}},
		{"a capability that is a boolean", rep("capability: sign", "capability: true"), "", 4, []string{"capability must be a string"}},
		{"a capability that is a map", rep("capability: sign", "capability: {sign: x}"), "", 4, []string{"capability must be a string"}},
	}
	runRefusals(t, "want/delegations/daily.yaml", parseDeleg, rows)

	person := func(old, repl string) string { return swap(t, personalPerson, old, repl) }
	runRefusals(t, wanted.SettingsPath, parsePerson, []refusalRow{
		{"an anchor on the person", person("person:", "person: &p"), "", 3, []string{"an anchor"}},
		{"a tag on the kind", person("kind: personal", "kind: !!str personal"), "", 2, []string{"a tag"}},
		{"a merge key in the person", person("{name:", "{<<: {name: Ada}, name:"), "", 3, []string{"a merge key"}},
		{"the person twice", personalPerson + "person: {name: Ada, address: ada@example.org}\n", "", 10, []string{`the key "person" appears twice`}},
		{"the name twice", person("name: Ben Example", "name: Ben Example, name: Ada"), "", 3, []string{`the key "name" appears twice`}},
		{"a number for the person's name", person("Ben Example", "2024"), "", 3, []string{"must be a string: write it in quotes"}},
		{"a date for the person's address", person("ben@example.com", "2024-01-02"), "", 3, []string{"must be a string"}},
		{"a list for the person", person("person: {name: Ben Example, address: ben@example.com}", "person: [Ben]"), "", 3, []string{"person must be a mapping"}},
		{"a string for the person", person("person: {name: Ben Example, address: ben@example.com}", "person: Ben"), "", 3, []string{"person must be a mapping"}},
		{"Person in another case", person("person:", "Person:"), "", 3, []string{`the member "Person" is not known`}},
		{"Kind in another case", person("kind:", "Kind:"), "", 2, []string{`the member "Kind" is not known`}},
		{"Personal in another case", person("kind: personal", "kind: Personal"), "", 2, []string{"kind must be one of personal"}},
		{"a reserved word as a key of the person", person("{name:", "{card: x, name:"), "", 3, []string{`the member "card" is not known`}},
		{"a reserved word as a key of a nested map for the name", person("Ben Example", "{card: x}"), "", 3, []string{"person.name must be a string"}},
		{"a store that is a map", person("[openpgp-card, software]", "{openpgp-card: x}"), "", 5, []string{"policy.stores must be a list"}},
		{"a store that is a number", person("[openpgp-card, software]", "[1]"), "", 5, []string{"policy.stores entry 1 must be a string"}},
		{"a store in upper case", person("[openpgp-card, software]", "[Software]"), "", 5, []string{"policy.stores entry 1 must be one of"}},
	})
}

func stringsRepeat(s string, n int) string {
	out := ""
	for range n {
		out += s
	}
	return out
}
