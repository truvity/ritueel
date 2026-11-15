package wanted_test

import (
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/wanted"
)

// What the reader of a card file refuses. Each row changes one thing of a good file, names the line of the fault
// (the line of the member's key; the line of the entry for a list entry; the line of the mapping for a member that
// is missing) and the words of the sentence, and carries a negative control: the same file with the one change that
// makes it good is accepted.

// cardBase is the file that the rows start from: every member, and the rows on the line 5.
const cardBase = `version: 1
serial: "10000001"
kind: root
applications: [piv, fido2]
other_rows: [3]
`

type cardRow struct {
	name  string
	from  string   // the text of cardBase that changes
	bad   string   // what it becomes
	good  string   // what it becomes for the control; "" keeps the original
	line  int      // the line of the fault
	words []string // words that the message holds
}

// cardRefusals are the refusals of the members.
func cardRefusals() []cardRow {
	var rows []cardRow
	add := func(name, from, bad, good string, line int, words ...string) {
		rows = append(rows, cardRow{name, from, bad, good, line, words})
	}
	const ver, ser, kind, apps, other = "version: 1\n", "serial: \"10000001\"\n", "kind: root\n", "applications: [piv, fido2]\n", "other_rows: [3]\n"

	// version
	add("version 2", ver, "version: 2\n", "", 1, "version must be 1")
	add("version 0", ver, "version: 0\n", "", 1, "version must be 1")
	add("version 11", ver, "version: 11\n", "", 1, "version must be 1")
	add("version written as a string", ver, "version: \"1\"\n", "", 1, "version", "integer")
	add("version written as a float", ver, "version: 1.0\n", "", 1, "version", "integer")
	add("version with a leading zero", ver, "version: 01\n", "", 1, "version", "integer")
	add("version negative", ver, "version: -1\n", "", 1, "version", "integer")
	add("version as true", ver, "version: true\n", "", 1, "version", "integer")
	add("version as a list", ver, "version: [1]\n", "", 1, "version", "integer")
	add("version missing", ver, "", "", 1, "the member version is required")
	add("version in a flow root and missing", cardBase, "{serial: \"1\", kind: root, applications: [piv]}\n", "{version: 1, serial: \"1\", kind: root, applications: [piv]}\n", 1, "version is required")

	// serial
	add("serial missing", ser, "", "", 1, "the member serial is required")
	add("serial unquoted", ser, "serial: 10000001\n", "", 2, "serial", "string", "quotes")
	add("serial unquoted and short", ser, "serial: 1\n", "", 2, "serial", "string", "quotes")
	add("serial as a float", ser, "serial: 1.5\n", "", 2, "serial", "string")
	add("serial as true", ser, "serial: true\n", "", 2, "serial", "string")
	add("serial empty in quotes", ser, "serial: \"\"\n", "", 2, "serial must be 1 to 10 digits")
	add("serial of 11 digits", ser, "serial: \"12345678901\"\n", "", 2, "serial must be 1 to 10 digits")
	add("serial of 10,000 digits", ser, "serial: \""+strings.Repeat("7", 10000)+"\"\n", "", 2, "serial must be 1 to 10 digits")
	add("serial of 100,000 zeros", ser, "serial: \""+strings.Repeat("0", 100000)+"\"\n", "", 2, "serial must be 1 to 10 digits")
	add("serial with a letter", ser, "serial: \"1000000a\"\n", "", 2, "serial must be 1 to 10 digits")
	add("serial of letters", ser, "serial: \"ABCDEF\"\n", "", 2, "serial must be 1 to 10 digits")
	add("serial in hexadecimal", ser, "serial: \"0x10\"\n", "", 2, "serial must be 1 to 10 digits")
	add("serial with a space", ser, "serial: \"1000 001\"\n", "", 2, "serial must be 1 to 10 digits")
	add("serial with a space at the end", ser, "serial: \"10000001 \"\n", "", 2, "serial must be 1 to 10 digits")
	add("serial with a space at the start", ser, "serial: \" 10000001\"\n", "", 2, "serial must be 1 to 10 digits")
	add("serial with a plus", ser, "serial: \"+1000001\"\n", "", 2, "serial must be 1 to 10 digits")
	add("serial with a minus", ser, "serial: \"-1000001\"\n", "", 2, "serial must be 1 to 10 digits")
	add("serial with a point", ser, "serial: \"1000.001\"\n", "", 2, "serial must be 1 to 10 digits")
	add("serial in exponent form", ser, "serial: \"1e3\"\n", "", 2, "serial must be 1 to 10 digits")
	add("serial with an underscore", ser, "serial: \"1_000_001\"\n", "", 2, "serial must be 1 to 10 digits")
	add("serial with a line feed", ser, "serial: \"1000\\n001\"\n", "", 2, "serial must be 1 to 10 digits")
	add("serial of Arabic-Indic digits", ser, "serial: \"\u0661\u0662\u0663\"\n", "", 2, "serial must be 1 to 10 digits")
	add("serial of fullwidth digits", ser, "serial: \"\uff11\uff12\uff13\"\n", "", 2, "serial must be 1 to 10 digits")
	add("serial null", ser, "serial: null\n", "", 2, "null")
	add("serial tilde", ser, "serial: ~\n", "", 2, "null")
	add("serial empty and unquoted", ser, "serial:\n", "", 2, "null or an empty value")
	add("serial as a list", ser, "serial: [\"10000001\"]\n", "", 2, "serial must be a string")
	add("serial as a mapping", ser, "serial: {a: \"1\"}\n", "", 2, "serial must be a string")
	add("serial twice", ser, ser+ser, "", 3, "appears twice")

	// kind
	add("kind missing", kind, "", "", 1, "the member kind is required")
	add("kind in upper case", kind, "kind: Root\n", "", 3, "kind must be one of", "root", "day-to-day", "server", "rehearsal")
	add("kind of the old name hsm", kind, "kind: hsm\n", "", 3, "kind must be one of")
	add("kind with an underscore", kind, "kind: day_to_day\n", "", 3, "kind must be one of")
	add("kind with a space", kind, "kind: \"root \"\n", "", 3, "kind must be one of")
	add("kind empty in quotes", kind, "kind: \"\"\n", "", 3, "kind must be one of")
	add("kind empty", kind, "kind:\n", "", 3, "null or an empty value")
	add("kind as a number", kind, "kind: 1\n", "", 3, "kind must be a string")
	add("kind as true", kind, "kind: true\n", "", 3, "kind must be a string")
	add("kind as a list", kind, "kind: [root]\n", "", 3, "kind must be a string")
	add("kind as a mapping", kind, "kind: {a: b}\n", "", 3, "kind must be a string")
	add("kind of a longer word", kind, "kind: roots\n", "", 3, "kind must be one of")
	add("kind of a day-to-day typo", kind, "kind: day-to-days\n", "", 3, "kind must be one of")
	add("kind twice", kind, kind+kind, "", 4, "appears twice")
	add("kind twice with two words", kind, kind+"kind: server\n", "", 4, "appears twice")

	// applications
	add("applications missing", apps, "", "", 1, "the member applications is required")
	add("applications empty", apps, "applications: []\n", "", 4, "applications must hold at least 1 entry")
	add("applications of four entries", apps, "applications: [piv, openpgp, fido2, piv]\n", "", 4, "at most 3 entries")
	add("applications of a hundred entries", apps, "applications: ["+strings.TrimSuffix(strings.Repeat("piv, ", 100), ", ")+"]\n", "", 4, "at most 3 entries")
	add("applications of 5,000 entries", apps, "applications: ["+strings.TrimSuffix(strings.Repeat("piv, ", 5000), ", ")+"]\n", "", 4, "at most 3 entries")
	add("applications unknown gpg", apps, "applications: [gpg]\n", "", 4, "applications entry 1 must be one of", "piv", "openpgp", "fido2")
	add("applications with an unknown second entry", apps, "applications: [piv, ssh]\n", "", 4, "entry 2 must be one of")
	add("applications in upper case", apps, "applications: [PIV]\n", "", 4, "entry 1 must be one of")
	add("applications with a space", apps, "applications: [\"piv \"]\n", "", 4, "entry 1 must be one of")
	add("applications twice piv", apps, "applications: [piv, piv]\n", "", 4, "entry 2 repeats an earlier entry")
	add("applications twice at the end", apps, "applications: [piv, fido2, piv]\n", "", 4, "entry 3 repeats an earlier entry")
	add("applications as a string", apps, "applications: piv\n", "", 4, "applications must be a list")
	add("applications as a mapping", apps, "applications: {piv: true}\n", "", 4, "applications must be a list")
	add("applications as a number", apps, "applications: 1\n", "", 4, "applications must be a list")
	add("applications empty and unquoted", apps, "applications:\n", "", 4, "null or an empty value")
	add("applications with a number", apps, "applications: [1]\n", "", 4, "entry 1 must be a string")
	add("applications with true", apps, "applications: [true]\n", "", 4, "entry 1 must be a string")
	add("applications with a list inside", apps, "applications: [[piv]]\n", "", 4, "entry 1 must be a string")
	add("applications with a mapping inside", apps, "applications: [{a: b}]\n", "", 4, "entry 1 must be a string")
	add("applications with a null", apps, "applications: [piv, null]\n", "", 4, "null")
	add("applications with a null as a tilde", apps, "applications: [~]\n", "", 4, "null")
	add("applications twice as a member", apps, apps+apps, "", 5, "appears twice")

	// other_rows
	add("other_rows without piv", apps, "applications: [fido2]\n", "", 5, "other_rows needs piv")
	add("other_rows with only openpgp", apps, "applications: [openpgp]\n", "", 5, "other_rows needs piv")
	add("other_rows with openpgp and fido2", apps, "applications: [openpgp, fido2]\n", "", 5, "other_rows needs piv")
	add("other_rows row 1", other, "other_rows: [1]\n", "", 5, "other_rows entry 1 must be from 2 to 6")
	add("other_rows row 7", other, "other_rows: [7]\n", "", 5, "other_rows entry 1 must be from 2 to 6")
	add("other_rows row 0", other, "other_rows: [0]\n", "", 5, "must be from 2 to 6")
	add("other_rows a high row", other, "other_rows: [999999999]\n", "", 5, "must be from 2 to 6")
	add("other_rows a row of ten digits", other, "other_rows: [1000000000]\n", "", 5, "must be an integer of plain decimal digits")
	add("other_rows a row of 50 digits", other, "other_rows: ["+strings.Repeat("9", 50)+"]\n", "", 5, "must be an integer of plain decimal digits")
	add("other_rows a negative row", other, "other_rows: [-3]\n", "", 5, "must be an integer of plain decimal digits")
	add("other_rows a signed row", other, "other_rows: [+3]\n", "", 5, "must be an integer of plain decimal digits")
	add("other_rows a row twice", other, "other_rows: [3, 3]\n", "", 5, "entry 2 repeats an earlier entry")
	add("other_rows a row twice, far apart", other, "other_rows: [2, 3, 4, 2]\n", "", 5, "entry 4 repeats an earlier entry")
	add("other_rows six entries", other, "other_rows: [2, 3, 4, 5, 6, 2]\n", "", 5, "other_rows must hold at most 5 entries")
	add("other_rows six entries that are all good rows twice", other, "other_rows: [2, 3, 4, 5, 6, 6]\n", "", 5, "at most 5 entries")
	add("other_rows of 5,000 entries", other, "other_rows: ["+strings.TrimSuffix(strings.Repeat("3, ", 5000), ", ")+"]\n", "", 5, "at most 5 entries")
	add("other_rows of 5,000 hostile entries", other, "other_rows: ["+strings.TrimSuffix(strings.Repeat("x, ", 5000), ", ")+"]\n", "", 5, "at most 5 entries")
	add("other_rows a quoted row", other, "other_rows: [\"3\"]\n", "", 5, "entry 1 must be an integer")
	add("other_rows a float row", other, "other_rows: [3.0]\n", "", 5, "entry 1 must be an integer")
	add("other_rows a row with a leading zero", other, "other_rows: [03]\n", "", 5, "entry 1 must be an integer")
	add("other_rows a row in hexadecimal", other, "other_rows: [0x3]\n", "", 5, "entry 1 must be an integer")
	add("other_rows a row in octal", other, "other_rows: [0o3]\n", "", 5, "entry 1 must be an integer")
	add("other_rows a row with an underscore", other, "other_rows: [1_0]\n", "", 5, "entry 1 must be an integer")
	add("other_rows a row in exponent form", other, "other_rows: [3e0]\n", "", 5, "entry 1 must be an integer")
	add("other_rows a row as a word", other, "other_rows: [three]\n", "", 5, "entry 1 must be an integer")
	add("other_rows a boolean row", other, "other_rows: [true]\n", "", 5, "entry 1 must be an integer")
	add("other_rows a null row", other, "other_rows: [~]\n", "", 5, "null")
	add("other_rows a list inside", other, "other_rows: [[3]]\n", "", 5, "entry 1 must be an integer")
	add("other_rows a mapping inside", other, "other_rows: [{a: 3}]\n", "", 5, "entry 1 must be an integer")
	add("other_rows a mapping", other, "other_rows: {a: 3}\n", "", 5, "other_rows must be a list")
	add("other_rows a number", other, "other_rows: 3\n", "", 5, "other_rows must be a list")
	add("other_rows a string", other, "other_rows: three\n", "", 5, "other_rows must be a list")
	add("other_rows empty and unquoted", other, "other_rows:\n", "", 5, "null or an empty value")
	add("other_rows twice", other, other+other, "", 6, "appears twice")
	add("other_rows a second entry bad", other, "other_rows: [3, 7]\n", "", 5, "entry 2 must be from 2 to 6")
	add("other_rows an entry in a block list on its own line", other, "other_rows:\n  - 3\n  - 9\n", "", 7, "entry 2 must be from 2 to 6")
	add("other_rows a repeat in a block list on its own line", other, "other_rows:\n  - 3\n  - 4\n  - 3\n", "", 8, "entry 3 repeats an earlier entry")
	add("other_rows a bad entry in the middle of a block list", other, "other_rows:\n  - 3\n  - x\n  - 4\n", "", 7, "entry 2 must be an integer")

	// holder and kept: the pages of the bundle once listed them, and they are not read in this version.
	add("holder", other, other+"holder: Example Person\n", other, 6, "holder", "not read in this version")
	add("holder quoted", other, other+"\"holder\": Example Person\n", other, 6, "holder", "not read in this version")
	add("holder as a list", other, other+"holder: [a]\n", other, 6, "holder", "not read in this version")
	add("holder in a flow root", cardBase, "{version: 1, serial: \"1\", kind: root, applications: [piv], holder: x}\n", "{version: 1, serial: \"1\", kind: root, applications: [piv]}\n", 1, "holder", "not read in this version")
	add("kept", other, other+"kept: safe at the office\n", other, 6, "kept", "not read in this version")
	add("kept as a mapping", other, other+"kept: {where: office}\n", other, 6, "kept", "not read in this version")
	add("a value that is the word holder is not the member", kind, "kind: holder\n", "", 3, "kind must be one of")
	add("a value that is the word kept is not the member", ser, "serial: kept\n", "", 2, "serial must be 1 to 10 digits")
	add("a list entry that is the word holder is not the member", apps, "applications: [holder]\n", "", 4, "entry 1 must be one of")
	add("a member of three pairs in place of the applications", apps, "applications: {piv: a, fido2: b, openpgp: c}\n", "", 4, "applications must be a list")
	add("a member of three pairs in place of the rows", other, "other_rows: {a: 1, b: 2, c: 3}\n", "", 5, "other_rows must be a list")
	add("holder first", ver, "holder: Example Person\n"+ver, ver, 1, "holder", "not read in this version")
	add("holder and kept: the first one is named", other, other+"holder: a\nkept: b\n", other, 6, "holder")
	add("kept before holder: the first one is named", other, other+"kept: b\nholder: a\n", other, 6, "kept")

	// Unknown members.
	add("an unknown member", other, other+"label: first\n", other, 6, "label", "is not known")
	add("an unknown member in the middle", ser, ser+"colour: red\n", "", 3, "colour", "is not known")
	add("an upper-case version", ver, "Version: 1\n", "", 1, "Version", "is not known")
	add("a member of the card map", other, other+"slots: []\n", other, 6, "slots", "is not known")
	add("a member of the settings", other, other+"name: Example\n", other, 6, "name", "is not known")
	add("a member written with a hyphen", other, "other-rows: [3]\n", other, 5, "other-rows", "is not known")
	add("the member rows", other, "rows: [3]\n", other, 5, "rows", "is not known")
	add("an unknown member with a hostile name", other, other+"\"a\\u0007b\": 1\n", other, 6, "is not known")
	add("an unknown member with a long name", other, other+strings.Repeat("x", 1000)+": 1\n", other, 6, "is not known")
	add("a number as a key", other, other+"1: x\n", other, 6, "key is not a string")
	add("a member with a key and no value", other, other+"lonely\n", other, -1)
	return rows
}

func TestParseCardRefusesWhatItShould(t *testing.T) {
	rows := cardRefusals()
	if len(rows) < 130 {
		t.Fatalf("only %d rows: a check that finds nothing to check fails", len(rows))
	}
	seen := map[string]bool{}
	for _, r := range rows {
		if seen[r.name] {
			t.Fatalf("the row %q is twice in the table", r.name)
		}
		seen[r.name] = true
		t.Run(r.name, func(t *testing.T) {
			bad := replaceOnce(t, cardBase, r.from, r.bad)
			e := refuseCard(t, bad, r.line, r.words...)
			// An error holds fixed words and a cut of the file's own text: never the whole of a long value.
			if len(e.Error()) > 600 {
				t.Errorf("the error is %d bytes long: %.80q", len(e.Error()), e.Error())
			}
			if e.Unwrap() != nil {
				t.Errorf("the fault of a text has a cause: %v", e.Unwrap())
			}
			// The negative control: the same file with the one change that makes it good is accepted.
			good := r.good
			if good == "" {
				good = r.from
			}
			mustCard(t, "root-a", replaceOnce(t, cardBase, r.from, good))
		})
	}
}

// A refusal that comes first is the one that is named: the members are read in the order of the page.
func TestParseCardNamesTheFirstFault(t *testing.T) {
	rows := []struct {
		name  string
		text  string
		line  int
		words string
	}{
		{"holder before an unknown member and a missing one", "bogus: 1\nholder: x\n", 2, "holder"},
		{"an unknown member before a missing one", "bogus: 1\nserial: \"1\"\n", 1, "bogus"},
		{"a missing member before a bad value", "version: 2\nserial: \"1\"\nkind: nope\n", 1, "applications is required"},
		{"the version before the serial", "version: 2\nserial: 1\nkind: nope\napplications: []\n", 1, "version must be 1"},
		{"the serial before the kind", "version: 1\nserial: 1\nkind: nope\napplications: []\n", 2, "serial"},
		{"the kind before the applications", "version: 1\nserial: \"1\"\nkind: nope\napplications: []\n", 3, "kind"},
		{"the applications before the rows", "version: 1\nserial: \"1\"\nkind: root\napplications: []\nother_rows: [9]\n", 4, "applications"},
		{"the rows last", "version: 1\nserial: \"1\"\nkind: root\napplications: [piv]\nother_rows: [9]\n", 5, "other_rows"},
		{"the rows of a card without piv", "version: 1\nserial: \"1\"\nkind: root\napplications: [fido2]\nother_rows: [9]\n", 5, "must be from 2 to 6"},
		{"two faults of the text before the members", "version: 1\r\nserial: 1\n", 1, "carriage return"},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) { _ = refuseCard(t, r.text, r.line, r.words) })
	}
}

// A file that holds no mapping, or none of the members.
func TestParseCardRefusesAFileThatIsNotACardFile(t *testing.T) {
	rows := []struct {
		name  string
		text  string
		line  int
		words string
	}{
		{"an empty file", "", 0, "no document"},
		{"only a marker", "---\n", -1, ""},
		{"only comments", "# a card\n", 0, "no document"},
		{"an empty mapping", "{}\n", 1, "the member version is required"},
		{"a list", "- a\n", 1, "not a mapping"},
		{"a flow list", "[version, serial]\n", 1, "not a mapping"},
		{"a scalar", "root\n", 1, "not a mapping"},
		{"a number", "1\n", 1, "not a mapping"},
		{"the text of a settings file", goodSettings, 2, "name"},
		{"the text of a root file", goodRoot, 3, "test"},
		{"the text of a delegation file", goodX509Delegation, 2, "type"},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) { _ = refuseCard(t, r.text, r.line, r.words) })
	}
}

// What the engine of strict YAML refuses, once for each family; the engine's own tests are not repeated.
func TestParseCardRefusesWhatStrictYAMLRefuses(t *testing.T) {
	good := cardRootA
	with := func(old, repl string) string { return replaceOnce(t, good, old, repl) }
	rows := []struct {
		name  string
		text  string
		line  int
		words string
	}{
		{"an anchor", with("kind: root", "kind: &k root"), 3, "anchor"},
		{"an alias", with("kind: root", "kind: &k root\nx: *k"), 3, "anchor"},
		{"an alias without an anchor", with("kind: root", "kind: *k"), -1, ""},
		{"a merge key", "<<: {a: 1}\n" + good, 1, "merge key"},
		{"a tag", with("kind: root", "kind: !!str root"), 3, "tag"},
		{"a custom tag", with("kind: root", "kind: !x root"), 3, "tag"},
		{"a tag on a list entry", with("[piv, fido2]", "[!!str piv, fido2]"), 4, "tag"},
		{"a tag on a row", with("[3]", "[!!int 3]"), 5, "tag"},
		{"a null", with("kind: root", "kind: null"), 3, "null"},
		{"an empty value", with("kind: root", "kind:"), 3, "null or an empty value"},
		{"a second document", good + "---\n" + good, 6, "second document"},
		{"an end marker", good + "...\n", 6, "end marker"},
		{"a directive", "%YAML 1.2\n---\n" + good, 1, "directive"},
		{"a complex key", with("kind: root", "? kind\n: root"), 3, "complex key"},
		{"a tab", with("kind: root", "kind:\troot"), 3, "tab"},
		{"a carriage return", strings.ReplaceAll(good, "\n", "\r\n"), 1, "carriage return"},
		{"a byte order mark", "\ufeff" + good, 1, "byte order mark"},
		{"a bidirectional control in a comment", with("kind: root", "kind: root # \u202e"), 3, "format character U+202E"},
		{"a zero-width space in a value", with("kind: root", "kind: ro\u200bot"), 3, "format character U+200B"},
		{"a control character in a comment", with("kind: root", "kind: root #\x07"), 3, "control character U+0007"},
		{"a line separator in a comment", with("kind: root", "kind: root #\u2028"), 3, "line separator U+2028"},
		{"a byte that is not UTF-8", with("kind: root", "kind: ro\xffot"), 3, "not valid UTF-8"},
		{"a byte that is not UTF-8 in a comment", with("kind: root", "kind: root # \xc3"), 3, "not valid UTF-8"},
		{"an escape that makes a control character", with("serial: \"10000001\"", "serial: \"1000000\\x00\""), 2, "serial must be 1 to 10 digits"},
		{"a repeated key", good + "kind: server\n", 6, "appears twice"},
		{"a repeated key, one in quotes", good + "\"kind\": server\n", 6, "appears twice"},
		{"a key that is a number", good + "1: a\n", 6, "key is not a string"},
		{"an unterminated list", with("[piv, fido2]", "[piv, fido2"), -1, ""},
		{"nested more than 16 levels", good + "x: " + strings.Repeat("[", 20) + strings.Repeat("]", 20) + "\n", -1, "nested more than 16"},
		{"nested 300 levels", good + "x: " + strings.Repeat("[", 300) + "\n", -1, ""},
		{"more than 10,000 nodes", good + "x: [" + strings.TrimSuffix(strings.Repeat("a, ", 10001), ", ") + "]\n", -1, "more than 10000 nodes"},
		{"a long applications list is refused before its length", strings.Replace(good, "[piv, fido2]", "["+strings.TrimSuffix(strings.Repeat("piv, ", 10001), ", ")+"]", 1), -1, "more than 10000 nodes"},
		{"a file of the limit and one byte", good + "#" + strings.Repeat("x", wanted.MaxBytes-len(good)) + "\n", 0, "longer than"},
		{"a file of a megabyte", good + "#" + strings.Repeat("x", 1<<20) + "\n", 0, "longer than"},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			e := refuseCard(t, r.text, r.line, r.words)
			if len(r.text) > wanted.MaxBytes && e.Line != 0 {
				t.Errorf("a file over the limit is refused with the line %d", e.Line)
			}
		})
	}
}

// Every file that strict YAML refuses for the settings file is refused by the reader of a card file as well, with
// the path of the card file.
func TestParseCardRefusesEveryRowOfTheEngineTable(t *testing.T) {
	rows := strictRows()
	if len(rows) < 100 {
		t.Fatalf("only %d rows: a check that finds nothing to check fails", len(rows))
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			c, err := wanted.ParseCard("root-a", []byte(r.text))
			if c != nil || err == nil {
				t.Fatalf("a card from %q", r.text)
			}
			e := wantFault(t, err, cardPath("root-a"), -1)
			if r.line >= 0 && e.Line != r.line && len(r.words) > 0 && !strings.Contains(e.Msg, "not known") && strings.Contains(e.Msg, r.words[0]) {
				t.Errorf("line %d, the settings reader says %d (%s)", e.Line, r.line, e.Msg)
			}
		})
	}
}

// A message holds a cut of a text from the file, never the whole of it, and never a character that is not
// printable.
func TestParseCardMessagesDoNotEchoWhatTheFileHolds(t *testing.T) {
	hostile := strings.Repeat(`A\u202e\a`, 100)
	for name, text := range map[string]string{
		"a member name":   "version: 1\nserial: \"1\"\nkind: root\napplications: [piv]\n\"" + hostile + "\": 1\n",
		"a kind":          "version: 1\nserial: \"1\"\nkind: \"" + hostile + "\"\napplications: [piv]\n",
		"an application":  "version: 1\nserial: \"1\"\nkind: root\napplications: [\"" + hostile + "\"]\n",
		"a serial":        "version: 1\nserial: \"" + strings.Repeat("9", 20000) + "\"\nkind: root\napplications: [piv]\n",
		"a member holder": "version: 1\nserial: \"1\"\nkind: root\napplications: [piv]\n\"holder\": " + strings.Repeat("h", 20000) + "\n",
	} {
		t.Run(name, func(t *testing.T) {
			c, err := wanted.ParseCard("root-a", []byte(text))
			if c != nil || err == nil {
				t.Fatalf("accepted: %v", c)
			}
			if !printable(err.Error()) {
				t.Errorf("not printable: %+q", err.Error())
			}
			if len(err.Error()) > 400 {
				t.Errorf("the error is %d bytes", len(err.Error()))
			}
		})
	}
}

// A refusal leaves nothing behind: two reads of the same bytes give equal results, and a refused read changes
// nothing for the next one (no state is kept between files).
func TestParseCardKeepsNoStateBetweenFiles(t *testing.T) {
	a1 := mustCard(t, "root-a", cardRootA)
	if _, err := wanted.ParseCard("root-a", []byte("version: 2\n")); err == nil {
		t.Fatal("accepted")
	}
	a2 := mustCard(t, "root-a", cardRootA)
	if a1.File.SHA256 != a2.File.SHA256 || a1.Serial != a2.Serial || a1.Kind != a2.Kind || !slicesEqual(a1.Applications, a2.Applications) || !slicesEqual(a1.OtherRows, a2.OtherRows) {
		t.Errorf("two reads of one file differ: %+v / %+v", a1, a2)
	}
	// The two cards share no memory.
	a1.Applications[0] = wanted.AppOpenPGP
	a1.OtherRows[0] = 6
	if a2.Applications[0] != wanted.AppPIV || a2.OtherRows[0] != 3 {
		t.Error("two cards share a slice")
	}
}

func slicesEqual[T comparable](a, b []T) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// The limits of the engine hold at their edge for a card file: a file of exactly MaxNodes nodes is read to its
// members (and refused there, for it is not a card), a file of one node more is refused for its size.
func TestParseCardAtTheLimitOfNodesAndDepth(t *testing.T) {
	// The root mapping, version, serial, kind and applications with two entries make 11 nodes; "x: [...]" adds two
	// and one for each entry.
	const fixed = 11 + 2
	head := "version: 1\nserial: \"1\"\nkind: root\napplications: [piv, fido2]\n"
	list := func(n int) string { return head + "x: [" + strings.TrimSuffix(strings.Repeat("a, ", n), ", ") + "]\n" }
	_ = refuseCard(t, list(wanted.MaxNodes-fixed), 5, "the member \"x\" is not known")
	_ = refuseCard(t, list(wanted.MaxNodes-fixed+1), 5, "more than 10000 nodes")
	// Sixteen levels: the root mapping, and fifteen lists, one in the other.
	deep := func(levels int) string {
		return head + "x: " + strings.Repeat("[", levels) + "a" + strings.Repeat("]", levels) + "\n"
	}
	_ = refuseCard(t, deep(wanted.MaxDepth-1), 5, "the member \"x\" is not known")
	_ = refuseCard(t, deep(wanted.MaxDepth), 5, "nested more than 16 levels")
}

// Bytes that are no file at all: nothing, a nil slice and eight megabytes. None crashes, each is refused with the
// path of the card file and no card.
func TestParseCardRefusesNoBytesAndTooManyBytes(t *testing.T) {
	for name, data := range map[string][]byte{
		"a nil slice":        nil,
		"an empty slice":     {},
		"one line feed":      []byte("\n"),
		"eight megabytes":    []byte(strings.Repeat("a", 8<<20)),
		"eight megabytes+1":  []byte(strings.Repeat("a", 8<<20+1)),
		"a long line of tab": []byte(strings.Repeat("\t", wanted.MaxBytes+1)),
		"only NUL bytes":     make([]byte, 1000),
		"only 0xff bytes":    []byte(strings.Repeat("\xff", 1000)),
	} {
		t.Run(name, func(t *testing.T) {
			c, err := wanted.ParseCard("root-a", data)
			if c != nil {
				t.Errorf("a card from %d bytes", len(data))
			}
			e := wantFault(t, err, cardPath("root-a"), -1)
			if len(e.Error()) > 400 {
				t.Errorf("the error is %d bytes", len(e.Error()))
			}
		})
	}
}
