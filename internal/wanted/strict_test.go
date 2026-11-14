package wanted_test

import (
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/wanted"
)

// What strict YAML refuses (docs/reference/bundle.md, "The wanted files": one document, no anchors, no merge
// keys, no repeated keys, UTF-8 with LF, no byte order mark, no tags, no aliases, an unknown key is an error), and
// the rules that go with it (record 0006, rule 5). Each row changes the one thing a good file has.

func TestStrictYAMLAcceptsWhatItShould(t *testing.T) {
	for name, text := range map[string]string{
		"a plain file":                  goodSettings,
		"a leading document marker":     "---\n" + goodSettings,
		"a marker with a comment":       "--- # the settings\n" + goodSettings,
		"comments everywhere":           "# one\n" + strings.ReplaceAll(goodSettings, "\n", " # two\n"),
		"blank lines":                   "\n\n" + strings.Replace(goodSettings, "\npolicy:", "\n\npolicy:", 1),
		"no final line feed":            strings.TrimSuffix(goodSettings, "\n"),
		"two final line feeds":          goodSettings + "\n",
		"a flow mapping as the root":    "{version: 1, name: Example, release_address: release@example.org, policy: {stores: [piv], min_firmware: 5.7.0, pin_policy: [once], require_name_constraints: true, validity_months: 13}}\n",
		"block lists":                   replaceOnce(t, goodSettings, "[piv, openpgp-card, aws-kms]", "\n    - piv\n    - openpgp-card"),
		"quoted keys":                   strings.Replace(goodSettings, "version:", `"version":`, 1),
		"single-quoted keys":            strings.Replace(goodSettings, "version:", `'version':`, 1),
		"a single-quoted string":        strings.Replace(goodSettings, "name: Example", "name: 'Example'", 1),
		"a double-quoted string":        strings.Replace(goodSettings, "name: Example", `name: "Example"`, 1),
		"a string that is a number":     strings.Replace(goodSettings, "name: Example", `name: "2024"`, 1),
		"extra spaces after the colon":  strings.Replace(goodSettings, "name: Example", "name:     Example", 1),
		"a trailing space on a comment": strings.Replace(goodSettings, "name: Example", "name: Example # a note ", 1),
	} {
		t.Run(name, func(t *testing.T) { mustSettings(t, text) })
	}
}

// strictRow is a file that strict YAML refuses, the line of the fault (negative: not checked) and words that its
// message holds.
type strictRow struct {
	name  string
	text  string
	line  int
	words []string
}

func strictRows() []strictRow {
	good := goodSettings
	with := func(old, repl string) string { return strings.Replace(good, old, repl, 1) }
	rows := []strictRow{
		// The text of the file.
		{"a byte order mark", "\ufeff" + good, 1, []string{"byte order mark"}},
		{"a byte order mark with the document marker after it", "\ufeff---\n" + good, 1, []string{"byte order mark"}},
		{"CRLF line ends", strings.ReplaceAll(good, "\n", "\r\n"), 1, []string{"carriage return"}},
		{"one carriage return in the middle", with("name: Example\n", "name: Example\r\n"), 2, []string{"carriage return"}},
		{"a lone carriage return", with("name: Example\n", "name: Example\r"), 2, []string{"carriage return"}},
		{"a tab in an indent", with("  stores:", "\tstores:"), 5, []string{"tab"}},
		{"a tab in a value", with("name: Example", "name:\tExample"), 2, []string{"tab"}},
		{"a tab in a comment", with("name: Example", "name: Example #\ta"), 2, []string{"tab"}},
		{"a tab inside quotes", with("name: Example", "name: \"Exa\tmple\""), 2, []string{"tab"}},
		{"a NUL", with("name: Example", "name: Exa\x00mple"), 2, []string{"control character U+0000"}},
		{"a NUL in a comment", with("name: Example", "name: Example #\x00"), 2, []string{"control character"}},
		{"a bell", with("name: Example", "name: Exa\ample"), 2, []string{"control character U+0007"}},
		{"an escape", with("name: Example", "name: Exa\x1bmple"), 2, []string{"control character U+001B"}},
		{"a vertical tab", with("name: Example", "name: Exa\vmple"), 2, []string{"control character U+000B"}},
		{"a form feed", with("name: Example", "name: Exa\fmple"), 2, []string{"control character U+000C"}},
		{"a delete character", with("name: Example", "name: Exa\x7fmple"), 2, []string{"control character U+007F"}},
		{"a C1 control character", with("name: Example", "name: Exa\u0085mple"), 2, []string{"control character U+0085"}},
		{"a bidirectional control in a comment", with("name: Example", "name: Example # \u202e evil"), 2, []string{"format character U+202E"}},
		{"a bidirectional isolate in a comment", with("name: Example", "name: Example # \u2066 evil"), 2, []string{"format character U+2066"}},
		{"a zero-width space in a value", with("name: Example", "name: Exa\u200bmple"), 2, []string{"format character U+200B"}},
		{"a zero-width joiner in a key", with("name: Example", "na\u200dme: Example"), 2, []string{"format character U+200D"}},
		{"a byte order mark in the middle", with("name: Example", "name: Exa\ufeffmple"), 2, []string{"format character U+FEFF"}},
		{"a soft hyphen", with("name: Example", "name: Exa\u00admple"), 2, []string{"format character U+00AD"}},
		{"a line separator", with("name: Example", "name: Example #\u2028x"), 2, []string{"line separator U+2028"}},
		{"a paragraph separator", with("name: Example", "name: Example #\u2029x"), 2, []string{"line separator U+2029"}},
		{"a byte that is not UTF-8", with("name: Example", "name: Exa\xffmple"), 2, []string{"not valid UTF-8"}},
		{"a truncated sequence", with("name: Example", "name: Exa\xc3"), 2, []string{"not valid UTF-8"}},
		{"an overlong NUL", with("name: Example", "name: Exa\xc0\x80mple"), 2, []string{"not valid UTF-8"}},
		{"an encoded surrogate", with("name: Example", "name: Exa\xed\xa0\x80mple"), 2, []string{"not valid UTF-8"}},
		{"a code point above the range", with("name: Example", "name: Exa\xf4\x90\x80\x80mple"), 2, []string{"not valid UTF-8"}},
		{"Latin-1 in a comment", with("name: Example", "name: Example # caf\xe9"), 2, []string{"not valid UTF-8"}},

		// What the file holds.
		{"an empty file", "", 0, []string{"no document"}},
		{"only a line feed", "\n", 0, []string{"no document"}},
		{"only spaces", "   \n  \n", 0, []string{"no document"}},
		{"only comments", "# nothing\n# here\n", 0, []string{"no document"}},
		{"only a document marker", "---\n", -1, nil},
		{"a list as the root", "- a\n- b\n", 1, []string{"not a mapping"}},
		{"a flow list as the root", "[a, b]\n", 1, []string{"not a mapping"}},
		{"a scalar as the root", "just text\n", 1, []string{"not a mapping"}},
		{"a number as the root", "42\n", 1, []string{"not a mapping"}},
		{"a quoted scalar as the root", "\"version\"\n", 1, []string{"not a mapping"}},
		{"a marker and a list", "---\n- a\n", 2, []string{"not a mapping"}},

		// One document.
		{"a second document", good + "---\n" + good, 10, []string{"second document"}},
		{"a second document marker after the first marker", "---\n---\n" + good, 2, []string{"second document"}},
		{"a second document after a comment", "# c\n---\n" + good + "---\n", 12, []string{"second document"}},
		{"a document marker after content", with("name: Example\n", "name: Example\n---\n"), 3, []string{"second document"}},
		{"a document marker with text after it", "--- text\n" + good, 1, []string{"after ---"}},
		{"a document marker with a mapping on its line", "--- {a: b}\n", 1, []string{"after ---"}},
		{"a document marker after a comment and content", good + "\n--- # again\n", 11, []string{"second document"}},
		{"an end marker", good + "...\n", 10, []string{"end marker"}},
		{"an end marker in the middle", with("name: Example\n", "name: Example\n...\n"), 3, []string{"end marker"}},
		{"an end marker and another document", good + "...\n---\n" + good, 10, []string{"end marker"}},
		{"an end marker with a comment", good + "... # end\n", 10, []string{"end marker"}},
		{"a YAML directive", "%YAML 1.2\n---\n" + good, 1, []string{"directive"}},
		{"a TAG directive", "%TAG ! tag:example.org,2026:\n---\n" + good, 1, []string{"directive"}},
		{"a directive after content", good + "%YAML 1.2\n", 10, []string{"directive"}},

		// What a tree can hold.
		{"an anchor", with("name: Example", "name: &n Example"), 2, []string{"anchor"}},
		{"an anchor on a mapping", with("policy:", "policy: &p"), 4, []string{"anchor"}},
		{"an anchor on a list entry", with("[piv, openpgp-card, aws-kms]", "[&a piv, openpgp-card, aws-kms]"), 5, []string{"anchor"}},
		{"an anchor on a key", with("name: Example", "&k name: Example"), 2, []string{"anchor"}},
		{"an anchor on an unused value", good + "x: &a 1\n", 10, []string{"anchor"}},
		{"an anchor and a tag on a value", with("name: Example", "name: &n !t Example"), 2, []string{"an anchor: a file has none"}},
		{"a tag and an anchor on a value", with("name: Example", "name: !t &n Example"), 2, []string{"a file has none"}},
		{"an alias after an anchor", with("name: Example", "name: &n Example\nrelease_address: *n"), 2, []string{"anchor"}},
		{"an alias to nothing", with("name: Example", "name: *n"), -1, []string{"YAML"}},
		{"a merge key", with("policy:\n", "<<: {a: 1}\npolicy:\n"), 4, []string{"merge key"}},
		{"a merge key with an alias", "base: &b {a: 1}\n<<: *b\n" + good, 1, []string{"anchor"}},
		{"a merge key of a list", "<<: [{a: 1}]\n" + good, 1, []string{"merge key"}},
		{"a merge key after the others", good + "<<: {a: 1}\n", 10, []string{"merge key"}},
		{"the tag !!str", with("name: Example", "name: !!str Example"), 2, []string{"tag"}},
		{"the tag !!int", with("validity_months: 13", "validity_months: !!int 13"), 9, []string{"tag"}},
		{"the tag !!bool", with("require_name_constraints: true", "require_name_constraints: !!bool true"), 8, []string{"tag"}},
		{"a custom tag", with("name: Example", "name: !custom Example"), 2, []string{"tag"}},
		{"a verbatim tag", with("name: Example", "name: !<tag:example.org,2026:x> Example"), 2, []string{"tag"}},
		{"the tag !!map", with("policy:", "policy: !!map"), 4, []string{"tag"}},
		{"the tag !!seq", with("[piv, openpgp-card, aws-kms]", "!!seq [piv, openpgp-card, aws-kms]"), 5, []string{"tag"}},
		{"the tag !!binary", with("name: Example", "name: !!binary RXhhbXBsZQ=="), 2, []string{"tag"}},
		{"the tag !!null", with("name: Example", "name: !!null"), 2, []string{"tag"}},
		{"the tag !!float", with("name: Example", "name: !!float 1.5"), 2, []string{"tag"}},
		{"a tag on a key", with("name: Example", "!!str name: Example"), 2, []string{"tag"}},
		{"a tag on the root", "!!map\n" + good, 1, []string{"tag"}},
		{"a tag in a list", with("[piv, openpgp-card, aws-kms]", "[!!str piv, openpgp-card, aws-kms]"), 5, []string{"tag"}},
		{"a repeated key", good + "name: Other\n", 10, []string{"appears twice"}},
		{"a repeated key in a nested mapping", with("  min_firmware: 5.7.0\n", "  min_firmware: 5.7.0\n  min_firmware: 5.8.0\n"), 7, []string{"appears twice"}},
		{"a repeated key, quoted and plain", good + "\"name\": Other\n", 10, []string{"appears twice"}},
		{"a repeated key, single-quoted", good + "'name': Other\n", 10, []string{"appears twice"}},
		{"a repeated key in a flow mapping", with("name: Example", "x: {a: 1, a: 2}"), 2, []string{"appears twice"}},
		{"a repeated key at the top of a flow root", "{version: 1, version: 1}\n", 1, []string{"appears twice"}},
		{"a repeated key that differs by case is another key", with("name: Example", "name: Example\nName: Example"), 3, []string{"not known"}},
		{"a complex key at the start of a line", with("name: Example", "? name\n: Example"), 2, []string{"complex key"}},
		{"a complex key with no key", with("name: Example", "?\n: Example"), 2, []string{"complex key"}},
		{"a complex key that is a list", with("name: Example", "? [a, b]\n: Example"), 2, []string{"complex key"}},
		{"a complex key in a nested mapping", with("  min_firmware: 5.7.0", "  ? min_firmware\n  : 5.7.0"), 6, []string{"complex key"}},
		{"a key that is a list in flow", "{[a]: 1}\n", 1, []string{"not a string"}},
		{"a key that is a mapping in flow", "{{a: b}: 1}\n", 1, []string{"not a string"}},
		{"a flow complex key that is a list", "{? [a]: 1}\n", 1, []string{"not a string"}},
		{"a number as a key", with("name: Example", "1: x"), 2, []string{"key is not a string", "quotes"}},
		{"true as a key", with("name: Example", "true: x"), 2, []string{"key is not a string"}},
		{"yes as a key is a string, and not a member", with("name: Example", "yes: x"), 2, []string{"not known"}},
		{"null as a key", with("name: Example", "null: x"), 2, []string{"null"}},
		{"a tilde as a key", with("name: Example", "~: x"), 2, []string{"null"}},
		{"a float as a key", with("name: Example", "1.5: x"), 2, []string{"key is not a string"}},
		{"a date as a key", with("name: Example", "2024-01-01: x"), 2, []string{"key is not a string"}},
		{"an unquoted account number as a key", with("name: Example", "000000000000: x"), 2, []string{"key is not a string", "quotes"}},
		{"a number as a key in a nested mapping", with("  min_firmware: 5.7.0", "  1: 5.7.0"), 6, []string{"key is not a string"}},
		{"a NUL written as an escape in a name", with("name: Example", `name: "Exa\x00mple"`), 2, []string{"name"}},
		{"a bidirectional control written as an escape in a name", with("name: Example", `name: "Exa\u202emple"`), 2, []string{"name"}},
		{"a line feed written as an escape in a name", with("name: Example", `name: "Exa\nmple"`), 2, []string{"name"}},
		{"a non-ASCII address written as an escape", with("release@example.org", `a\u202e@example.org`), -1, nil},
		{"an escape in a key", with("name: Example", `"na\u202eme": Example`), 2, []string{"not known"}},
		{"null written null", with("name: Example", "name: null"), 2, []string{"null"}},
		{"null written Null", with("name: Example", "name: Null"), 2, []string{"null"}},
		{"null written NULL", with("name: Example", "name: NULL"), 2, []string{"null"}},
		{"null written as a tilde", with("name: Example", "name: ~"), 2, []string{"null"}},
		{"an empty value", with("name: Example", "name:"), 2, []string{"null or an empty value"}},
		{"an empty value before a comment", with("name: Example", "name: # none"), 2, []string{"null or an empty value"}},
		{"an empty list entry", with("[piv, openpgp-card, aws-kms]", "\n    - piv\n    -"), 7, []string{"null"}},
		{"a null in a flow list", with("[piv, openpgp-card, aws-kms]", "[piv, ~]"), 5, []string{"null"}},
		{"an empty flow list entry", with("[piv, openpgp-card, aws-kms]", "[piv, , aws-kms]"), -1, nil},
		{"a null mapping", "version: 1\nname: Example\nrelease_address: release@example.org\npolicy: ~\n", 4, []string{"null"}},
		{"a null in an unknown member", good + "x: null\n", 10, []string{"null"}},
		{"a key with no value", good + "lonely\n", -1, nil},
		{"a malformed mapping", "a: b: c\n", -1, []string{"not valid YAML"}},
		{"an unterminated flow list", "x: [a, b\n", -1, nil},
		{"an unterminated quote", with("name: Example", "name: \"Example"), -1, nil},
		{"a flow list closed twice", "x: [a]]\n", -1, nil},
		{"indentation that goes back to nothing", "a:\n    b: 1\n  c: 2\n", -1, nil},
	}
	return rows
}

func TestStrictYAMLRefusesWhatItShould(t *testing.T) {
	rows := strictRows()
	if len(rows) < 100 {
		t.Fatalf("only %d rows: a check that finds nothing to check fails", len(rows))
	}
	seen := map[string]bool{}
	for _, r := range rows {
		if seen[r.name] {
			t.Fatalf("the row %q is twice in the table", r.name)
		}
		seen[r.name] = true
		t.Run(r.name, func(t *testing.T) {
			_ = refuseSettings(t, r.text, r.line, r.words...)
		})
	}
}

// A file that strict YAML refuses is refused by every reader that shares it, with the path of that file.
func TestEveryReaderOfAFileRefusesWhatStrictYAMLRefuses(t *testing.T) {
	settings := mustSettings(t, goodSettings)
	for _, r := range strictRows() {
		bad := r.text
		t.Run(r.name, func(t *testing.T) {
			if len(r.words) == 0 && r.line < 0 {
				return // the rows whose refusal comes from the library's own error text
			}
			// The delegation and root readers apply the same rules to the bytes. A text built for the settings can
			// also be refused for another cause by them, so only the rows whose fault is in the strict layer count.
			if _, err := wanted.ParseRoot("x509", []byte(bad)); err == nil {
				t.Errorf("ParseRoot accepts it")
			} else {
				_ = wantFault(t, err, "want/roots/x509.yaml", -1)
			}
			if _, err := wanted.ParseDelegation("example", []byte(bad), settings); err == nil {
				t.Errorf("ParseDelegation accepts it")
			} else {
				_ = wantFault(t, err, "want/delegations/example.yaml", -1)
			}
		})
	}
}

func TestAnAliasBombIsRefusedAtTheFirstAnchorAndAtOnce(t *testing.T) {
	// Nine levels of nine aliases would expand to 9^9 values; the file is refused before anything expands.
	var b strings.Builder
	b.WriteString("a: &a0 [x, x, x, x, x, x, x, x, x]\n")
	for i := 1; i <= 9; i++ {
		b.WriteString("a" + string(rune('0'+i)) + ": &a" + string(rune('0'+i)) + " [")
		for j := 0; j < 9; j++ {
			if j > 0 {
				b.WriteString(", ")
			}
			b.WriteString("*a" + string(rune('0'+i-1)))
		}
		b.WriteString("]\n")
	}
	_ = refuseSettings(t, b.String(), 1, "anchor")
	if _, err := wanted.ParseRoot("x509", []byte(b.String())); err == nil {
		t.Error("ParseRoot accepts an alias bomb")
	}
}

func TestADeepFlowNestingIsRefusedAtTheLimitAndNeverCrashes(t *testing.T) {
	for _, depth := range []int{17, 100, 1000, 10000, 100000, 1000000} {
		t.Run(strings.Repeat("x", 0)+itoa(depth), func(t *testing.T) {
			text := "x: " + strings.Repeat("[", depth) + strings.Repeat("]", depth) + "\n"
			if len(text) > wanted.MaxBytes {
				_ = refuseSettings(t, text, 0, "longer than")
				return
			}
			e := refuseSettings(t, text, -1)
			if !strings.Contains(e.Msg, "nested more than 16 levels") && !strings.Contains(e.Msg, "YAML") {
				t.Errorf("message %q", e.Msg)
			}
		})
	}
	// Unterminated, so the library meets the depth before anything closes.
	_ = refuseSettings(t, "x: "+strings.Repeat("[", 200000)+"\n", -1)
}

func TestADeepBlockNestingIsRefusedAndNeverCrashes(t *testing.T) {
	for _, depth := range []int{17, 200, 5000} {
		var b strings.Builder
		for i := 0; i < depth; i++ {
			b.WriteString(strings.Repeat(" ", i) + "- ")
			if i < depth-1 {
				b.WriteString("\n")
			}
		}
		b.WriteString("x\n")
		text := "x:\n" + b.String()
		if len(text) > wanted.MaxBytes {
			continue
		}
		t.Run(itoa(depth), func(t *testing.T) {
			_ = refuseSettings(t, text, -1)
		})
	}
	for _, depth := range []int{17, 300} {
		var b strings.Builder
		for i := 0; i < depth; i++ {
			b.WriteString(strings.Repeat(" ", i) + "a:\n")
		}
		b.WriteString(strings.Repeat(" ", depth) + "a: 1\n")
		t.Run("mappings "+itoa(depth), func(t *testing.T) {
			e := refuseSettings(t, b.String(), -1)
			if !strings.Contains(e.Msg, "nested more than 16 levels") && !strings.Contains(e.Msg, "not known") {
				t.Errorf("message %q", e.Msg)
			}
		})
	}
}

// nested makes a file whose one member x holds mappings nested so that the whole file has depth levels,
// counting the root mapping as level 1.
func nested(depth int) string {
	var b strings.Builder
	for i := 0; i < depth-1; i++ {
		b.WriteString(strings.Repeat(" ", i) + "x:\n")
	}
	b.WriteString(strings.Repeat(" ", depth-1) + "x: 1\n")
	return b.String()
}

func TestSixteenLevelsPassTheLimitAndSeventeenDoNot(t *testing.T) {
	// The members of this file are not the file's, so the reader refuses it anyway; what tells the two cases apart is
	// the reason: a file at the limit is read to the end and refused for its member, one over it is refused for its depth.
	at := refuseSettings(t, nested(16), 1, "not known")
	if strings.Contains(at.Msg, "nested") {
		t.Errorf("sixteen levels refused for depth: %s", at.Msg)
	}
	over := refuseSettings(t, nested(17), 17, "nested more than 16 levels")
	_ = over
	// A scalar adds no level, a list that holds a mapping adds two.
	seq := "a:\n" + strings.Repeat("  - ", 1) + "b: 1\n"
	_ = refuseSettings(t, seq, 1, "not known")
	deepSeq := "a: " + strings.Repeat("[", 15) + "x" + strings.Repeat("]", 15) + "\n" // root + 15 lists = 16 levels
	_ = refuseSettings(t, deepSeq, 1, "not known")
	tooDeepSeq := "a: " + strings.Repeat("[", 16) + "x" + strings.Repeat("]", 16) + "\n" // 17 levels
	_ = refuseSettings(t, tooDeepSeq, 1, "nested more than 16 levels")
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var d []byte
	for n > 0 {
		d = append([]byte{byte('0' + n%10)}, d...)
		n /= 10
	}
	return string(d)
}

// listOfNodes makes a file with one member whose list has n entries; the file has the root, the key, the list
// and the n entries: n+3 nodes.
func listOfNodes(n int) string {
	return "x: [" + strings.TrimSuffix(strings.Repeat("a, ", n), ", ") + "]\n"
}

func TestTenThousandNodesPassTheLimitAndOneMoreDoesNot(t *testing.T) {
	at := refuseSettings(t, listOfNodes(wanted.MaxNodes-3), 1, "not known")
	if strings.Contains(at.Msg, "nodes") {
		t.Errorf("10,000 nodes refused for their number: %s", at.Msg)
	}
	e := refuseSettings(t, listOfNodes(wanted.MaxNodes-2), 1, "more than 10000 nodes")
	_ = e
	// Keys count as nodes: a mapping of 5,000 pairs is 10,001 nodes with the root.
	var b strings.Builder
	for i := 0; i < 5000; i++ {
		b.WriteString("k" + itoa(i) + ": 1\n")
	}
	_ = refuseSettings(t, b.String(), -1, "more than 10000 nodes")
	// And 4,999 pairs are 9,999 nodes: read to the end and refused for the first unknown member.
	b.Reset()
	for i := 0; i < 4999; i++ {
		b.WriteString("k" + itoa(i) + ": 1\n")
	}
	if e := refuseSettings(t, b.String(), 1, "not known"); strings.Contains(e.Msg, "nodes") {
		t.Errorf("9,999 nodes refused for their number")
	}
}

func TestAFileOfMaxBytesIsReadAndOneByteMoreIsNotParsed(t *testing.T) {
	pad := func(n int) string {
		head := goodSettings + "# "
		fill := n - len(head) - 1
		if fill < 0 {
			t.Fatal("the file is shorter than its head")
		}
		return head + strings.Repeat("x", fill) + "\n"
	}
	exact := pad(wanted.MaxBytes)
	if len(exact) != wanted.MaxBytes {
		t.Fatalf("the test file has %d bytes", len(exact))
	}
	s := mustSettings(t, exact)
	if len(s.File.Data) != wanted.MaxBytes {
		t.Errorf("the file kept %d bytes", len(s.File.Data))
	}
	over := pad(wanted.MaxBytes + 1)
	e := refuseSettings(t, over, 0, "longer than")
	if !strings.Contains(e.Msg, "262144") {
		t.Errorf("the message does not say the limit: %s", e.Msg)
	}
	// A file that is too long for YAML as well as for the limit is refused for the limit, before its text is read:
	// there is no line, even when a bad byte stands in the first line.
	bad := "\xff" + strings.Repeat("x", wanted.MaxBytes)
	_ = refuseSettings(t, bad, 0, "longer than")
	// Delegation and root readers have the same limit.
	big := goodRoot + "# " + strings.Repeat("x", wanted.MaxBytes)
	if _, err := wanted.ParseRoot("x509", []byte(big)); err == nil {
		t.Error("ParseRoot reads a file over the limit")
	} else {
		_ = wantFault(t, err, "want/roots/x509.yaml", 0, "longer than")
	}
	if _, err := wanted.ParseDelegation("example", []byte(goodX509Delegation+"# "+strings.Repeat("x", wanted.MaxBytes)), mustSettings(t, goodSettings)); err == nil {
		t.Error("ParseDelegation reads a file over the limit")
	} else {
		_ = wantFault(t, err, "want/delegations/example.yaml", 0, "longer than")
	}
}

func TestAMessageHoldsOnlyAShortEscapedPieceOfTheFile(t *testing.T) {
	long := strings.Repeat("a", 100)
	e := refuseSettings(t, goodSettings+long+": 1\n", 10, "not known")
	if strings.Contains(e.Msg, long) || !strings.Contains(e.Msg, strings.Repeat("a", 40)+"...") {
		t.Errorf("the member name is not cut at 40 characters: %s", e.Msg)
	}
	e = refuseSettings(t, goodSettings+"a\u00e9\U0001f600: 1\n", 10, "not known")
	for _, w := range []string{`\u00e9`, `\ud83d\ude00`} {
		if !strings.Contains(e.Msg, w) {
			t.Errorf("the message does not hold the escape %s: %s", w, e.Msg)
		}
	}
	// A repeated key shows the key, escaped.
	e = refuseSettings(t, goodSettings+"k\u00e9: 1\nk\u00e9: 2\n", 11, "appears twice")
	if !strings.Contains(e.Msg, `k\u00e9`) {
		t.Errorf("the repeated key is not shown escaped: %s", e.Msg)
	}
	// The text of an error of the library is cut and escaped as well.
	e = refuseSettings(t, "x: [a\n"+strings.Repeat("\u00e9", 200)+"\n", -1)
	if len(e.Msg) > 200 {
		t.Errorf("the message of a library error is %d bytes: %s", len(e.Msg), e.Msg)
	}
}

// The page says "no tags". The non-specific tag, a lone exclamation mark, is a tag: it must be refused wherever a
// tag is, on a value, on a key and on a mapping, as the other tags are.
func TestTheNonSpecificTagIsRefusedLikeEveryOtherTag(t *testing.T) {
	good := goodSettings
	for name, text := range map[string]string{
		"on a value":   strings.Replace(good, "name: Example", "name: ! Example", 1),
		"on a key":     strings.Replace(good, "name: Example", "! name: Example", 1),
		"on a mapping": strings.Replace(good, "policy:", "policy: !", 1),
		"on a list":    strings.Replace(good, "[piv, openpgp-card, aws-kms]", "! [piv, openpgp-card, aws-kms]", 1),
		"in a list":    strings.Replace(good, "[piv, openpgp-card, aws-kms]", "[! piv, openpgp-card, aws-kms]", 1),
	} {
		t.Run(name, func(t *testing.T) {
			s, err := wanted.ParseSettings(settingsPath, []byte(text))
			if err == nil {
				t.Fatalf("accepted, with the name %q", s.Name)
			}
			_ = wantFault(t, err, settingsPath, -1, "tag")
		})
	}
}

// The text of an error of the library can hold a piece of the file (the name of an alias that has no anchor), so it
// is cut and escaped like every other text from the file.
func TestTheTextOfALibraryErrorHoldsNoLongPieceOfTheFile(t *testing.T) {
	name := strings.Repeat("a", 300)
	e := refuseSettings(t, strings.Replace(goodSettings, "name: Example", "name: *"+name, 1), -1, "not valid YAML")
	if strings.Contains(e.Msg, strings.Repeat("a", 90)) || len(e.Msg) > 140 {
		t.Errorf("the message holds a long piece of the file (%d bytes): %s", len(e.Msg), e.Msg)
	}
}

func TestAMemberNameIsCutAtFortyCharactersAndNotBefore(t *testing.T) {
	for n, cut := range map[int]bool{39: false, 40: false, 41: true, 42: true} {
		name := strings.Repeat("b", n)
		e := refuseSettings(t, goodSettings+name+": 1\n", 10, "not known")
		if got := strings.Contains(e.Msg, "..."); got != cut {
			t.Errorf("a name of %d characters: cut %v, want %v: %s", n, got, cut, e.Msg)
		}
		if shown := strings.Count(strings.ReplaceAll(e.Msg, "member", ""), "b"); shown != min(n, 40) {
			t.Errorf("a name of %d characters shows %d of them", n, shown)
		}
	}
}

// The bare "!" is a tag that the library drops without a mark, so a scan of the text refuses it where it starts a
// token. Every place a value, a key or a flow item can stand is tried, in the three readers, and each file is
// first read without the "!" to show that the "!" is the only fault.
func TestABareBangThatStartsATokenIsRefusedInEveryPlace(t *testing.T) {
	const flowPolicy = "policy: {stores: [piv], min_firmware: 5.7.0, pin_policy: [once], require_name_constraints: true, validity_months: 13}\n"
	head := "version: 1\nname: Example\nrelease_address: release@example.org\n"
	for name, c := range map[string]struct{ ok, bad string }{
		"a block value":              {head + flowPolicy, head + strings.Replace(flowPolicy, "validity_months: 13", "validity_months: ! 13", 1)},
		"a flow list item":           {head + flowPolicy, head + strings.Replace(flowPolicy, "[piv]", "[! piv]", 1)},
		"a flow list item after one": {head + flowPolicy, head + strings.Replace(flowPolicy, "[once]", "[once, ! always]", 1)},
		"a flow key":                 {head + flowPolicy, head + strings.Replace(flowPolicy, "{stores", "{! stores", 1)},
		"a flow key after a comma":   {head + flowPolicy, head + strings.Replace(flowPolicy, "min_firmware", "! min_firmware", 1)},
		"a flow mapping":             {head + flowPolicy, head + strings.Replace(flowPolicy, "policy: {", "policy: ! {", 1)},
		"a flow list":                {head + flowPolicy, head + strings.Replace(flowPolicy, "stores: [", "stores: ! [", 1)},
		"a boolean":                  {goodSettings, strings.Replace(goodSettings, "true", "! true", 1)},
		"a number":                   {goodSettings, strings.Replace(goodSettings, ": 13", ": ! 13", 1)},
		"a version":                  {goodSettings, strings.Replace(goodSettings, "version: 1", "version: ! 1", 1)},
		"a firmware version":         {goodSettings, strings.Replace(goodSettings, "5.7.0", "! 5.7.0", 1)},
		"the first key":              {goodSettings, "! " + goodSettings},
		"a key in a block mapping":   {goodSettings, strings.Replace(goodSettings, "  stores:", "  ! stores:", 1)},
		"the value on its own line":  {goodSettings, strings.Replace(goodSettings, "name: Example", "name:\n  ! Example", 1)},
		"after a comment line":       {goodSettings, "# a comment\n" + strings.Replace(goodSettings, "name: Example", "name: ! Example", 1)},
		"a quoted key":               {goodSettings, strings.Replace(goodSettings, "name: Example", "\"name\": ! Example", 1)},
		"a single-quoted key":        {goodSettings, strings.Replace(goodSettings, "name: Example", "'name': ! Example", 1)},
		"after a quoted value":       {goodSettings, strings.Replace(goodSettings, "name: Example", "name: \"Example\"\nversion2: ! 1", 1)},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := wanted.ParseSettings(settingsPath, []byte(c.ok)); err != nil {
				t.Fatalf("the file without the bang is refused: %v", err)
			}
			_, err := wanted.ParseSettings(settingsPath, []byte(c.bad))
			e := wantFault(t, err, settingsPath, -1, "a tag: a file has none")
			if e.Line < 1 {
				t.Errorf("no line: %+v", e)
			}
			if lines := strings.Split(c.bad, "\n"); e.Line > len(lines) || !strings.Contains(lines[e.Line-1], "!") {
				t.Errorf("line %d does not hold the bang", e.Line)
			}
		})
	}
}

// A bare "!" that ends a flow collection or stands alone after a colon at the end of a line is not YAML: the library
// refuses it with its own words, and so does every reader. The refusal is by the library and not by the tag rule, so
// the test wants "not valid YAML" and a line, and the file without the bang to be accepted.
func TestABareBangThatIsNotYAMLIsRefusedByEveryReader(t *testing.T) {
	const flowPolicy = "policy: {stores: [piv], min_firmware: 5.7.0, pin_policy: [once], require_name_constraints: true, validity_months: 13}\n"
	head := "version: 1\nname: Example\nrelease_address: release@example.org\n"
	for name, c := range map[string]struct{ ok, bad string }{
		"a flow value, bare":             {head + flowPolicy, head + strings.Replace(flowPolicy, "validity_months: 13", "validity_months: !", 1)},
		"a flow list item, bare":         {head + flowPolicy, head + strings.Replace(flowPolicy, "[piv]", "[piv, !]", 1)},
		"the last flow list item, bare":  {head + flowPolicy, head + strings.Replace(flowPolicy, "[once]", "[once, !]", 1)},
		"a flow mapping value, bare":     {head + flowPolicy, head + strings.Replace(flowPolicy, "require_name_constraints: true", "require_name_constraints: !", 1)},
		"a bang alone on a line":         {goodSettings, strings.Replace(goodSettings, "name: Example", "name:\n! Example", 1)},
		"a bang alone after a key colon": {goodSettings, strings.Replace(goodSettings, "release_address: release@example.org", "release_address:\n! release@example.org", 1)},
		"a bang in a list of its own":    {goodSettings, goodSettings + "extra: [!]\n"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := wanted.ParseSettings(settingsPath, []byte(c.ok)); err != nil {
				t.Fatalf("the file without the bang is refused: %v", err)
			}
			s, err := wanted.ParseSettings(settingsPath, []byte(c.bad))
			if s != nil {
				t.Fatalf("accepted: %q", c.bad)
			}
			e := wantFault(t, err, settingsPath, -1, "not valid YAML")
			if e.Line < 1 {
				t.Errorf("no line: %+v", e)
			}
		})
	}
	flowRoles := "version: 1\ntype: openpgp-subkey\nroot: acme-release\ncapability: sign\nkms_read_roles: {\"111122223333\": !}\n"
	_ = refuseDelegation(t, flowRoles, -1, "not valid YAML")
	_ = refuseDelegation(t, "version: 1\ntype: x509-intermediate\nroot: acme-tls\npermitted_dns_names: [example.org, !]\n", -1, "not valid YAML")
	_ = refuseRoot(t, "version: 1\nkind: x509\ntest: [!]\n", -1, "not valid YAML")
	_ = refuseRoot(t, "version: 1\nkind: x509\ntest: {a: !}\n", -1, "not valid YAML")
	_ = refuseRoot(t, "version: 1\nkind:\n! x509\n", -1, "not valid YAML")
}

// A "!" that starts a node is a tag in every language of the file: the column of a node counts characters, not
// bytes, so a key or a value with characters of two, three or four bytes before the bang must not hide it.
func TestABareBangAfterNonASCIITextIsRefusedAtTheRightLine(t *testing.T) {
	const kids = "name: Example\nrelease_address: release@example.org\n"
	for name, lead := range map[string]string{
		"two bytes":   "\u00e9",
		"three bytes": "\u65e5\u672c",
		"four bytes":  "\U0001F600",
		"mixed":       "a\u00e9\u65e5\U0001F600",
	} {
		for form, c := range map[string]struct{ text string }{
			"a flow key":           {"version: 1\n" + kids + "policy: {\"" + lead + "\": x, stores: [piv], ! min_firmware: 5.7.0}\n"},
			"a value after quoted": {"version: 1\n" + kids + "policy: {\"" + lead + "\": ! x}\n"},
			"a flow item":          {"version: 1\n" + kids + "policy: {stores: [\"" + lead + "\", ! piv]}\n"},
			"a block value":        {"version: 1\n" + kids + "keyring: \"" + lead + "\"\nvalidity_months: ! 13\n"},
			"after a comment":      {"version: 1\n# " + lead + "\n" + kids + "validity_months: ! 13\n"},
			"a key itself":         {"version: 1\n" + kids + lead + ": 1\n! " + lead + "2: 1\n"},
		} {
			t.Run(name+" "+form, func(t *testing.T) {
				_, err := wanted.ParseSettings(settingsPath, []byte(c.text))
				e := wantFault(t, err, settingsPath, -1, "a tag: a file has none")
				lines := strings.Split(c.text, "\n")
				if e.Line < 1 || e.Line > len(lines) || !strings.Contains(lines[e.Line-1], "!") {
					t.Errorf("line %d does not hold the bang", e.Line)
				}
			})
		}
	}
}

func TestABareBangIsRefusedInADelegationAndInARootFile(t *testing.T) {
	arn := "arn:aws:iam::111122223333:role/example-certifier-read"
	flowOK := "version: 1\ntype: openpgp-subkey\nroot: acme-release\ncapability: sign\nkms_read_roles: {\"111122223333\": " + arn + "}\n"
	if d, err := wanted.ParseDelegation("example", []byte(flowOK), mustSettings(t, goodSettings)); err != nil || !d.Valid() {
		t.Fatalf("the file without the bang is refused: %v", err)
	}
	for name, text := range map[string]string{
		"a key of the account map":                  strings.Replace(flowOK, "{\"111", "{! \"111", 1),
		"the value of the account map":              strings.Replace(flowOK, "\": arn", "\": ! arn", 1),
		"the value after a quoted key and no space": strings.Replace(flowOK, "\": arn", "\":! arn", 1),
		"the map":                strings.Replace(flowOK, "kms_read_roles: {", "kms_read_roles: ! {", 1),
		"the type":               strings.Replace(flowOK, "type: openpgp-subkey", "type: ! openpgp-subkey", 1),
		"the root":               strings.Replace(flowOK, "root: acme-release", "root: !", 1),
		"a block account key":    strings.Replace(goodOpenPGPDelegation, "  \"111122223333\":", "  ! \"111122223333\":", 1),
		"a block account value":  strings.Replace(goodOpenPGPDelegation, "333\": arn", "333\": ! arn", 1),
		"a list entry":           strings.Replace(goodX509Delegation, "[example.org]", "[! example.org]", 1),
		"a list entry after one": strings.Replace(goodX509Delegation, "permitted_dns_names: [example.org]", "permitted_dns_names: [example.org, ! example.net]", 1),
		"a block list entry":     "version: 1\ntype: x509-intermediate\nroot: acme-tls\npermitted_dns_names:\n  - ! example.org\n",
	} {
		t.Run("delegation "+name, func(t *testing.T) {
			_ = refuseDelegation(t, text, -1, "a tag: a file has none")
		})
	}
	for name, text := range map[string]string{
		"a version":      "version: ! 1\nkind: x509\n",
		"a kind":         "version: 1\nkind: ! x509\n",
		"the test":       "version: 1\nkind: x509\ntest: ! false\n",
		"the test, bare": "version: 1\nkind: x509\ntest: !\n",
		"a key":          "version: 1\n! kind: x509\n",
	} {
		t.Run("root "+name, func(t *testing.T) {
			_ = refuseRoot(t, text, -1, "a tag: a file has none")
		})
	}
}

// A "!" that is a character of a text is not a tag: in a plain value, a quoted text, a comment and a block scalar.
// Each file is judged by its own member rules, so a file that fails one of them must not fail as a tag.
func TestABangThatIsATextIsNotRefusedAsATag(t *testing.T) {
	for name, tail := range map[string]string{
		"a plain value":           "release_address: u!v@example.org\n",
		"a plain value, last":     "release_address: release@example.org!\n",
		"a quoted value":          "release_address: \"u!v@example.org\"\n",
		"a single-quoted value":   "release_address: 'u!v@example.org'\n",
		"a comment on the value":  "release_address: release@example.org # ! a note\n",
		"a comment of its own":    "release_address: release@example.org\n# ! a note\n",
		"a comment after a quote": "release_address: \"release@example.org\" # ! a note\n",
	} {
		t.Run(name, func(t *testing.T) {
			text := strings.Replace(goodSettings, "release_address: release@example.org\n", tail, 1)
			s, err := wanted.ParseSettings(settingsPath, []byte(text))
			if err != nil {
				if strings.Contains(err.Error(), "a tag") {
					t.Fatalf("refused as a tag: %v", err)
				}
				// A file that another rule refuses is fine here; the rule is not the tag rule.
				return
			}
			if !strings.Contains(s.ReleaseAddress, "@example.org") {
				t.Errorf("the address is %q", s.ReleaseAddress)
			}
		})
	}
	// A member that no file may hold: its refusal is the member rule, in the words of that rule.
	for name, text := range map[string]string{
		"a plain value":              "x: Hello!\n",
		"a plain value with a comma": "x: a, !y\n",
		"a plain value with a space": "x: a !b\n",
		"double quotes":              "x: \"! b\"\n",
		"double quotes with a colon": "x: \"a: ! b\"\n",
		"single quotes":              "x: '! b'\n",
		"a block scalar":             "x: |\n  ! b\n",
		"a block scalar, folded":     "x: >\n  ! b\n  c: ! d\n",
		"a comment":                  "# ! x\nx: 1\n",
		"a key with a bang":          "x!: 1\n",
		"a quoted key with a bang":   "\"! x\": 1\n",
	} {
		t.Run("member "+name, func(t *testing.T) {
			e := refuseSettings(t, goodSettings+text, -1, "not known")
			if strings.Contains(e.Msg, "tag") {
				t.Errorf("refused as a tag: %s", e.Msg)
			}
		})
	}
}

// The bang rule did not replace the rule for every other tag: the walk of the tree still refuses a named tag and a
// core tag, and the scan names the line first.
func TestANamedTagIsStillRefusedWithItsLine(t *testing.T) {
	for name, text := range map[string]string{
		"a named tag":    strings.Replace(goodSettings, "name: Example", "name: !custom Example", 1),
		"a core tag":     strings.Replace(goodSettings, "name: Example", "name: !!str Example", 1),
		"a verbatim tag": strings.Replace(goodSettings, "name: Example", "name: !<tag:example.org,2024:x> Example", 1),
		"a tag on a key": strings.Replace(goodSettings, "name: Example", "!!str name: Example", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if e := refuseSettings(t, text, 2, "a tag"); e.Msg != "a tag: a file has none" {
				t.Errorf("the words of the fault are %q", e.Msg)
			}
		})
	}
}

// A block scalar whose header stands on a line of its own (the key is on the line before) is valid YAML. The scan of
// the text must not take the rest of the file for the text of that scalar: a "!" on a later line starts a token.
func TestABareBangAfterABlockScalarOnItsOwnLineIsRefused(t *testing.T) {
	const policy = "policy:\n  stores: [piv]\n  min_firmware: 5.7.0\n  pin_policy: [once]\n  require_name_constraints: true\n  validity_months: 13\n"
	for name, c := range map[string]struct{ ok, bad string }{
		"a literal scalar, strip": {
			"version: 1\nname: Example\nrelease_address:\n|-\n release@example.org\n" + policy,
			"version: 1\nname: Example\nrelease_address:\n|-\n release@example.org\n" + strings.Replace(policy, "months: 13", "months: ! 13", 1),
		},
		"a folded scalar, strip": {
			"version: 1\nname: Example\nrelease_address:\n>-\n release@example.org\n" + policy,
			"version: 1\nname: Example\nrelease_address:\n>-\n release@example.org\n" + strings.Replace(policy, "constraints: true", "constraints: ! true", 1),
		},
	} {
		t.Run(name, func(t *testing.T) {
			s, err := wanted.ParseSettings(settingsPath, []byte(c.ok))
			if err != nil || s.ReleaseAddress != "release@example.org" {
				t.Fatalf("the file without the bang is refused or misread: %v", err)
			}
			_, err = wanted.ParseSettings(settingsPath, []byte(c.bad))
			_ = wantFault(t, err, settingsPath, -1, "a tag: a file has none")
		})
	}
}

// In a flow mapping a colon that follows a quoted key is the value indicator whatever comes after it, and a space
// may stand between the key and the colon. A "!" after it starts a token.
func TestABareBangAfterAQuotedFlowKeyThatHasASpaceBeforeTheColonIsRefused(t *testing.T) {
	const head = "version: 1\nname: Example\nrelease_address: release@example.org\n"
	const policy = "policy: {stores: [piv], min_firmware: 5.7.0, pin_policy: [once], require_name_constraints: true, \"validity_months\"%s13}\n"
	good := head + strings.Replace(policy, "%s", ": ", 1)
	if _, err := wanted.ParseSettings(settingsPath, []byte(good)); err != nil {
		t.Fatalf("the file without the bang is refused: %v", err)
	}
	for name, sep := range map[string]string{"one space": " :! ", "two spaces": "  :! ", "no space": ":! "} {
		t.Run(name, func(t *testing.T) {
			_, err := wanted.ParseSettings(settingsPath, []byte(head+strings.Replace(policy, "%s", sep, 1)))
			_ = wantFault(t, err, settingsPath, -1, "a tag: a file has none")
		})
	}
}

// The scan of the text and the walk of the tree both refuse a tag, so that one holds when the other misses. A named
// tag after the key indicator of a flow collection, with no space between them, is seen by the tree.
func TestTheWalkOfTheTreeRefusesATagThatTheScanOfTheTextDoesNotSee(t *testing.T) {
	const head = "version: 1\nname: Example\nrelease_address: release@example.org\n"
	for name, policy := range map[string]string{
		"a key in a flow mapping": "policy: {?!x stores: [piv], min_firmware: 5.7.0, pin_policy: [once], require_name_constraints: true, validity_months: 13}\n",
		"an item of a flow list":  "policy: {stores: [?!x piv], min_firmware: 5.7.0, pin_policy: [once], require_name_constraints: true, validity_months: 13}\n",
		"a key after another":     "policy: {stores: [piv], min_firmware: 5.7.0, ?!!str pin_policy: [once], require_name_constraints: true, validity_months: 13}\n",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := wanted.ParseSettings(settingsPath, []byte(head+policy))
			_ = wantFault(t, err, settingsPath, 4, "a tag")
		})
	}
}

// A plain value may go on at the next line, and that line may start with a quote: the quote is then a character of
// the value and opens no quoted text. A "!" on a later line starts a token all the same.
func TestABareBangAfterAQuoteThatStartsAContinuationLineIsRefused(t *testing.T) {
	const policy = "policy:\n  stores: [piv]\n  min_firmware: 5.7.0\n  pin_policy: [once]\n  require_name_constraints: true\n  validity_months: %s\n"
	for name, cont := range map[string]string{
		"a double quote":                 "    \"x\n",
		"a single quote":                 "    'x\n",
		"a double quote and a backslash": "    \"x\\\n",
		"a bracket, which fails closed":  "    [\n",
	} {
		t.Run(name, func(t *testing.T) {
			head := "version: 1\nname: Example\nrelease_address: release@example.org\nkeyring:\n  license: MIT\n" + cont
			s, err := wanted.ParseSettings(settingsPath, []byte(head+strings.Replace(policy, "%s", "13", 1)))
			if err != nil || s.Policy.ValidityMonths != 13 {
				t.Fatalf("the file without the bang is refused: %v", err)
			}
			_, err = wanted.ParseSettings(settingsPath, []byte(head+strings.Replace(policy, "%s", "! 13", 1)))
			_ = wantFault(t, err, settingsPath, -1, "a tag: a file has none")
		})
	}
}
