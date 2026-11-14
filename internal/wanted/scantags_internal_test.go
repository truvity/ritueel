package wanted

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// firstBang returns the first node of the tree, in the order of the file, whose text starts with "!", or nil. It uses
// one walker for the whole walk, the way the walk of a file does.
func firstBang(lines [][]byte, n *yaml.Node) *yaml.Node {
	return (&walker{lines: lines}).firstBang(n)
}

func (w *walker) firstBang(n *yaml.Node) *yaml.Node {
	if w.bangAt(n) {
		return n
	}
	for _, c := range n.Content {
		if b := w.firstBang(c); b != nil {
			return b
		}
	}
	return nil
}

// scanTags refuses a node of the text whose source starts with "!" and passes any other text, also a text that is
// not YAML: it reads the first document of the bytes by itself and leaves every other fault to [read]. It is the
// check on a text alone, for these tests.
func scanTags(path string, data []byte) (err error) {
	defer func() {
		if recover() != nil {
			err = nil
		}
	}()
	var doc yaml.Node
	if yaml.Unmarshal(data, &doc) != nil {
		return nil
	}
	if n := firstBang(bytes.Split(data, []byte("\n")), &doc); n != nil {
		return errorf(path, n.Line, tagMsg)
	}
	return nil
}

// scanTags refuses a "!" that starts a token (a tag of any kind, the bare "!" among them: the library drops the
// bare one without a mark) and lets a "!" that is part of a text pass. The page says a file has no tags
// (docs/reference/bundle.md, "Strict YAML"). These rows are the scan on its own; the readers' own tests refuse the
// same files through the public functions.

// tagRefused rows: the text and the line of the fault. A text that the library does not read as YAML at all
// ("a: [b, !]", "a: {b: !}", "a:\n! b") is not a row: the library refuses it with its own words and the scan passes
// it on; the readers' tests hold those.
var tagRefused = []struct {
	name string
	text string
	line int
}{
	{"on a value", "a: ! b\n", 1},
	{"on a value, many spaces", "a:      ! b\n", 1},
	{"on an empty value", "a: !\n", 1},
	{"on a value at the end of the file with no newline", "a: !", 1},
	{"on a key", "! a: b\n", 1},
	{"on a line of its own", "a:\n  ! b\n", 2},
	{"on a line of its own, nested", "a:\n  b:\n    c:\n      ! d\n", 4},
	{"first in a list", "- ! a\n", 1},
	{"in a list in a list", "- - ! a\n", 1},
	{"in a list in a mapping", "a:\n  - b\n  - ! c\n", 3},
	{"in a mapping in a list", "- a: ! b\n", 1},
	{"after a key in a list", "- a: b\n  c: ! d\n", 2},
	{"a named tag", "a: !x b\n", 1},
	{"a core tag", "a: !!str b\n", 1},
	{"a verbatim tag", "a: !<tag:example.org,2024:x> b\n", 1},
	{"after a flow list opens", "a: [! b]\n", 1},
	{"after a flow list opens, many spaces", "a: [   ! b]\n", 1},
	{"after a comma in a flow list", "a: [b, ! c]\n", 1},
	{"after a comma with no space", "a: [b,! c]\n", 1},
	{"on the last item of a flow list", "a: [b, c, ! d]\n", 1},
	{"as an item of its own in a flow list", "a: [!, b]\n", 1},
	{"after a flow mapping opens", "a: {! b: c}\n", 1},
	{"on the value of a flow mapping", "a: {b: ! c}\n", 1},
	{"on the second value of a flow mapping", "a: {b: c, d: ! e}\n", 1},
	{"after the quoted key of a flow mapping", "a: {\"b\":! c}\n", 1},
	{"after the quoted key of a flow mapping with a space", "a: {\"b\": ! c}\n", 1},
	{"after the single-quoted key of a flow mapping", "a: {'b':! c}\n", 1},
	{"a flow list in a flow list", "a: [[b], [! c]]\n", 1},
	{"a flow mapping in a flow list", "a: [{b: ! c}]\n", 1},
	{"a flow list on the next line", "a: [b,\n  ! c]\n", 2},
	{"a flow mapping on the next line", "a: {b: c,\n  d: ! e}\n", 2},
	{"on the root of a flow mapping", "{a: ! b}\n", 1},
	{"on the whole value after a block scalar ends", "a: |\n  text\nb: ! 1\n", 3},
	{"after a block scalar with indicators ends", "a: |2-\n   text\nb: ! 1\n", 3},
	{"after a folded scalar ends", "a: >\n  text\nb: ! 1\n", 3},
	{"after a block scalar in a list ends", "- a: |\n    text\n  b: ! 1\n", 3},
	{"after a block scalar with a comment ends", "a: | # text\n  x\nb: ! 1\n", 3},
	{"after a block scalar that holds a blank line", "a: |\n  x\n\n  y\nb: ! 1\n", 5},
	{"after a block scalar that holds a bang", "a: |\n  ! x\nb: ! 1\n", 3},
	{"after a double-quoted text on one line", "a: \"x\"\nb: ! 1\n", 2},
	{"after a double-quoted text that has an escaped quote", "a: \"x\\\"\"\nb: ! 1\n", 2},
	{"after a single-quoted text with a doubled quote", "a: 'it''s'\nb: ! 1\n", 2},
	{"after a double-quoted text on three lines", "a: \"x\n  y\n  z\"\nb: ! 1\n", 4},
	{"after a single-quoted text on three lines", "a: 'x\n  y\n  z'\nb: ! 1\n", 4},
	{"after a comment", "# a bang !\na: ! b\n", 2},
	{"after a comment with a bang in a value line", "a: b # !\nc: ! d\n", 2},
	{"after a quoted key", "\"a\": ! b\n", 1},
	{"after a single-quoted key", "'a': ! b\n", 1},
	{"after an item that is a quoted text", "- \"a\"\n- ! b\n", 2},
	{"after an item that holds a plain value with a bang", "- a!\n- ! b\n", 2},
	{"an anchor is refused first, a tag on it as well", "a: ! &x b\n", 1},
	{"on a value after a long plain value", "a: Hello, World! a b c\nb: ! 1\n", 2},
	{"in a flow list after a quoted item", "a: [\"x\", ! y]\n", 1},
	{"in a flow list after a quoted item with a bang", "a: [\"x!\", ! y]\n", 1},
	{"in a flow list after a single-quoted item", "a: ['x', ! y]\n", 1},
	{"on a multi-line flow list opened on an earlier line", "a: [\n  b,\n  ! c\n]\n", 3},
	{"in the second line of a flow list that has a quote on the first", "a: [\"b\",\n  ! c]\n", 2},
	{"after a closing flow list on the same line", "a: [b]\nc: ! d\n", 2},
	{"after the end of a flow mapping on the same line", "a: {b: c}\nd: ! e\n", 2},
	{"a bang before a comment-looking text", "a: ! #b\n", 1},
	{"on a key of a flow mapping on the root", "{! a: b}\n", 1},
	{"on a list item that follows a key with a colon and a comment", "a: # c\n  ! b\n", 2},
	{"two lines after a block scalar ended", "a: |\n  x\nb: 1\nc: ! 2\n", 4},
	{"after a hash that is part of a plain item of a flow list", "a: [b#c, ! d]\n", 1},
	{"after a double quote inside a plain value", "a: x\"y\nb: ! 1\n", 2},
	{"after an apostrophe inside a plain value", "a: it's\nb: ! 1\n", 2},
	{"after a key indicator and a space in a flow list", "a: [? ! b]\n", 1},
	{"after a key indicator and a space in a flow mapping", "a: {? ! b: c}\n", 1},
	{"after a flow mapping that closed", "a: {b: c}\nd: ! e\n", 2},
}

// tagPassed rows: a "!" inside a text is a character, not a tag.
var tagPassed = []struct {
	name string
	text string
}{
	{"no bang at all", "a: b\n"},
	{"a bang at the end of a plain value", "a: Hello!\n"},
	{"a bang in the middle of a plain value", "a: He!lo\n"},
	{"a bang after a space in a plain value", "a: a !b\n"},
	{"a bang after a comma in a plain value of a block", "a: x, !y\n"},
	{"a bang after a colon with no space in a plain value", "a: x:!y\n"},
	{"a bang in an address", "a: u!v@example.org\n"},
	{"a bang in a key", "a!: b\n"},
	{"a bang in the middle of a key", "a!b: c\n"},
	{"a bang inside double quotes", "a: \"! b\"\n"},
	{"a bang after a colon and a space inside double quotes", "a: \"x: ! y\"\n"},
	{"a bang inside single quotes", "a: '! b'\n"},
	{"a bang after a colon and a space inside single quotes", "a: 'x: ! y'\n"},
	{"a bang after a bracket inside quotes", "a: \"[! x]\"\n"},
	{"a bang after a comma inside quotes", "a: \"x, ! y\"\n"},
	{"a bang inside a double-quoted text that goes on to the next line", "a: \"x\n  ! y\"\n"},
	{"a bang inside a single-quoted text that goes on to the next line", "a: 'x\n  ! y'\n"},
	{"a bang after an escaped quote in a double-quoted text", "a: \"x\\\" ! y\"\n"},
	{"a bang inside a double-quoted key", "\"! a\": b\n"},
	{"a bang inside a single-quoted key", "'! a': b\n"},
	{"a bang inside a quoted item of a flow list", "a: [\"! x\", 'y ! z']\n"},
	{"a bang inside a quoted key of a flow mapping", "a: {\"! x\": y}\n"},
	{"a bang in a comment", "# ! a\na: b\n"},
	{"a bang in a comment after a value", "a: b # ! c\n"},
	{"a bang in a comment after a flow list", "a: [b] # ! c\n"},
	{"a bang in a comment of its own after a key", "a: # ! b\n  c: d\n"},
	{"a bang first on a block scalar line", "a: |\n  ! b\n"},
	{"a bang first on a folded scalar line", "a: >\n  ! b\n"},
	{"a bang after a colon on a block scalar line", "a: |\n  x: ! y\n"},
	{"a bang on a block scalar line after a blank line", "a: |\n  x\n\n  ! y\n"},
	{"a bang on a block scalar line with a strip indicator", "a: |-\n  ! y\n"},
	{"a bang on a block scalar line with a keep indicator", "a: |+\n  ! y\n"},
	{"a bang on a block scalar line with an indent indicator", "a: |2\n   ! y\n"},
	{"a bang on a block scalar line with a comment on the header", "a: | # x\n  ! y\n"},
	{"a bang on a block scalar line in a list", "- |\n  ! y\n"},
	{"a bang on a block scalar line of a key in a list", "- a: |\n    ! y\n"},
	{"a bang on a block scalar line of a key two levels down", "a:\n  b: |\n    ! y\n"},
	{"a bang on a deeper block scalar line", "a: |\n  x\n    ! y\n"},
	{"a bang in a flow list inside a plain word", "a: [b!, c]\n"},
	{"a bang first in a flow item that is a word with a bang", "a: [b, c!d]\n"},
	{"a bang after a dash with no space", "a: -!\n"},
	{"a bang after a question mark with no space", "a: ?!\n"},
	{"a bang in a list item", "- a!\n"},
	{"a bang after a hash with no space", "a: b#!c\n"},
	{"a colon and a bang after an escaped quote in a double-quoted text", "a: \"x\\\": ! y\"\n"},
	{"a colon and a bang in a comment after a value", "a: b # x: ! c\n"},
	{"a comma and a bang in a plain value after a flow mapping closed", "a: {b: c}\nd: x, !y\n"},
	{"a bang on a block scalar line indented by one under a list item", "- |\n ! x\n"},
	{"a bang on a block scalar line indented by one under a nested list item", "a:\n  - |\n   ! x\n"},
	{"a bang on a block scalar line indented by one under a key", "a: |\n ! y\n"},
	{"a bang on a block scalar line indented by one under a nested key", "a:\n  b: |\n   ! y\n"},
	{"an anchor is no bang", "a: &x b\n"},
	{"an alias is no bang", "a: &x b\nc: *x\n"},
	{"a bang that starts a continuation line of a plain value", "a: b\n  ! c\n"},
	{"a bang that starts two continuation lines of a plain value", "a: b\n  c\n  ! d\n"},
	{"a bang after a quote that starts a continuation line", "a: x\n \"y\nb: z!\n"},
}

func TestAnyTagThatStartsATokenIsRefusedWithItsLine(t *testing.T) {
	for _, r := range tagRefused {
		t.Run(r.name, func(t *testing.T) {
			err := scanTags("f.yaml", []byte(r.text))
			if err == nil {
				t.Fatalf("accepted: %q", r.text)
			}
			var e *Error
			ok := errors.As(err, &e)
			if !ok || e.Line != r.line || e.Path != "f.yaml" || !strings.Contains(e.Msg, "a tag") {
				t.Fatalf("got %#v, want line %d and a tag", err, r.line)
			}
		})
	}
}

func TestABangThatIsPartOfATextIsNotATag(t *testing.T) {
	for _, r := range tagPassed {
		t.Run(r.name, func(t *testing.T) {
			if err := scanTags("f.yaml", []byte(r.text)); err != nil {
				t.Fatalf("refused %q: %v", r.text, err)
			}
		})
	}
}

// taggedInTree tells whether the library marks any node of the text as tagged. A node that holds an anchor is left
// out with its tag: an anchor is refused by its own rule, whatever follows it, and the library puts the position of
// such a node at the anchor, not at the tag.
func taggedInTree(n *yaml.Node) bool {
	if n.Anchor == "" && n.Style&yaml.TaggedStyle != 0 {
		return true
	}
	for _, c := range n.Content {
		if taggedInTree(c) {
			return true
		}
	}
	return false
}

// The scan and the walk of the tree must refuse the same tags: when the library marks a node as tagged, the text
// at the position of that node starts with "!", wherever the node stands (after a key indicator, after a quote that
// starts a continuation line, in a flow collection). A bare "!" is the one tag the tree does not show; the scan
// treats it like the others. No outside program runs: only bytes in memory.
func FuzzScanTagsRefusesEveryTagTheTreeShows(f *testing.F) {
	for _, r := range tagRefused {
		f.Add([]byte(r.text))
		f.Add([]byte(strings.ReplaceAll(r.text, "! ", "!x ")))
		f.Add([]byte(strings.ReplaceAll(r.text, "!", "!!str")))
	}
	for _, r := range tagPassed {
		f.Add([]byte(r.text))
	}
	f.Add([]byte("a: [?! b]\n"))
	f.Add([]byte("a: x\n \"y\nb: ! 1\n"))
	f.Add([]byte("a: {\"\u00e9\" :! 1}\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		// The scan runs after the checks of the text and of the lines, which refuse tabs, controls and markers.
		if scanText("f.yaml", data) != nil || scanLines("f.yaml", data) != nil {
			return
		}
		err := scanTags("f.yaml", data)
		if err != nil {
			var e *Error
			if !errors.As(err, &e) || e.Line < 1 || !strings.Contains(e.Msg, "a tag") {
				t.Fatalf("the fault is %#v", err)
			}
			return
		}
		var n yaml.Node
		if yaml.Unmarshal(data, &n) == nil && taggedInTree(&n) {
			t.Fatalf("the tree shows a tag and the scan passed: %q", data)
		}
	})
}

// In a flow collection a "?" is the key indicator when it is followed by anything, not only by a space, so a tag
// may follow it with no space between them. The page says a file has no tags, so these files are refused.
func TestABareBangAfterAFlowKeyIndicatorIsRefused(t *testing.T) {
	for _, text := range []string{
		"a: [?! b]\n",
		"a: {?! b: c}\n",
		"a: {x: y, ?! b: c}\n",
		"a: [?!x b]\n",
		"a: [?   ! b]\n",
		"a: [? ! b]\n",
	} {
		if err := scanTags("f.yaml", []byte(text)); err == nil {
			t.Errorf("accepted: %q", text)
		}
	}
}

// A doubled quote inside a single-quoted text is a quote character, not the end of the text. The scan must neither
// take the text for finished (a "!" after a colon inside it is not a tag) nor lose the end of the quote (a "!" after
// the closing quote of a key is a tag).
func TestADoubledQuoteDoesNotEndASingleQuotedText(t *testing.T) {
	for _, text := range []string{
		"a: 'it''s: ! b'\n",
		"a: 'x'': ! y'\n",
		"a: '''': ! y'\n",
		"a: ['x'': ! y', 'z']\n",
		"'a''b: ! c': d\n",
	} {
		if err := scanTags("f.yaml", []byte(text)); err != nil {
			t.Errorf("refused a text with no tag: %q: %v", text, err)
		}
	}
	for _, text := range []string{
		"a: {'x''' :! 1}\n",
		"a: {'''':! 1}\n",
		"a: 'it''s'\nb: ! 1\n",
		"a: ['x''', ! y]\n",
	} {
		if err := scanTags("f.yaml", []byte(text)); err == nil {
			t.Errorf("accepted a tag: %q", text)
		}
	}
}

// bangAt reads the line and the column of a node (a column counts characters from 1) and says whether the text there
// starts with "!". A node with no usable position is not a tag.
func TestBangAtReadsTheTextAtTheLineAndColumnOfANode(t *testing.T) {
	lines := [][]byte{[]byte("a: ! b"), []byte("\u00e9\u65e5: !x"), []byte("\U0001F600!"), []byte(""), []byte("!")}
	for _, r := range []struct {
		name      string
		line, col int
		want      bool
	}{
		{"the bang of a line", 1, 4, true},
		{"the key before it", 1, 1, false},
		{"the space before it", 1, 3, false},
		{"the letter after it", 1, 6, false},
		{"after two-byte and three-byte characters", 2, 5, true},
		{"the two-byte character itself", 2, 1, false},
		{"the three-byte character itself", 2, 2, false},
		{"a bang after a four-byte character", 3, 2, true},
		{"the four-byte character", 3, 1, false},
		{"the bytes of a character are not columns", 3, 5, false},
		{"an empty line", 4, 1, false},
		{"the bang that is the whole line", 5, 1, true},
		{"one past the end of the last line", 5, 2, false},
		{"far past the end of the line", 1, 100, false},
		{"line zero is no position", 0, 1, false},
		{"a negative line", -1, 1, false},
		{"one past the last line", 6, 1, false},
		{"column zero is no position", 1, 0, false},
		{"a negative column", 1, -3, false},
		{"column zero on a line that starts with a bang", 5, 0, false},
		{"a negative column on a line that starts with a bang", 5, -1, false},
	} {
		t.Run(r.name, func(t *testing.T) {
			if got := (&walker{lines: lines}).bangAt(&yaml.Node{Line: r.line, Column: r.col}); got != r.want {
				t.Errorf("line %d column %d: %v, want %v", r.line, r.col, got, r.want)
			}
		})
	}
	if (&walker{}).bangAt(&yaml.Node{Line: 1, Column: 1}) {
		t.Error("no lines: no tag")
	}
}

// firstBang walks the tree in the order of the file and returns the first node whose text starts with "!".
func TestFirstBangIsTheFirstNodeInTheOrderOfTheFile(t *testing.T) {
	for _, r := range []struct {
		name, text string
		line       int // 0: none
	}{
		{"none", "a: b\nc: [d, e]\n", 0},
		{"the first of two", "a: ! b\nc: ! d\n", 1},
		{"a nested one before a later one", "a:\n  - x\n  - ! y\nb: ! z\n", 3},
		{"deep in a flow collection", "a: {b: [c, {d: ! e}]}\n", 1},
		{"in the last item only", "a:\n  b:\n    c:\n      - 1\n      - [2, ! 3]\n", 5},
		{"a key", "a: b\n! c: d\n", 2},
		{"a named tag is a bang as well", "a: b\nc: !!str d\n", 2},
		{"a tag on the root", "!!map\na: b\n", 1},
	} {
		t.Run(r.name, func(t *testing.T) {
			var doc yaml.Node
			if err := yaml.Unmarshal([]byte(r.text), &doc); err != nil {
				t.Fatal(err)
			}
			n := firstBang(bytes.Split([]byte(r.text), []byte("\n")), &doc)
			switch {
			case r.line == 0 && n != nil:
				t.Errorf("found a bang at line %d", n.Line)
			case r.line != 0 && (n == nil || n.Line != r.line):
				t.Errorf("found %v, want line %d", n, r.line)
			}
		})
	}
}

// scanTags is the check on a text alone: a text that is not YAML is no concern of it (the library refuses it in its
// own words, in read), it reads the first document only, and it never panics on bytes of any kind.
func TestScanTagsLeavesWhatIsNotItsToTheLibrary(t *testing.T) {
	for _, text := range []string{
		"",
		"\n",
		"# only a comment ! x\n",
		"a: [b, !]\n",
		"a: {b: !}\n",
		"a:\n! b\n",
		"a: [\n",
		"a: \"unclosed ! \n",
		"- - - - [ ! ",
		"a: b\n---\nc: ! d\n",
		"a: b\n...\n---\n! c\n",
		"\xff\xfe ! \x00",
	} {
		if err := scanTags("f.yaml", []byte(text)); err != nil {
			t.Errorf("refused %q: %v", text, err)
		}
	}
	// The fault carries the path given, the line of the node and the one text of a tag.
	err := scanTags("want/x.yaml", []byte("a: b\nc:\n  - d\n  - ! e\n"))
	var e *Error
	if !errors.As(err, &e) || e.Path != "want/x.yaml" || e.Line != 4 || e.Msg != tagMsg {
		t.Fatalf("got %#v", err)
	}
}

// The walk refuses a node whose text starts with "!" the same way in a key, a value, an item of a list and an item
// of a flow collection: one fault, the one text of a tag, the path and the line of the node.
func TestTheWalkRefusesABangInAKeyAValueAndAnItemWithOneText(t *testing.T) {
	for name, text := range map[string]string{
		"key":   "! a: b\n",
		"value": "a: ! b\n",
		"item":  "a:\n  - ! b\n",
		"flow":  "a: [! b]\n",
		"empty": "a: !\n",
		"named": "a: !b c\n",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := read("f.yaml", []byte(text))
			var e *Error
			if !errors.As(err, &e) || e.Msg != tagMsg || e.Path != "f.yaml" || e.Line < 1 {
				t.Fatalf("got %#v", err)
			}
		})
	}
}

// Whatever read accepts has no tagged node in the tree and no node whose text starts with "!", and whatever it
// refuses is an *Error with a line or the words of a limit. Only bytes in memory.
func FuzzReadAcceptsNoTag(f *testing.F) {
	for _, r := range tagRefused {
		f.Add([]byte(r.text))
	}
	for _, r := range tagPassed {
		f.Add([]byte(r.text))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		d, err := read("f.yaml", data)
		if err != nil {
			var e *Error
			if !errors.As(err, &e) || e.Msg == "" {
				t.Fatalf("the fault is %#v", err)
			}
			return
		}
		var n yaml.Node
		if yaml.Unmarshal(data, &n) != nil {
			t.Fatalf("read accepts a text that the library refuses: %q", data)
		}
		if taggedInTree(&n) || firstBang(bytes.Split(data, []byte("\n")), &n) != nil {
			t.Fatalf("read accepts a tag: %q", data)
		}
		if d.root == nil || d.root.Kind != yaml.MappingNode {
			t.Fatalf("read accepts a document that is not a mapping: %q", data)
		}
	})
}

// A flow list on one very long line, with the bang far from the start of the line (the column is large), is read in
// full: the bang is found at its own line, and the same file without it is not refused as a tag.
func TestABangFarFromTheStartOfALongLineIsFound(t *testing.T) {
	pad := strings.Repeat(" ", 60000)
	items := strings.Repeat("a, ", 3000)
	for _, r := range []struct {
		name, text string
		tag        bool
	}{
		{"none", "version: 1\nx: [" + pad + items + "b]\n", false},
		{"the last item", "version: 1\nx: [" + pad + items + "! b]\n", true},
		{"a bang inside a plain item", "version: 1\nx: [" + pad + items + "b!]\n", false},
		{"after a long non-ASCII run", "version: 1\nx: [\"" + strings.Repeat("日", 20000) + "\", ! b]\n", true},
	} {
		t.Run(r.name, func(t *testing.T) {
			_, err := read("f.yaml", []byte(r.text))
			var e *Error
			isTag := errors.As(err, &e) && e.Msg == tagMsg
			if isTag != r.tag {
				t.Fatalf("tag fault %v, want %v: %v", isTag, r.tag, err)
			}
			if r.tag && e.Line != 2 {
				t.Errorf("line %d, want 2", e.Line)
			}
		})
	}
}

// The walk refuses a node that the library marks as tagged wherever its position is, and a node whose text starts
// with "!" whatever its style: the two checks do not depend on each other. The nodes are made by hand.
func TestTheWalkHoldsTheTagStyleAndThePositionAsTwoChecks(t *testing.T) {
	lines := [][]byte{[]byte("x"), []byte("! y")}
	for _, r := range []struct {
		name string
		node yaml.Node
		tag  bool
	}{
		{"marked as tagged, text is not a bang", yaml.Node{Kind: yaml.ScalarNode, Style: yaml.TaggedStyle, Tag: "!!str", Value: "x", Line: 1, Column: 1}, true},
		{"not marked, text is a bang", yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "y", Line: 2, Column: 1}, true},
		{"not marked, text is not a bang", yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "y", Line: 2, Column: 3}, false},
		{"not marked, no position", yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "x"}, false},
	} {
		t.Run(r.name, func(t *testing.T) {
			w := &walker{d: &document{file: newFile("f.yaml", nil)}, lines: lines}
			err := w.walk(&r.node, 2)
			var e *Error
			if isTag := errors.As(err, &e) && e.Msg == tagMsg; isTag != r.tag {
				t.Fatalf("tag fault %v, want %v: %v", isTag, r.tag, err)
			}
		})
	}
}

// A line of two bare tags ("!0 !0") is read by the library as two documents, with no marker between them. A file holds
// one document, so it is refused in the words of that rule, whatever the second one holds.
func TestTwoDocumentsThatHaveNoMarkerBetweenThemAreRefused(t *testing.T) {
	for _, text := range []string{"!0 !0\n", "!0 !0", "! !\n", "!x !y\n"} {
		if _, err := read("f.yaml", []byte(text)); err == nil {
			t.Errorf("accepted %q", text)
		}
	}
	_, err := read("f.yaml", []byte("!0 !0\n"))
	var e *Error
	if !errors.As(err, &e) || e.Msg != "a second document: a file holds one document" || e.Line != 0 {
		t.Fatalf("got %#v", err)
	}
}

// wantBang is the answer of the plain rule, with no shortcut: the text at the column of the node (characters, from
// 1) starts with "!".
func wantBang(line []byte, col int) bool {
	if col < 1 {
		return false
	}
	runes := []rune(string(line))
	return col <= len(runes) && runes[col-1] == '!'
}

// The walker answers the same for every order of the lookups on one walker: up the columns of a line, down them, and
// in a mixed order, on lines of ASCII, of non-ASCII and of both, and across lines. This holds the restart of the
// cursor (a column below the last one) and its resume (a column at or above it).
func TestBangAtGivesTheSameAnswerInAnyOrderOfLookups(t *testing.T) {
	lines := [][]byte{
		[]byte("a: ! b, c: !d"),
		[]byte("é! 日!x \U0001F600! !é"),
		[]byte(""),
		[]byte("!日!日!"),
		[]byte("plain ! ascii !"),
	}
	type look struct{ line, col int }
	var all []look
	for i, l := range lines {
		for c := -1; c <= len([]rune(string(l)))+2; c++ {
			all = append(all, look{i + 1, c})
		}
	}
	orders := map[string][]look{"up": all}
	down := make([]look, len(all))
	mixed := make([]look, 0, len(all))
	for i, l := range all {
		down[len(all)-1-i] = l
	}
	// A fixed stride that visits every row once, so the columns and the lines jump about.
	for i := 0; i < len(all); i++ {
		mixed = append(mixed, all[(i*7)%len(all)])
	}
	orders["down"], orders["mixed"] = down, mixed
	for name, order := range orders {
		t.Run(name, func(t *testing.T) {
			w := &walker{lines: lines}
			for _, l := range order {
				want := wantBang(lines[l.line-1], l.col)
				if got := w.bangAt(&yaml.Node{Line: l.line, Column: l.col}); got != want {
					t.Fatalf("line %d column %d: %v, want %v", l.line, l.col, got, want)
				}
			}
		})
	}
}

// The count of the work, with no clock. On a line that is not ASCII a lookup at a column that is not below the last
// one counts on from the place the walker keeps, and a lookup below it starts again at the line start. A place that
// the walker was given by hand shows which of the two happened: the answer is the one of the place. The same holds
// on another line: the place of one line is no place of another.
func TestBangAtCountsOnFromTheLastColumnOfALineThatIsNotASCII(t *testing.T) {
	// Columns: 1 to 4 are the four characters of the first word, 5 is "!". The bytes: three each, so "!" is at 12.
	line := []byte("日日日日!x")
	bang := &yaml.Node{Line: 1, Column: 5}
	if got := (&walker{lines: [][]byte{line}}).bangAt(bang); !got {
		t.Fatal("the bang at column 5 is not found on a fresh walker")
	}
	// The place says: column 4 starts at byte 12, which is the byte of the bang. A lookup of column 5 that counts on
	// from there steps over the bang and finds "x".
	w := &walker{lines: [][]byte{line}, cur: cursor{line: 1, col: 4, off: 12}}
	if w.bangAt(bang) {
		t.Error("a lookup at a higher column did not count on from the last place")
	}
	if w.cur != (cursor{line: 1, col: 5, off: 13}) {
		t.Errorf("the place after the lookup is %+v", w.cur)
	}
	// The same column again counts on from itself: nothing to step over.
	w = &walker{lines: [][]byte{line}, cur: cursor{line: 1, col: 5, off: 12}}
	if !w.bangAt(bang) {
		t.Error("a lookup at the column of the last place did not use it")
	}
	// A column below the place starts again at the line start, and the answer is the true one.
	w = &walker{lines: [][]byte{line}, cur: cursor{line: 1, col: 6, off: 99}}
	if !w.bangAt(bang) {
		t.Error("a lookup below the last place did not start again")
	}
	if w.cur != (cursor{line: 1, col: 5, off: 12}) {
		t.Errorf("the place after the restart is %+v", w.cur)
	}
	// The place of another line is not used.
	w = &walker{lines: [][]byte{line}, cur: cursor{line: 2, col: 4, off: 12}}
	if !w.bangAt(bang) {
		t.Error("the place of another line was used")
	}
	// A column past the end gives the end of the line, and no bang.
	w = &walker{lines: [][]byte{line}}
	if w.bangAt(&yaml.Node{Line: 1, Column: 50}) || w.cur.off != len(line) {
		t.Errorf("past the end: place %+v", w.cur)
	}
}

// A line of ASCII is indexed by the column: the walker never counts on it, so its place stays empty, and a line that
// is not ASCII is marked once.
func TestBangAtDoesNotCountOnALineOfASCII(t *testing.T) {
	lines := [][]byte{[]byte("a: [b, ! c]"), []byte("é: !")}
	w := &walker{lines: lines}
	for c := 1; c <= 12; c++ {
		_ = w.bangAt(&yaml.Node{Line: 1, Column: c})
	}
	if w.cur != (cursor{}) {
		t.Errorf("the walker counted on a line of ASCII: %+v", w.cur)
	}
	if w.ascii[0] != asciiYes {
		t.Errorf("line 1 is marked %d", w.ascii[0])
	}
	if !w.bangAt(&yaml.Node{Line: 2, Column: 4}) || w.ascii[1] != asciiNo || w.cur.line != 2 {
		t.Errorf("line 2: marked %d, place %+v", w.ascii[1], w.cur)
	}
}

// The weaker form of the time bound: the files are near the size limit, with thousands of nodes after one very long
// run on one line, and the test has no clock but the default timeout of go test. Where the scan of the line start
// is done again for every node, these files take seconds. The count of the work is held by the two tests above.
func TestAFileNearTheSizeLimitIsReadWithOneLongLine(t *testing.T) {
	items := strings.Repeat("a, ", 4000)
	for name, run := range map[string]string{
		"a run of spaces":            strings.Repeat(" ", 200000),
		"a run of non-ASCII letters": "\"" + strings.Repeat("日", 60000) + "\", ",
	} {
		for _, tag := range []bool{false, true} {
			text := "version: 1\nx: [" + run + items
			if tag {
				text += "! b]\n"
			} else {
				text += "b]\n"
			}
			if len(text) > MaxBytes {
				t.Fatalf("%s: %d bytes, the limit is %d", name, len(text), MaxBytes)
			}
			t.Run(name, func(t *testing.T) {
				_, err := read("f.yaml", []byte(text))
				var e *Error
				isTag := errors.As(err, &e) && e.Msg == tagMsg
				if isTag != tag || (tag && e.Line != 2) {
					t.Fatalf("tag fault %v, want %v: %v", isTag, tag, err)
				}
			})
		}
	}
}
