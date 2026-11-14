package wanted

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strconv"
	"unicode"
	"unicode/utf8"

	"go.yaml.in/yaml/v3"
)

// tagMsg is the text of the fault of a tag.
const tagMsg = "a tag: a file has none"

// The limits of a file. They hold before a file is typed: a file over [MaxBytes] is refused before it is
// parsed, and a tree over the limits is refused before any member is read.
const (
	// MaxBytes is the largest wanted file that is read: 256 KiB, the limit of a JSON file (proposed).
	MaxBytes = 256 << 10
	// MaxDepth is the deepest nesting that a file may have: the root mapping is level 1.
	MaxDepth = 16
	// MaxNodes is the most nodes that a file may have, keys and values together.
	MaxNodes = 10000
)

// File is a wanted file as stored: its path in the bundle, its bytes as they were read and the SHA-256 of
// the bytes as 64 lower-case hexadecimal digits, which `sha256sum` gives too (record 0005, rule 6). The
// bytes are a copy that the parser made, and are never written again.
type File struct {
	// Path is the path of the file in the bundle, with "/" as the separator.
	Path string
	// Data is the content of the file, exactly as it was read.
	Data []byte
	// SHA256 is the digest of Data.
	SHA256 string
}

// newFile makes a File with a copy of data.
func newFile(path string, data []byte) File {
	sum := sha256.Sum256(data)
	return File{Path: path, Data: slices.Clone(data), SHA256: hex.EncodeToString(sum[:])}
}

// document is a file that has passed the rules of strict YAML: its text, its tree and the file it came from.
// The root is a mapping, and nothing in the tree is an anchor, an alias, a tag or a null.
type document struct {
	file File
	root *yaml.Node
}

// fail makes an error at the line of a node.
func (d *document) fail(n *yaml.Node, msg string) *Error {
	line := 0
	if n != nil {
		line = n.Line
	}
	return errorf(d.file.Path, line, msg)
}

// read applies the rules of strict YAML to the bytes of one file and returns the document, or an
// [*Error]. It does not look at a member.
func read(path string, data []byte) (*document, error) {
	if len(data) > MaxBytes {
		return nil, errorf(path, 0, fmt.Sprintf("the file is longer than %d bytes", MaxBytes))
	}
	if err := scanText(path, data); err != nil {
		return nil, err
	}
	if err := scanLines(path, data); err != nil {
		return nil, err
	}
	root, err := parse(path, data)
	if err != nil {
		return nil, err
	}
	d := &document{file: newFile(path, data), root: root}
	if root.Kind != yaml.MappingNode {
		return nil, d.fail(root, "the document is not a mapping")
	}
	w := &walker{d: d, lines: bytes.Split(data, []byte("\n"))}
	if err := w.walk(root, 1); err != nil {
		return nil, err
	}
	return d, nil
}

// scanText refuses the characters that a wanted file does not hold, anywhere in it, comments included:
// bytes that are not UTF-8, a byte order mark, a carriage return, a tab, any other control character, a
// format character and the two separators U+2028 and U+2029. Only LF is allowed. The line of the first
// fault is in the error.
func scanText(path string, data []byte) error {
	line := 1
	for i := 0; i < len(data); {
		r, size := utf8.DecodeRune(data[i:])
		switch {
		case r == utf8.RuneError && size <= 1:
			return errorf(path, line, "the text is not valid UTF-8")
		case r == 0xFEFF && i == 0:
			return errorf(path, line, "the file starts with a byte order mark")
		case r == '\n':
			line++
		case r == '\r':
			return errorf(path, line, "a carriage return: lines end with LF only")
		case r == '\t':
			return errorf(path, line, "a tab: indent with spaces")
		case unicode.Is(unicode.Cc, r):
			return errorf(path, line, fmt.Sprintf("a control character U+%04X", r))
		case unicode.Is(unicode.Cf, r):
			return errorf(path, line, fmt.Sprintf("a format character U+%04X", r))
		case r == 0x2028 || r == 0x2029:
			return errorf(path, line, fmt.Sprintf("a line separator U+%04X", r))
		}
		i += size
	}
	return nil
}

// scanLines refuses what the tree of a document cannot show: a directive, a document marker that is not
// the first line of content, the end marker "...", and an explicit key ("? "). A marker is a line that
// starts in column 0.
func scanLines(path string, data []byte) error {
	seenContent := false
	seenStart := false
	for i, line := range bytes.Split(data, []byte("\n")) {
		n := i + 1
		switch {
		case len(line) > 0 && line[0] == '%':
			return errorf(path, n, "a directive: a file has none")
		case isMarker(line, "---"):
			if seenStart || seenContent {
				return errorf(path, n, "a second document: a file holds one document, and --- may only stand at its start")
			}
			seenStart = true
			if rest := bytes.TrimLeft(line[3:], " "); len(rest) > 0 && rest[0] != '#' {
				return errorf(path, n, "the content starts on the line after ---")
			}
			continue
		case isMarker(line, "..."):
			return errorf(path, n, "a document end marker: a file has none")
		}
		trimmed := bytes.TrimLeft(line, " ")
		if len(trimmed) == 0 || trimmed[0] == '#' {
			continue
		}
		seenContent = true
		if trimmed[0] == '?' && (len(trimmed) == 1 || trimmed[1] == ' ') {
			return errorf(path, n, "a complex key: write the key on the line of its value")
		}
	}
	return nil
}

// bangAt tells whether the source text of the node n starts with "!": that is a tag, and a bare "!" (the
// non-specific tag) among them. The library puts the start of a node that has a tag at its tag, and drops a bare
// "!" without a mark in the tree, so a value that follows it would be read in two ways (as typed, or as a
// string). A plain value cannot start with "!", and a "!" inside a text is not at the start of its node, so no
// text is mistaken. lines are the lines of the file; the column of the node counts characters, not bytes. A node
// the library gives no position (line 0) is not a tag.
func bangAt(lines [][]byte, n *yaml.Node) bool {
	if n.Line < 1 || n.Line > len(lines) || n.Column < 1 {
		return false
	}
	l, off := lines[n.Line-1], 0
	for c := 1; c < n.Column && off < len(l); c++ {
		_, size := utf8.DecodeRune(l[off:])
		off += size
	}
	return off < len(l) && l[off] == '!'
}

// firstBang returns the first node of the tree, in the order of the file, whose text starts with "!", or nil.
func firstBang(lines [][]byte, n *yaml.Node) *yaml.Node {
	if bangAt(lines, n) {
		return n
	}
	for _, c := range n.Content {
		if b := firstBang(lines, c); b != nil {
			return b
		}
	}
	return nil
}

// scanTags refuses a node of the text whose source starts with "!" and passes any other text, also a text that is
// not YAML: it reads the first document of the bytes by itself and leaves every other fault to [read]. [read] does
// not call it, because it has the tree already and refuses the same nodes in its walk; it is the check on a text
// alone, for a test.
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

// isMarker tells whether the line is the marker m alone or m followed by a space.
func isMarker(line []byte, m string) bool {
	return bytes.Equal(line, []byte(m)) || bytes.HasPrefix(line, []byte(m+" "))
}

// yamlLine finds the line number in the text of an error of the library.
var yamlLine = regexp.MustCompile(`line ([0-9]{1,9})`)

// parse reads the bytes into a tree of nodes with the library, which reads the file once. It returns the root
// of the one document. A panic of the library is an error.
func parse(path string, data []byte) (root *yaml.Node, err error) {
	defer func() {
		if r := recover(); r != nil {
			root, err = nil, errorf(path, 0, "the text could not be read as YAML")
		}
	}()
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var doc yaml.Node
	if err := dec.Decode(&doc); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errorf(path, 0, "the file holds no document")
		}
		return nil, libraryError(path, err)
	}
	var second yaml.Node
	if err := dec.Decode(&second); !errors.Is(err, io.EOF) {
		return nil, errorf(path, 0, "a second document: a file holds one document")
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 {
		return nil, errorf(path, doc.Line, "the file holds no document")
	}
	return doc.Content[0], nil
}

// libraryError turns the error of the library into an error of this package: the line, and the text of the
// library cut and escaped, because the text can hold a piece of the file.
func libraryError(path string, err error) *Error {
	msg := err.Error()
	line := 0
	if m := yamlLine.FindStringSubmatch(msg); m != nil {
		line, _ = strconv.Atoi(m[1])
	}
	return errorf(path, line, "not valid YAML: "+shownN(msg, 80))
}

// walker walks the tree once, counting nodes, and refuses what strict YAML refuses and the tree shows.
type walker struct {
	d     *document
	lines [][]byte // the lines of the file, to find the text at the position of a node
	nodes int
}

// walk checks the node n at the level depth and every node below it. A level is a mapping or a sequence that holds
// another: the root mapping is level 1, and a scalar does not add a level.
func (w *walker) walk(n *yaml.Node, depth int) error {
	if (n.Kind == yaml.MappingNode || n.Kind == yaml.SequenceNode) && depth > MaxDepth {
		return w.d.fail(n, fmt.Sprintf("nested more than %d levels", MaxDepth))
	}
	if w.nodes++; w.nodes > MaxNodes {
		return w.d.fail(n, fmt.Sprintf("more than %d nodes", MaxNodes))
	}
	switch {
	case n.Kind == yaml.AliasNode:
		return w.d.fail(n, "an alias: a file has none")
	case n.Anchor != "":
		return w.d.fail(n, "an anchor: a file has none")
	case n.Style&yaml.TaggedStyle != 0, bangAt(w.lines, n):
		return w.d.fail(n, tagMsg)
	}
	switch n.Kind {
	case yaml.ScalarNode:
		if n.Tag == "!!null" {
			return w.d.fail(n, "a null or an empty value: leave the member out")
		}
	case yaml.SequenceNode:
		for _, c := range n.Content {
			if err := w.walk(c, depth+1); err != nil {
				return err
			}
		}
	case yaml.MappingNode:
		return w.walkMapping(n, depth)
	default:
		return w.d.fail(n, "a node that a file does not hold")
	}
	return nil
}

// walkMapping checks the keys of a mapping and walks its values. A key is a string, written plain or in
// quotes, and appears once.
func (w *walker) walkMapping(n *yaml.Node, depth int) error {
	if len(n.Content)%2 != 0 {
		return w.d.fail(n, "a mapping with a key and no value")
	}
	seen := make(map[string]bool, len(n.Content)/2)
	for i := 0; i < len(n.Content); i += 2 {
		key, val := n.Content[i], n.Content[i+1]
		if err := w.walk(key, depth+1); err != nil {
			return err
		}
		switch {
		case key.Kind != yaml.ScalarNode:
			return w.d.fail(key, "a key that is not a string")
		case key.Tag == "!!merge":
			return w.d.fail(key, "a merge key: a file has none")
		case key.Tag != "!!str":
			return w.d.fail(key, "the key is not a string: write it in quotes when it is a number or another word that YAML reads as a value")
		case seen[key.Value]:
			return w.d.fail(key, "the key \""+shown(key.Value)+"\" appears twice in one mapping")
		}
		seen[key.Value] = true
		if err := w.walk(val, depth+1); err != nil {
			return err
		}
	}
	return nil
}
