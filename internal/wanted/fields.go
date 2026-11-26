package wanted

import (
	"fmt"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"
)

// member is one member of a mapping of a wanted file: its name, whether it is always required (a member
// that is required only in some cases is checked by the code of its file), and the values it may have when it
// has a fixed set. The tables of members are the one place that names them: the reader refuses what is not in
// its table, and a test compares the tables with the schemas of docs/reference/bundle.md.
type member struct {
	name     string
	required bool
	enum     []string
}

// The fixed sets of values.
var (
	kindEnum  = []string{"personal"}
	storeEnum = []string{"piv", "openpgp-card", "aws-kms", "software"}
	// personalStoreEnum are the stores of a personal bundle: the primary is a software key that the person adopts
	// (record 0008, rule 6) and the subkeys are on an OpenPGP card (rule 9). A piv slot holds no key of a person
	// (the road not taken in record 0008), and a primary in a cloud key service is not covered for a person yet
	// (rule 8).
	personalStoreEnum = []string{"openpgp-card", "software"}
	pinPolicyEnum     = []string{"never", "once", "always"}
	typeEnum          = []string{TypeX509Intermediate, TypeOpenPGPSubkey, TypeSSHCAKey}
	capabilityEnum    = []string{"sign", "authenticate"}
	useEnum           = []string{"user", "host"}
	rootKindEnum      = []string{string(RootX509), string(RootOpenPGP), string(RootSSH)}
	// The fixed sets of a card file (docs/reference/cards.md, "The card file").
	cardKindEnum    = []string{string(CardRoot), string(CardDayToDay), string(CardServer), string(CardRehearsal)}
	applicationEnum = []string{string(AppPIV), string(AppOpenPGP), string(AppFIDO2)}
)

// mapping is a mapping node of a document whose members were checked against a table: no member is unknown,
// and every always-required member is there.
type mapping struct {
	d    *document
	ctx  string // "" for the top of the file, else the name of the member this mapping is the value of
	node *yaml.Node
	val  map[string]*yaml.Node
	key  map[string]*yaml.Node
}

// what names a member in a message: "policy.stores", or "version" at the top.
func (m *mapping) what(name string) string {
	if m.ctx == "" {
		return name
	}
	return m.ctx + "." + name
}

// mappingOf reads n as a mapping whose members are in the table. An unknown member is an error that names it,
// at its line, and so is a required member that is missing, at the line of the mapping. ctx names the member
// that holds the mapping ("" for the file's own).
func (d *document) mappingOf(n *yaml.Node, ctx string, table []member) (*mapping, error) {
	m := &mapping{d: d, ctx: ctx, node: n, val: map[string]*yaml.Node{}, key: map[string]*yaml.Node{}}
	if n.Kind != yaml.MappingNode {
		return nil, d.fail(n, ctxWord(ctx)+"must be a mapping")
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, v := n.Content[i], n.Content[i+1]
		if !slices.ContainsFunc(table, func(t member) bool { return t.name == k.Value }) {
			return nil, d.fail(k, ctxIn(ctx)+"the member \""+shown(k.Value)+"\" is not known")
		}
		m.val[k.Value], m.key[k.Value] = v, k
	}
	for _, t := range table {
		if t.required && m.val[t.name] == nil {
			return nil, d.fail(n, "the member "+m.what(t.name)+" is required")
		}
	}
	return m, nil
}

// ctxWord is the start of a sentence about the whole mapping that a member holds.
func ctxWord(ctx string) string {
	if ctx == "" {
		return "the document "
	}
	return ctx + " "
}

// ctxIn is the start of a sentence about a member of a mapping.
func ctxIn(ctx string) string {
	if ctx == "" {
		return ""
	}
	return ctx + ": "
}

// has reports whether the member is there.
func (m *mapping) has(name string) bool { return m.val[name] != nil }

// fail makes an error at the line of a member's key, or of the mapping.
func (m *mapping) fail(name, msg string) *Error {
	if k := m.key[name]; k != nil {
		return m.d.fail(k, msg)
	}
	return m.d.fail(m.node, msg)
}

// str reads the member as a string. A plain scalar that the library reads as another type (a number, a
// boolean, a date) is not a string: it is an error that says to write it in quotes.
func (m *mapping) str(name string) (string, error) {
	v := m.val[name]
	switch {
	case v.Kind != yaml.ScalarNode:
		return "", m.d.fail(v, m.what(name)+" must be a string")
	case v.Tag != "!!str":
		return "", m.d.fail(v, m.what(name)+" must be a string: write it in quotes when it looks like a number, a boolean or a date")
	}
	return v.Value, nil
}

// enumStr reads the member as one of a fixed set.
func (m *mapping) enumStr(name string, set []string) (string, error) {
	s, err := m.str(name)
	if err != nil {
		return "", err
	}
	if !slices.Contains(set, s) {
		return "", m.d.fail(m.val[name], m.what(name)+" must be one of "+strings.Join(set, ", "))
	}
	return s, nil
}

// boolean reads the member as a boolean: the plain word true or false, and no other spelling.
func (m *mapping) boolean(name string) (bool, error) {
	v := m.val[name]
	if v.Kind == yaml.ScalarNode && v.Tag == "!!bool" {
		switch v.Value {
		case "true":
			return true, nil
		case "false":
			return false, nil
		}
	}
	return false, m.d.fail(v, m.what(name)+" must be true or false, written plain in lower case")
}

// integer reads the member as an integer: plain decimal digits, no sign, no leading zero, no underscore and
// at most nine digits.
func (m *mapping) integer(name string) (int, error) {
	return m.intNode(m.val[name], m.what(name))
}

// intNode reads one node as an integer by the rule of [mapping.integer]; at names it in a message.
func (m *mapping) intNode(v *yaml.Node, at string) (int, error) {
	if v.Kind != yaml.ScalarNode || v.Tag != "!!int" || !plainInteger(v.Value) {
		return 0, m.d.fail(v, at+" must be an integer of plain decimal digits: no sign, no leading zero, no underscore, at most nine digits")
	}
	n := 0
	for _, c := range v.Value {
		n = n*10 + int(c-'0')
	}
	return n, nil
}

// integers reads the member as a list of integers, in flow or block style, of at most most entries, each from
// lo to hi and none twice. The length is checked before the first entry is read. An empty list is a list.
func (m *mapping) integers(name string, most, lo, hi int) ([]int, error) {
	v := m.val[name]
	if v.Kind != yaml.SequenceNode {
		return nil, m.d.fail(v, m.what(name)+" must be a list")
	}
	if len(v.Content) > most {
		return nil, m.d.fail(v, m.what(name)+fmt.Sprintf(" must hold at most %d entries", most))
	}
	out := make([]int, 0, len(v.Content))
	for i, e := range v.Content {
		at := fmt.Sprintf("%s entry %d", m.what(name), i+1)
		n, err := m.intNode(e, at)
		if err != nil {
			return nil, err
		}
		if n < lo || n > hi {
			return nil, m.d.fail(e, at+fmt.Sprintf(" must be from %d to %d", lo, hi))
		}
		if slices.Contains(out, n) {
			return nil, m.d.fail(e, at+" repeats an earlier entry")
		}
		out = append(out, n)
	}
	return out, nil
}

// plainInteger tells whether s is 0, or one to nine decimal digits with no leading zero.
func plainInteger(s string) bool {
	if s == "0" {
		return true
	}
	if s == "" || len(s) > 9 || s[0] == '0' {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// strings reads the member as a sequence of strings, in flow or block style, with at least that many entries and
// none twice. When set is not nil, each entry is one of it.
func (m *mapping) strings(name string, least int, set []string) ([]string, error) {
	v := m.val[name]
	if v.Kind != yaml.SequenceNode {
		return nil, m.d.fail(v, m.what(name)+" must be a list")
	}
	if len(v.Content) < least {
		return nil, m.d.fail(v, m.what(name)+fmt.Sprintf(" must hold at least %d entry", least))
	}
	out := make([]string, 0, len(v.Content))
	for i, e := range v.Content {
		at := fmt.Sprintf("%s entry %d", m.what(name), i+1)
		if e.Kind != yaml.ScalarNode || e.Tag != "!!str" {
			return nil, m.d.fail(e, at+" must be a string: write it in quotes when it looks like a number, a boolean or a date")
		}
		if set != nil && !slices.Contains(set, e.Value) {
			return nil, m.d.fail(e, at+" must be one of "+strings.Join(set, ", "))
		}
		if slices.Contains(out, e.Value) {
			return nil, m.d.fail(e, at+" repeats an earlier entry")
		}
		out = append(out, e.Value)
	}
	return out, nil
}

// object reads the member as a mapping with the table of its own.
func (m *mapping) object(name string, table []member) (*mapping, error) {
	return m.d.mappingOf(m.val[name], m.what(name), table)
}
