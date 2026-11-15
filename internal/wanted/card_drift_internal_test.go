package wanted

import (
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/testrepo"
)

// The JSON Schema block of docs/reference/cards.md, under "The card file", is the shape of a card file. The code
// states the same shape in its table cardMembers and its enums. This test reads the block and compares the member
// names, the required members, the enum values, the limits and "additionalProperties: false" with the code, so
// that a member in one and not the other fails. It also reads every YAML example of that section with the reader.
// The rules that the schema cannot state (rows only with piv, the form of the name, two files with one card) are
// tested by the tests of the reader.

// cardSchema is the part of a JSON Schema that the card file uses.
type cardSchema struct {
	Type                 string                 `json:"type"`
	Required             []string               `json:"required"`
	Enum                 []any                  `json:"enum"`
	Const                any                    `json:"const"`
	Pattern              string                 `json:"pattern"`
	MinItems             *int                   `json:"minItems"`
	MaxItems             *int                   `json:"maxItems"`
	UniqueItems          *bool                  `json:"uniqueItems"`
	Minimum              *int                   `json:"minimum"`
	Maximum              *int                   `json:"maximum"`
	AdditionalProperties json.RawMessage        `json:"additionalProperties"`
	Properties           map[string]*cardSchema `json:"properties"`
	Items                *cardSchema            `json:"items"`
}

const cardsPage = "cards.md"

// cardsSection returns the text of the page from the heading of the card file to the next heading of that level.
func cardsSection(t *testing.T) string {
	t.Helper()
	page := string(testrepo.Read(t, "docs", "reference", cardsPage))
	const head = "### The card file, `want/cards/NAME.yaml`"
	i := strings.Index(page, head)
	if i < 0 {
		t.Fatalf("the page %s has no section %q", cardsPage, head)
	}
	rest := page[i+len(head):]
	if j := strings.Index(rest, "\n### "); j >= 0 {
		rest = rest[:j]
	}
	return rest
}

// pageCardSchema returns the one schema block of the section of the card file.
func pageCardSchema(t *testing.T) *cardSchema {
	t.Helper()
	blocks := schemaBlock.FindAllSubmatch([]byte(cardsSection(t)), -1)
	if len(blocks) != 1 {
		t.Fatalf("the section of the card file in %s holds %d schema blocks, want 1", cardsPage, len(blocks))
	}
	var s cardSchema
	if err := json.Unmarshal(blocks[0][1], &s); err != nil {
		t.Fatalf("the schema block of the card file is not JSON: %v", err)
	}
	return &s
}

func cardEnumStrings(t *testing.T, where string, list []any) []string {
	t.Helper()
	var out []string
	for _, v := range list {
		s, ok := v.(string)
		if !ok {
			t.Fatalf("%s: an enum value of the page is not a string: %v", where, v)
		}
		out = append(out, s)
	}
	slices.Sort(out)
	return out
}

func TestTheCardSchemaOnThePageIsTheTableOfTheCode(t *testing.T) {
	s := pageCardSchema(t)
	if s.Type != "object" {
		t.Errorf("the type of the card file is %q on the page", s.Type)
	}
	if string(s.AdditionalProperties) != "false" {
		t.Errorf("additionalProperties is %s on the page, and the code refuses every unknown member", s.AdditionalProperties)
	}
	if got, want := keysOf2(s.Properties), names(cardMembers); !slices.Equal(got, want) {
		t.Errorf("the page has the members %v, the code %v", got, want)
	}
	if got, want := sorted(s.Required), requiredOf(cardMembers); !slices.Equal(got, want) {
		t.Errorf("the page requires %v, the code %v", got, want)
	}
	// version: the one version.
	if v := s.Properties["version"]; v == nil || v.Const != float64(Version) {
		t.Errorf("version on the page: %+v, the code reads %d", v, Version)
	}
	// serial: a string of 1 to MaxSerialDigits digits.
	serial := s.Properties["serial"]
	if serial == nil || serial.Type != "string" {
		t.Fatalf("serial on the page: %+v", serial)
	}
	if want := fmt.Sprintf("^[0-9]{1,%d}$", MaxSerialDigits); serial.Pattern != want {
		t.Errorf("the pattern of the serial is %q on the page, the code reads %q", serial.Pattern, want)
	}
	re, err := regexp.Compile(serial.Pattern)
	if err != nil {
		t.Fatalf("the pattern of the serial: %v", err)
	}
	for _, v := range []string{"", "0", "1", "0000000001", "1234567890", "12345678901", "a", "1 ", " 1", "-1", "1\n", "\u0661"} {
		if re.MatchString(v) != (SerialKey(v) != "") {
			t.Errorf("the pattern and SerialKey disagree on %q", v)
		}
	}
	// kind: the four kinds.
	kind := s.Properties["kind"]
	if kind == nil || kind.Enum == nil {
		t.Fatalf("kind on the page: %+v", kind)
	}
	if got, want := cardEnumStrings(t, "kind", kind.Enum), sorted(cardKindEnum); !slices.Equal(got, want) {
		t.Errorf("the kinds on the page %v, in the code %v", got, want)
	}
	// applications: 1 to MaxApplications, none twice, from the three.
	apps := s.Properties["applications"]
	if apps == nil || apps.Type != "array" || apps.Items == nil || apps.Items.Enum == nil {
		t.Fatalf("applications on the page: %+v", apps)
	}
	if got, want := cardEnumStrings(t, "applications", apps.Items.Enum), sorted(applicationEnum); !slices.Equal(got, want) {
		t.Errorf("the applications on the page %v, in the code %v", got, want)
	}
	if apps.MinItems == nil || *apps.MinItems != 1 || apps.MaxItems == nil || *apps.MaxItems != MaxApplications || apps.UniqueItems == nil || !*apps.UniqueItems {
		t.Errorf("the limits of applications on the page: %+v", apps)
	}
	// other_rows: at most MaxOtherRows rows, FirstBundleRow to LastRow, none twice.
	rows := s.Properties[otherRowsMember]
	if rows == nil || rows.Type != "array" || rows.Items == nil {
		t.Fatalf("%s on the page: %+v", otherRowsMember, rows)
	}
	if rows.MaxItems == nil || *rows.MaxItems != MaxOtherRows || rows.UniqueItems == nil || !*rows.UniqueItems {
		t.Errorf("the limits of %s on the page: %+v", otherRowsMember, rows)
	}
	if rows.MinItems != nil && *rows.MinItems != 0 {
		t.Errorf("the page needs %d rows; the code allows an empty list", *rows.MinItems)
	}
	if rows.Items.Type != "integer" || rows.Items.Minimum == nil || *rows.Items.Minimum != FirstBundleRow || rows.Items.Maximum == nil || *rows.Items.Maximum != LastRow {
		t.Errorf("the rows on the page: %+v", rows.Items)
	}
}

func keysOf2(m map[string]*cardSchema) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// The members that the table of the section names are the members of the code (the file name is not a member).
func TestTheMembersOfTheTableOnThePageAreTheMembersOfTheCode(t *testing.T) {
	row := regexp.MustCompile("(?m)^\\| `([a-z_]+)`(?:, `([a-z_]+)`)? \\|")
	var got []string
	for _, m := range row.FindAllStringSubmatch(cardsSection(t), -1) {
		got = append(got, m[1])
		if m[2] != "" {
			got = append(got, m[2])
		}
	}
	slices.Sort(got)
	if want := names(cardMembers); !slices.Equal(got, want) {
		t.Errorf("the table of the page has %v, the code %v", got, want)
	}
}

// Every YAML example of the section is a card file that the reader accepts, so that the page and the code cannot
// drift.
func TestTheExamplesOnThePageAreCardFiles(t *testing.T) {
	blocks := regexp.MustCompile("(?s)```yaml\n(.*?)```").FindAllStringSubmatch(cardsSection(t), -1)
	if len(blocks) == 0 {
		t.Fatal("the section of the card file holds no YAML example: a check that finds nothing fails")
	}
	for i, b := range blocks {
		c, err := ParseCard("example", []byte(b[1]))
		if err != nil {
			t.Errorf("example %d of the page is refused: %v\n%s", i+1, err, b[1])
			continue
		}
		if !c.Valid() {
			t.Errorf("example %d: the card is not valid", i+1)
		}
	}
	// The first example is the one that the page opens with, and a change of one word of it is a refusal.
	first := blocks[0][1]
	if _, err := ParseCard("example", []byte(strings.Replace(first, "version: 1", "version: 2", 1))); err == nil {
		t.Error("the first example with version 2 is accepted")
	}
	if _, err := ParseCard("example", []byte(strings.Replace(first, "kind: root", "kind: hsm", 1))); err == nil {
		t.Error("the first example with a kind of the old name is accepted")
	}
}

// The tables of the card file are complete: no member twice, none without a name, the enums hold what the constants
// say.
func TestTheCardTableIsComplete(t *testing.T) {
	if len(cardMembers) == 0 {
		t.Fatal("the table of the card file is empty: a check that finds nothing fails")
	}
	seen := map[string]bool{}
	for _, m := range cardMembers {
		if m.name == "" || seen[m.name] {
			t.Errorf("the member %q is empty or twice", m.name)
		}
		seen[m.name] = true
	}
	if got, want := names(cardMembers), []string{"applications", "kind", "other_rows", "serial", "version"}; !slices.Equal(got, want) {
		t.Errorf("members %v, want %v", got, want)
	}
	if got, want := requiredOf(cardMembers), []string{"applications", "kind", "serial", "version"}; !slices.Equal(got, want) {
		t.Errorf("required members %v, want %v", got, want)
	}
	if !slices.Equal(cardKindEnum, []string{"root", "day-to-day", "server", "rehearsal"}) {
		t.Errorf("kinds %v", cardKindEnum)
	}
	if !slices.Equal(applicationEnum, []string{"piv", "openpgp", "fido2"}) {
		t.Errorf("applications %v", applicationEnum)
	}
	if otherRowsMember != "other_rows" {
		t.Errorf("the member of the rows of other bundles is %q", otherRowsMember)
	}
	// holder and kept are not members of the card file: they are refused by name.
	for _, n := range []string{"holder", "kept"} {
		if seen[n] {
			t.Errorf("%s is a member of the table, and the reader refuses it", n)
		}
	}
}
