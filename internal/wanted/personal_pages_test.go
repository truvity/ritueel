package wanted_test

import (
	"regexp"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/testrepo"
	"ritueel.id/ritueel/internal/wanted"
)

// The example files that the pages show for a person's bundle are read by the readers as they are written, and
// judged against each other with a card file that the page names. The pages are docs/reference/personal-openpgp.md
// (the files of a person) and docs/reference/bundle.md (a delegation of the company bundle). A block is told by the
// comment on its first line, or by its members.

var yamlBlock = regexp.MustCompile("(?s)```yaml\n(.*?)```")

type pageBlock struct {
	page, text string
	line       int
}

func blocksOf(t *testing.T, page string) []pageBlock {
	t.Helper()
	text := string(testrepo.Read(t, "docs", "reference", page))
	var out []pageBlock
	for _, m := range yamlBlock.FindAllStringSubmatchIndex(text, -1) {
		out = append(out, pageBlock{page, text[m[2]:m[3]], 1 + strings.Count(text[:m[0]], "\n")})
	}
	return out
}

func TestTheExampleFilesOfAPersonOnThePagesPassTheReadersAndTheCheckAcross(t *testing.T) {
	var settings *wanted.Settings
	var root *wanted.Root
	var ids *wanted.UserIDs
	var delegations []*wanted.Delegation
	seen := map[string]int{}
	blocks := blocksOf(t, "personal-openpgp.md")
	// The settings first: a delegation is read against them.
	for _, b := range blocks {
		if strings.Contains(b.text, "kind: personal") {
			s, err := wanted.ParseSettings(wanted.SettingsPath, []byte(b.text))
			if err != nil {
				t.Errorf("%s:%d ritueel.yaml: %v", b.page, b.line, err)
				continue
			}
			settings = s
			seen["ritueel.yaml"]++
		}
	}
	if settings == nil {
		t.Fatal("the page shows no ritueel.yaml of a person")
	}
	for _, b := range blocks {
		first, _, _ := strings.Cut(b.text, "\n")
		var err error
		switch {
		case first == "# want/roots/openpgp.yaml":
			if root, err = wanted.ParseRoot("openpgp", []byte(b.text)); err == nil {
				seen["root"]++
			}
		case first == "# want/openpgp.yaml":
			if ids, err = wanted.ParseUserIDs([]byte(b.text)); err == nil {
				seen["user ids"]++
			}
		case strings.HasPrefix(first, "# want/delegations/") && strings.HasSuffix(first, ".yaml"):
			name := strings.TrimSuffix(strings.TrimPrefix(first, "# want/delegations/"), ".yaml")
			var d *wanted.Delegation
			if d, err = wanted.ParseDelegation(name, []byte(b.text), settings); err == nil {
				delegations = append(delegations, d)
				seen["delegation"]++
			}
		case strings.Contains(b.text, "kind: personal"):
		default:
			t.Errorf("%s:%d: a block of YAML that this test cannot tell: %q", b.page, b.line, first)
		}
		if err != nil {
			t.Errorf("%s:%d (%s): %v", b.page, b.line, first, err)
		}
	}
	for _, kind := range []string{"ritueel.yaml", "root", "user ids", "delegation"} {
		if seen[kind] == 0 {
			t.Errorf("the page shows no %s", kind)
		}
	}
	if t.Failed() {
		return
	}
	// The card that the delegation names is a day-to-day card with the application openpgp: the page says so.
	var cards []*wanted.Card
	for _, d := range delegations {
		cards = append(cards, mustCard(t, d.Card, personalCard))
	}
	if err := wanted.CheckPersonal(settings, []*wanted.Root{root}, delegations, cards, ids, personalNow); err != nil {
		t.Errorf("the example files of the page against each other: %v", err)
	}
	// The key of the example is the key of a person: neither refused example.
	if k := root.Keys(); len(k) != 1 || k[0].Fingerprint == wanted.ExampleFingerprint || k[0].Fingerprint == wanted.PlaceholderFingerprint {
		t.Errorf("keys %+v", k)
	}
	if strings.EqualFold(settings.Person.Name, wanted.ExamplePersonName) {
		t.Errorf("the example person is the refused one: %+v", settings.Person)
	}
}

func TestTheExampleFilesOfACompanyDelegationOnTheBundlePagePassTheReaders(t *testing.T) {
	blocks := blocksOf(t, "bundle.md")
	var company *wanted.Settings
	for _, b := range blocks {
		if strings.Contains(b.text, "release_address:") {
			s, err := wanted.ParseSettings(wanted.SettingsPath, []byte(b.text))
			if err != nil {
				t.Fatalf("%s:%d ritueel.yaml: %v", b.page, b.line, err)
			}
			company = s
		}
	}
	if company == nil {
		t.Fatal("the page shows no ritueel.yaml of a company")
	}
	n := 0
	for _, b := range blocks {
		if !strings.Contains(b.text, "\ntype: ") {
			continue
		}
		n++
		if _, err := wanted.ParseDelegation("example", []byte(b.text), company); err != nil {
			t.Errorf("%s:%d: %v", b.page, b.line, err)
		}
	}
	if n != 3 {
		t.Errorf("the page shows %d delegation files, want 3", n)
	}
}
