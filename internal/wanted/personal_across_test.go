package wanted_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/wanted"
)

// The rules across the files of a person (CheckPersonal and CheckCompanyRoots), each with a neighbour that passes.

// bundleOf is a personal bundle in memory: its delegations and its cards by name, read with the readers.
type bundleOf struct {
	root        string
	person      string
	cards       map[string]string
	delegations map[string]string // by name; read in the order of the names
	userIDs     string
}

func goodBundle() bundleOf {
	return bundleOf{
		root: personalOpenPGP, person: personalPerson,
		cards:       map[string]string{"day-ana": personalCard},
		delegations: map[string]string{"daily": personalSign, "ssh": swap0(personalSign, "capability: sign", "capability: authenticate")},
	}
}

func swap0(s, old, repl string) string { return strings.Replace(s, old, repl, 1) }

func (b bundleOf) check(t *testing.T) error {
	t.Helper()
	s := mustSettings(t, b.person)
	var roots []*wanted.Root
	if b.root != "" {
		roots = append(roots, mustRoot(t, "openpgp", b.root))
	}
	var ds []*wanted.Delegation
	for _, name := range sortedKeys(b.delegations) {
		d, err := wanted.ParseDelegation(name, []byte(b.delegations[name]), s)
		if err != nil {
			t.Fatalf("delegation %s: %v", name, err)
		}
		ds = append(ds, d)
	}
	var cards []*wanted.Card
	for _, name := range sortedKeys(b.cards) {
		cards = append(cards, mustCard(t, name, b.cards[name]))
	}
	var ids *wanted.UserIDs
	if b.userIDs != "" {
		var err error
		if ids, err = wanted.ParseUserIDs([]byte(b.userIDs)); err != nil {
			t.Fatal(err)
		}
	}
	return wanted.CheckPersonal(s, roots, ds, cards, ids, personalNow)
}

func sortedKeys(m map[string]string) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	for i := range out {
		for j := i + 1; j < len(out); j++ {
			if out[j] < out[i] {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}

func TestEachCombinationRuleHasItsNeighbourThatPasses(t *testing.T) {
	cardWith := func(old, repl string) func(*bundleOf) {
		return func(b *bundleOf) { b.cards["day-ana"] = swap(t, personalCard, old, repl) }
	}
	delegWith := func(name, old, repl string) func(*bundleOf) {
		return func(b *bundleOf) { b.delegations[name] = swap(t, b.delegations[name], old, repl) }
	}
	rootWith := func(old, repl string) func(*bundleOf) {
		return func(b *bundleOf) { b.root = swap(t, b.root, old, repl) }
	}
	nothing := func(*bundleOf) {}
	type row struct {
		name  string
		bad   func(*bundleOf)
		good  func(*bundleOf)
		path  string
		words []string
	}
	const daily = "want/delegations/daily.yaml"
	rows := []row{
		{"a card that is missing", delegWith("daily", "day-ana", "day-bob"), nothing, daily, []string{"the card day-bob has no card file in want/cards"}},
		{"a card of the kind root", cardWith("day-to-day", "root"), nothing, daily, []string{"is of the kind root", "day-to-day card"}},
		{"a card of the kind server", cardWith("day-to-day", "server"), nothing, daily, []string{"is of the kind server"}},
		{"a card of the kind rehearsal, no test root", cardWith("day-to-day", "rehearsal"), func(b *bundleOf) {
			cardWith("day-to-day", "rehearsal")(b)
			rootWith("kind: openpgp\n", "kind: openpgp\ntest: true\n")(b)
		}, daily, []string{"is of the kind rehearsal", "only for a test root"}},
		{"a card of the kind rehearsal, a test root that says false", func(b *bundleOf) {
			cardWith("day-to-day", "rehearsal")(b)
			rootWith("kind: openpgp\n", "kind: openpgp\ntest: false\n")(b)
		}, nothing, daily, []string{"only for a test root"}},
		{"a card with piv only", cardWith("[openpgp]", "[piv]"), cardWith("[openpgp]", "[piv, openpgp]"), daily, []string{"does not list the application openpgp"}},
		{"a card with fido2 only", cardWith("[openpgp]", "[fido2]"), cardWith("[openpgp]", "[openpgp, fido2]"), daily, []string{"does not list the application openpgp"}},
		{"a card with piv and fido2", cardWith("[openpgp]", "[piv, fido2]"), nothing, daily, []string{"does not list the application openpgp"}},
		{"the pair twice", func(b *bundleOf) { b.delegations["ssh"] = personalSign },
			func(b *bundleOf) { b.delegations["ssh"] = swap(t, personalSign, "sign", "authenticate") },
			"want/delegations/ssh.yaml", []string{"the card day-ana has the capability sign in the delegation daily already", "one delegation is one key"}},
		{"the pair twice, under names that sort the other way", func(b *bundleOf) { b.delegations["aaa"] = personalSign }, nothing,
			"want/delegations/daily.yaml", []string{"in the delegation aaa already"}},
		{"the same capability on another card", nothing, func(b *bundleOf) {
			b.cards["day-bob"] = personalCard
			b.delegations["bob"] = swap(t, personalSign, "day-ana", "day-bob")
		}, "", nil},
		{"a delegation under another root", delegWith("daily", "root: openpgp", "root: other"), nothing, daily, []string{"under the root other", "the one root openpgp"}},
		{"a delegation under a root with another name", delegWith("daily", "root: openpgp", "root: openpgp-2"), nothing, daily, []string{"under the root openpgp-2"}},
		{"no root", func(b *bundleOf) { b.root = ""; b.delegations = nil }, nothing, "want/roots", []string{"needs one root file of the kind openpgp"}},
		{"a root with no encryption", rootWith("encryption: true\n", ""), rootWith("encryption: true", "encryption: false"), rootFile, []string{"needs the member encryption"}},
		{"a root with no keys", func(b *bundleOf) { b.root = "version: 1\nkind: openpgp\nencryption: true\n" }, nothing, rootFile, []string{"needs the member keys"}},
		{"a root of the kind x509", func(b *bundleOf) { b.root = "version: 1\nkind: x509\n"; b.delegations = nil }, nothing, rootFile, []string{"no root of the kind x509"}},
		{"a root of the kind ssh", func(b *bundleOf) { b.root = "version: 1\nkind: ssh\n"; b.delegations = nil }, nothing, rootFile, []string{"no root of the kind ssh"}},
		{"a user ID that is the person's, in the same case", func(b *bundleOf) {
			b.userIDs = "version: 1\nuser_ids:\n  - {name: Ben Example, address: ben@example.com}\n"
		}, func(b *bundleOf) {
			b.userIDs = "version: 1\nuser_ids:\n  - {name: Ben Example, address: ben@example.org}\n"
		}, wanted.UserIDsPath, []string{"user_ids[1]", "always the primary user ID"}},
		{"a user ID that is the person's, the name in another case", func(b *bundleOf) {
			b.userIDs = "version: 1\nuser_ids:\n  - {name: BEN EXAMPLE, address: ben@example.com}\n"
		}, nothing, wanted.UserIDsPath, []string{"always the primary user ID"}},
		{"a user ID that is the person's, the address in another case", func(b *bundleOf) {
			b.userIDs = "version: 1\nuser_ids:\n  - {name: Ben Example, address: Ben@Example.COM}\n"
		}, nothing, wanted.UserIDsPath, []string{"always the primary user ID"}},
		{"a user ID that is the person's, both in another case", func(b *bundleOf) {
			b.userIDs = "version: 1\nuser_ids:\n  - {name: bEn eXaMpLe, address: BEN@example.com}\n"
		}, nothing, wanted.UserIDsPath, []string{"always the primary user ID"}},
		{"the person's retirement, the name in another case", func(b *bundleOf) {
			b.userIDs = "version: 1\nuser_ids:\n  - {name: ben example, address: ben@example.com, retire: true}\n"
		}, func(b *bundleOf) {
			b.userIDs = "version: 1\nuser_ids:\n  - {name: ben example, address: ben@example.net, retire: true}\n"
		}, wanted.UserIDsPath, []string{"user_ids[1] retires the user ID of person in ritueel.yaml", "cannot be retired here"}},
		{"the person's retirement among other entries", func(b *bundleOf) {
			b.userIDs = "version: 1\nuser_ids:\n  - {name: Ada, address: ada@example.org}\n  - {name: Ben Example, address: BEN@EXAMPLE.COM, retire: true}\n"
		}, nothing, wanted.UserIDsPath, []string{"user_ids[2] retires the user ID of person"}},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			if r.words != nil {
				b := goodBundle()
				r.bad(&b)
				_ = wantFault(t, b.check(t), r.path, 0, r.words...)
			}
			b := goodBundle()
			r.good(&b)
			if err := b.check(t); err != nil {
				t.Errorf("the neighbour of the row is refused: %v", err)
			}
		})
	}
}

func TestAllTheCardKindsAgainstTheTestFlagOfTheRoot(t *testing.T) {
	for _, kind := range []string{"root", "day-to-day", "server", "rehearsal"} {
		for _, test := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s with test %v", kind, test), func(t *testing.T) {
				b := goodBundle()
				b.cards["day-ana"] = swap(t, personalCard, "day-to-day", kind)
				if test {
					b.root = swap(t, b.root, "kind: openpgp\n", "kind: openpgp\ntest: true\n")
				}
				err := b.check(t)
				allowed := kind == "day-to-day" || (kind == "rehearsal" && test)
				if allowed != (err == nil) {
					t.Errorf("a %s card under a root with test %v: %v", kind, test, err)
				}
			})
		}
	}
}

func TestTwoRootsAndRootsOfAnotherKindAreRefusedInEveryOrder(t *testing.T) {
	s := mustPersonal(t)
	open1 := mustRoot(t, "openpgp", personalOpenPGP)
	open2 := mustRoot(t, "other", personalOpenPGP)
	x509 := mustRoot(t, "tls", "version: 1\nkind: x509\n")
	ssh := mustRoot(t, "ssh", "version: 1\nkind: ssh\n")
	check := func(roots ...*wanted.Root) error {
		return wanted.CheckPersonal(s, roots, nil, nil, nil, personalNow)
	}
	if err := check(open1); err != nil {
		t.Fatalf("one root: %v", err)
	}
	_ = wantFault(t, check(open1, open2), "want/roots/other.yaml", 0, "this is the second root file")
	_ = wantFault(t, check(open2, open1), "want/roots/openpgp.yaml", 0, "this is the second root file")
	// A root of another kind is named before a second root is, in whatever place it stands.
	for _, roots := range [][]*wanted.Root{{open1, x509}, {x509, open1}, {open1, open2, x509}, {x509}} {
		_ = wantFault(t, check(roots...), "want/roots/tls.yaml", 0, "no root of the kind x509", "delete this file")
	}
	for _, roots := range [][]*wanted.Root{{open1, ssh}, {ssh, open1}, {ssh}} {
		_ = wantFault(t, check(roots...), "want/roots/ssh.yaml", 0, "no root of the kind ssh")
	}
	_ = wantFault(t, check(), "want/roots", 0, "needs one root file of the kind openpgp")
	_ = wantFault(t, check(open1, nil), "want/roots", 0, "not made by the reader")
}

func TestAPersonalBundleWithTheMembersOfACompany(t *testing.T) {
	s := mustPersonal(t)
	// A delegation of a company type is read, and CheckPersonal refuses it by its type.
	root := mustRoot(t, "openpgp", personalOpenPGP)
	for name, text := range map[string]string{
		"an x509-intermediate": "version: 1\ntype: x509-intermediate\nroot: openpgp\npermitted_dns_names: [example.org]\n",
		"an ssh-ca-key":        "version: 1\ntype: ssh-ca-key\nroot: openpgp\nuse: user\n",
	} {
		d, err := wanted.ParseDelegation("x", []byte(text), s)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		_ = wantFault(t, wanted.CheckPersonal(s, []*wanted.Root{root}, []*wanted.Delegation{d}, nil, nil, personalNow), "want/delegations/x.yaml", 0, "delegations of the type openpgp-subkey only")
	}
	// The members that only a company's delegation holds are refused by the reader of a personal one.
	refuse := func(extra string, words ...string) {
		t.Helper()
		d, err := wanted.ParseDelegation("daily", []byte(personalSign+extra), s)
		if d != nil {
			t.Errorf("a value beside the error: %v", err)
		}
		_ = wantFault(t, err, "want/delegations/daily.yaml", -1, words...)
	}
	refuse("permitted_dns_names: [example.org]\n", "permitted_dns_names is not a member of a delegation of the type openpgp-subkey")
	refuse("permitted_uri_hosts: [example.org]\n", "permitted_uri_hosts is not a member of a delegation of the type openpgp-subkey")
	refuse("use: user\n", "use is not a member of a delegation of the type openpgp-subkey")
	refuse("kms_read_roles: {}\n", "kms_read_roles is not a member of a delegation of a personal bundle")
	// The two members that a company's ritueel.yaml holds.
	for _, member := range []string{"name: Ben", "release_address: ben@example.com"} {
		_ = refuseSettings(t, personalPerson+member+"\n", 10, strings.SplitN(member, ":", 2)[0]+" is not allowed in a personal bundle")
	}
	// A personal bundle that has no person is refused too.
	_ = refuseSettings(t, swap(t, personalPerson, "person: {name: Ben Example, address: ben@example.com}\n", ""), 1, "needs the member person")
}

func TestACompanyBundleWithTheMembersOfAPerson(t *testing.T) {
	// A company's OpenPGP root may list reasons and nothing of a person.
	company := mustRoot(t, "openpgp", "version: 1\nkind: openpgp\nrevocation_reasons: [retired]\n")
	if err := wanted.CheckCompanyRoots([]*wanted.Root{company}); err != nil {
		t.Errorf("a company root: %v", err)
	}
	for name, text := range map[string]string{
		"keys":                "version: 1\nkind: openpgp\nkeys:\n" + adoptedLine,
		"encryption true":     "version: 1\nkind: openpgp\nencryption: true\n",
		"encryption false":    "version: 1\nkind: openpgp\nencryption: false\n",
		"both, and a reasons": personalOpenPGP,
	} {
		_ = wantFault(t, wanted.CheckCompanyRoots([]*wanted.Root{mustRoot(t, "openpgp", text)}), rootFile, 0, "keys and encryption are for the OpenPGP root of a personal bundle")
		// The same file after a company's root, in the other order, and the roots of other kinds around it.
		x509 := mustRoot(t, "x509", goodRoot)
		_ = wantFault(t, wanted.CheckCompanyRoots([]*wanted.Root{x509, mustRoot(t, "openpgp", text)}), rootFile, 0, "personal bundle")
		_ = name
	}
	_ = wantFault(t, wanted.CheckCompanyRoots([]*wanted.Root{{}}), "want/roots", 0, "not made by the reader")
	_ = wantFault(t, wanted.CheckCompanyRoots([]*wanted.Root{nil}), "want/roots", 0, "not made by the reader")
	// ritueel.yaml: a person, or kind: personal, in a company bundle.
	_ = refuseSettings(t, goodSettings+"person: {name: Ben, address: ben@example.com}\n", 10, "person is only allowed with kind: personal")
	_ = refuseSettings(t, goodSettings+"kind: personal\n", -1)
	// A delegation: the card of a person in a company's delegation, in each of the three types.
	company2 := mustSettings(t, goodSettings)
	for name, text := range map[string]string{
		"an openpgp-subkey": personalSign, "an x509-intermediate": goodX509Delegation + "card: day-ana\n", "an ssh-ca-key": goodSSHDelegation + "card: day-ana\n",
	} {
		d, err := wanted.ParseDelegation("daily", []byte(text), company2)
		if d != nil {
			t.Errorf("%s: a value beside the error", name)
		}
		_ = wantFault(t, err, "want/delegations/daily.yaml", -1, "card")
	}
}

func TestACompanyStoreIsNotAPersonalOne(t *testing.T) {
	// Each store, alone, in each kind of bundle: a person's primary is a software key that the person adopts, and the
	// subkeys are on an OpenPGP card.
	for store, personal := range map[string]bool{"openpgp-card": true, "software": true, "piv": false, "aws-kms": false} {
		pers := swap(t, personalPerson, "[openpgp-card, software]", "["+store+"]")
		comp := swap(t, goodSettings, "[piv, openpgp-card, aws-kms]", "["+store+"]")
		if _, err := wanted.ParseSettings(wanted.SettingsPath, []byte(comp)); err != nil {
			t.Errorf("a company bundle with the store %s: %v", store, err)
		}
		_, err := wanted.ParseSettings(wanted.SettingsPath, []byte(pers))
		if personal != (err == nil) {
			t.Errorf("a personal bundle with the store %s: %v", store, err)
		}
	}
	_ = refuseSettings(t, swap(t, personalPerson, "[openpgp-card, software]", "[piv, aws-kms]"), 5, "policy.stores holds piv, which is reserved for stage two")
}

// manyDelegations is n delegations of a person that pass their reader: two capabilities on each of n/2 cards.
func manyDelegations(t *testing.T, n int) ([]*wanted.Delegation, []*wanted.Card) {
	t.Helper()
	s := mustPersonal(t)
	var ds []*wanted.Delegation
	var cs []*wanted.Card
	for i := range (n + 1) / 2 {
		card := fmt.Sprintf("day-%02d", i)
		cs = append(cs, mustCard(t, card, personalCard))
		for j, capability := range []string{"sign", "authenticate"} {
			if len(ds) == n {
				break
			}
			text := swap(t, swap(t, personalSign, "day-ana", card), "sign", capability)
			d, err := wanted.ParseDelegation(fmt.Sprintf("d%02d-%d", i, j), []byte(text), s)
			if err != nil {
				t.Fatal(err)
			}
			ds = append(ds, d)
		}
	}
	return ds, cs
}

func TestSixteenDelegationsPassAndSeventeenDoNot(t *testing.T) {
	s, root := mustPersonal(t), mustRoot(t, "openpgp", personalOpenPGP)
	ds, cs := manyDelegations(t, 16)
	if err := wanted.CheckPersonal(s, []*wanted.Root{root}, ds, cs, nil, personalNow); err != nil {
		t.Fatalf("16 delegations: %v", err)
	}
	ds, cs = manyDelegations(t, 17)
	_ = wantFault(t, wanted.CheckPersonal(s, []*wanted.Root{root}, ds, cs, nil, personalNow), wanted.DelegationsDir, 0, "a personal bundle holds at most 16 delegation files")
	// The count comes before the judging of each delegation: 17 of which the first has no card is a count fault.
	ds, _ = manyDelegations(t, 17)
	_ = wantFault(t, wanted.CheckPersonal(s, []*wanted.Root{root}, ds, nil, nil, personalNow), wanted.DelegationsDir, 0, "at most 16")
}

// The names of the delegation files are counted when the folder is listed, before any of them is read.
func TestSeventeenDelegationFilesAreRefusedBeforeAnyIsRead(t *testing.T) {
	// Files that would each give another error if one were read: not YAML, a control character, too long, not
	// UTF-8, a delegation under a root that is not there, a file that the system will not let a reader open.
	bad := map[string]string{
		"a-not-yaml":     "{[",
		"b-control":      "version: 1\x07\n",
		"c-too-long":     "version: 1\n# " + strings.Repeat("x", wanted.MaxBytes) + "\n",
		"d-not-utf8":     "\xff\xfe\n",
		"e-no-root":      personalSign,
		"f-empty":        "",
		"g-company-type": "version: 1\ntype: ssh-ca-key\nroot: openpgp\nuse: user\n",
		"h-card":         swap0(personalSign, "day-ana", "Bad_Card"),
	}
	files := map[string]string{"ritueel.yaml": personalPerson}
	i := 0
	for name, text := range bad {
		files["want/delegations/"+name+".yaml"] = text
		i++
	}
	for ; i < 17; i++ {
		files[fmt.Sprintf("want/delegations/z%02d.yaml", i)] = "not a delegation\n"
	}
	dir, fsys := bundleDir(t, files)
	if os.Getuid() == 0 {
		t.Skip("a file of mode 0 is readable for root")
	}
	// One file that the system will not let be read.
	unreadable := filepath.Join(dir, "want/delegations/z16.yaml")
	if err := os.Chmod(unreadable, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(unreadable, 0o644) })
	s := mustPersonal(t)
	const words = "a personal bundle holds at most 16 delegation files"
	_ = wantFault(t, wanted.CheckDelegations(fsys, s), wanted.DelegationsDir, 0, words)
	_, err := wanted.ListDelegations(fsys, s)
	_ = wantFault(t, err, wanted.DelegationsDir, 0, words)
	// Sixteen of the same files are read, and the first one that fails is named: the count was the only difference.
	if err := os.Remove(filepath.Join(dir, "want/delegations/e-no-root.yaml")); err != nil {
		t.Fatal(err)
	}
	err = wanted.CheckDelegations(fsys, s)
	e := wantFault(t, err, "", -1)
	if strings.Contains(e.Msg, words) || e.Path == wanted.DelegationsDir {
		t.Errorf("16 files are refused for their count: %v", err)
	}
	if e.Path != "want/delegations/a-not-yaml.yaml" {
		t.Errorf("the first file in the order of the names is read first: %s", e.Path)
	}
}

func TestTheLeftoversOfAStoppedWriteDoNotCountTowardsSixteen(t *testing.T) {
	files := map[string]string{"ritueel.yaml": personalPerson}
	for i := range 16 {
		files[fmt.Sprintf("want/delegations/d%02d.yaml", i)] = "x: 1\n"
	}
	for i := range 5 {
		files[fmt.Sprintf("want/delegations/.rt-%d.yaml", i)] = "x: 1\n"
		files[fmt.Sprintf("want/delegations/.RT-up-%d", i)] = "x: 1\n"
	}
	_, fsys := bundleDir(t, files)
	s := mustPersonal(t)
	e := wantFault(t, wanted.CheckDelegations(fsys, s), "want/delegations/d00.yaml", -1)
	if strings.Contains(e.Msg, "at most 16") {
		t.Errorf("leftovers are counted: %v", e)
	}
	// A company bundle has no such limit, with the same names.
	files["want/delegations/d16.yaml"] = "x: 1\n"
	_, fsys = bundleDir(t, files)
	e = wantFault(t, wanted.CheckDelegations(fsys, mustSettings(t, goodSettings)), "want/delegations/d00.yaml", -1)
	if strings.Contains(e.Msg, "at most 16") {
		t.Errorf("a company bundle is limited: %v", e)
	}
	// The 17th file of a personal bundle is the one too many, whatever its name.
	_, fsys = bundleDir(t, files)
	_ = wantFault(t, wanted.CheckDelegations(fsys, s), wanted.DelegationsDir, 0, "at most 16")
}

func TestCheckPersonalRefusesValuesThatNoReaderMade(t *testing.T) {
	root := mustRoot(t, "openpgp", personalOpenPGP)
	s := mustPersonal(t)
	_ = wantFault(t, wanted.CheckPersonal(s, []*wanted.Root{root}, nil, nil, &wanted.UserIDs{}, personalNow), wanted.UserIDsPath, 0, "not made by the reader")
	_ = wantFault(t, wanted.CheckPersonal(&wanted.Settings{}, []*wanted.Root{root}, nil, nil, nil, personalNow), wanted.SettingsPath, 0, "not made by the reader")
	_ = wantFault(t, wanted.CheckPersonal(nil, []*wanted.Root{root}, nil, nil, nil, personalNow), wanted.SettingsPath, 0, "not made by the reader")
	// The settings of a company bundle are no settings of a person.
	_ = wantFault(t, wanted.CheckPersonal(mustSettings(t, goodSettings), []*wanted.Root{root}, nil, nil, nil, personalNow), wanted.SettingsPath, 0, "personal bundle")
}
