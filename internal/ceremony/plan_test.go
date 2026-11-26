//go:build linux || darwin

package ceremony_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/buildinfo"
	"ritueel.id/ritueel/internal/canonjson"
	"ritueel.id/ritueel/internal/ceremony"
	"ritueel.id/ritueel/internal/ceremony/files"
	"ritueel.id/ritueel/internal/pki"
	"ritueel.id/ritueel/internal/wanted"
)

// The plan of the first apply of a software test root (docs/reference/ceremony-record.md, "The
// plan"; record 0005, rules 7, 8, 13 and 20). The golden plan below is spelled out member by member
// here, with the digests and the serials worked out by hand, and is never read back from what the
// code makes.

const (
	pfSerialA = "2030405060708090a0b0c0d0e0f101112131415"
	pfSerialB = "161718191a1b1c1d1e1f20212223242526272829"
	pfSumSet  = "de7e95553070161d57bf2808180006eb24e4728cdae674917f5067414053adf0"
	pfSumRoot = "6361aad1be3135735e62b61b62f5427c1e27c85823d20de10bb5cfa6dfb9c3a7"

	pfGolden = `{"applies":[{"change":"create","object":"x509/A"},{"change":"create","object":"x509/B"}],` +
		`"births":[{"label":"A","place":"x509-root-a","purpose":"x509-root","store":"software"},` +
		`{"label":"B","place":"x509-root-b","purpose":"x509-root","store":"software"}],` +
		`"ceremony":"20261120T100000Z-apply","ceremony_time":"2026-11-20T10:00:00Z","command":"apply",` +
		`"made_at":"2026-11-20T10:00:00Z",` +
		`"ritueel":{"os_arch":"linux/amd64","sha256":"abababababababababababababababababababababababababababababababab","version":"v0.0.0-test"},` +
		`"root":{"copyable":true,"label":"A","store":"software","test":true},` +
		`"signatures":[` +
		`{"derived":true,"kind":"root-certificate","n":1,"not_after":"2029-11-20T10:00:00Z","not_before":"2026-11-20T10:00:00Z","serial":"` + pfSerialA + `","subject":"A"},` +
		`{"derived":true,"kind":"root-removal","n":2,"subject":"A"},` +
		`{"derived":true,"kind":"root-certificate","n":3,"not_after":"2029-11-20T10:00:00Z","not_before":"2026-11-20T10:00:00Z","serial":"` + pfSerialB + `","subject":"B"},` +
		`{"derived":true,"kind":"root-removal","n":4,"subject":"B"},` +
		`{"derived":true,"kind":"root-list","n":5,"subject":"A"}],` +
		`"trust_sequence":1,"version":1,` +
		`"wanted":[{"path":"ritueel.yaml","sha256":"` + pfSumSet + `"},{"path":"want/roots/x509.yaml","sha256":"` + pfSumRoot + `"}]}`

	pfGoldenDigest = "384d9da09dbf26cc732c289d19c5ae429d2d91a9e4529cad1344dac91ab2ca9a"
)

func TestTheGoldenPlanIsMadeByteForByte(t *testing.T) {
	// The digests of the two wanted files are those that were worked out by hand.
	if sum([]byte(pfSettings)) != pfSumSet || sum([]byte(pfX509Test)) != pfSumRoot {
		t.Fatal("the constants of the golden plan do not match the test files")
	}
	p := pfPlan(t, pfFiles())
	if got := string(p.JSON); got != pfGolden {
		t.Fatalf("the plan is\n%s\nwant\n%s", got, pfGolden)
	}
	if p.SHA256 != pfGoldenDigest || sum([]byte(pfGolden)) != pfGoldenDigest {
		t.Errorf("digest = %s, want %s", p.SHA256, pfGoldenDigest)
	}
	if p.Prefix != pfGoldenDigest[:8] {
		t.Errorf("prefix = %q, want %q", p.Prefix, pfGoldenDigest[:8])
	}
	if p.Name != pfName {
		t.Errorf("name = %q, want %q", p.Name, pfName)
	}
	if !p.Time.Equal(pfClock) || p.Time.Location() != time.UTC {
		t.Errorf("time = %v", p.Time)
	}
	if p.Program != pfProgram {
		t.Errorf("program = %+v", p.Program)
	}
	if p.RootName != "x509" {
		t.Errorf("root name = %q", p.RootName)
	}
}

func TestTheGoldenPlanIsAcceptedByTheReadersThatJudgeIt(t *testing.T) {
	p := pfPlan(t, pfFiles())
	fp, err := files.ReadPlan(p.JSON)
	if err != nil {
		t.Fatalf("files.ReadPlan: %v", err)
	}
	if fp.Ceremony != pfName || fp.Command != "apply" || fp.TrustSequence == nil || *fp.TrustSequence != 1 {
		t.Errorf("plan read as %+v", fp)
	}
	if ok, err := canonjson.IsCanonical(p.JSON); err != nil || !ok {
		t.Errorf("the plan is not canonical: %v %v", ok, err)
	}
	if bytes.HasSuffix(p.JSON, []byte("\n")) {
		t.Error("the plan ends with a line feed")
	}
	if p.Plan == nil || p.Plan.Ceremony != pfName {
		t.Errorf("Plan = %+v", p.Plan)
	}
	if canon, err := p.Plan.Canonical(); err != nil || !bytes.Equal(canon, p.JSON) {
		t.Errorf("the plan read back writes %q, %v", canon, err)
	}
}

func TestTheTypedValuesOfAPlanAreWhatThePlanSays(t *testing.T) {
	p := pfPlan(t, pfFiles())
	wantApplies := []ceremony.Change{{Change: "create", Object: "x509/A"}, {Change: "create", Object: "x509/B"}}
	if !reflect.DeepEqual(p.Applies, wantApplies) {
		t.Errorf("Applies = %+v", p.Applies)
	}
	wantBirths := []ceremony.PlanBirth{
		{Label: "A", Purpose: "x509-root", Store: "software", Place: "x509-root-a"},
		{Label: "B", Purpose: "x509-root", Store: "software", Place: "x509-root-b"},
	}
	if !reflect.DeepEqual(p.Births, wantBirths) {
		t.Errorf("Births = %+v", p.Births)
	}
	wantSigs := []ceremony.PlanSignature{
		{N: 1, Kind: "root-certificate", Subject: "A", Serial: pfSerialA, NotBefore: "2026-11-20T10:00:00Z", NotAfter: "2029-11-20T10:00:00Z", Derived: true},
		{N: 2, Kind: "root-removal", Subject: "A", Derived: true},
		{N: 3, Kind: "root-certificate", Subject: "B", Serial: pfSerialB, NotBefore: "2026-11-20T10:00:00Z", NotAfter: "2029-11-20T10:00:00Z", Derived: true},
		{N: 4, Kind: "root-removal", Subject: "B", Derived: true},
		{N: 5, Kind: "root-list", Subject: "A", Derived: true},
	}
	if !reflect.DeepEqual(p.Signatures, wantSigs) {
		t.Errorf("Signatures = %+v", p.Signatures)
	}
	if len(p.Wanted) != 2 || p.Wanted[0].Path != "ritueel.yaml" || p.Wanted[0].SHA256 != pfSumSet || p.Wanted[1].Path != "want/roots/x509.yaml" || p.Wanted[1].SHA256 != pfSumRoot {
		t.Errorf("Wanted = %+v", p.Wanted)
	}
	if len(p.LeavesOut) != 0 {
		t.Errorf("LeavesOut = %+v", p.LeavesOut)
	}
}

// pfDecode reads a plan into a generic value.
func pfDecode(t testing.TB, b []byte) map[string]any {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		t.Fatal(err)
	}
	return m
}

// pfEncode writes a generic value as json.Marshal does: members in the order of their names and no
// white space, which for these values is the canonical form of RFC 8785; it also writes a null, which
// the canonical writer refuses.
func pfEncode(t testing.TB, m any) []byte {
	t.Helper()
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// pfEdit makes the golden plan, lets edit change its members, and writes it canonically again.
func pfEdit(t testing.TB, edit func(m map[string]any)) []byte {
	t.Helper()
	m := pfDecode(t, []byte(pfGolden))
	edit(m)
	return pfEncode(t, m)
}

func pfList(m map[string]any, key string) []any { return m[key].([]any) }

func pfObj(l []any, i int) map[string]any { return l[i].(map[string]any) }

func TestEveryMemberOfThePlanIsWhatThePageSays(t *testing.T) {
	m := pfDecode(t, []byte(pfPlan(t, pfFiles()).JSON))
	num := func(v any) string { return fmt.Sprint(v) }
	// The version, the command, the name and the two times.
	if num(m["version"]) != "1" || m["command"] != "apply" || m["ceremony"] != "20261120T100000Z-apply" {
		t.Errorf("version, command or ceremony: %v %v %v", m["version"], m["command"], m["ceremony"])
	}
	if m["made_at"] != "2026-11-20T10:00:00Z" || m["ceremony_time"] != "2026-11-20T10:00:00Z" {
		t.Errorf("made_at %v, ceremony_time %v", m["made_at"], m["ceremony_time"])
	}
	// The program that made the plan.
	prog := m["ritueel"].(map[string]any)
	if len(prog) != 3 || prog["version"] != "v0.0.0-test" || prog["os_arch"] != "linux/amd64" || prog["sha256"] != strings.Repeat("ab", 32) {
		t.Errorf("ritueel = %v", prog)
	}
	// Members that the first apply leaves out.
	for _, k := range []string{"inputs", "requests", "arguments", "touches", "last_record_sha256", "base_sequence", "root_reason", "leaves_out"} {
		if _, ok := m[k]; ok {
			t.Errorf("the plan has the member %q", k)
		}
	}
	// The root, with no fingerprint yet.
	root := m["root"].(map[string]any)
	if len(root) != 4 || root["label"] != "A" || root["store"] != "software" || root["test"] != true || root["copyable"] != true {
		t.Errorf("root = %v", root)
	}
	// The trust sequence of the first set.
	if num(m["trust_sequence"]) != "1" {
		t.Errorf("trust_sequence = %v", m["trust_sequence"])
	}
	// The member names of the plan and no others.
	want := []string{"applies", "births", "ceremony", "ceremony_time", "command", "made_at", "ritueel", "root", "signatures", "trust_sequence", "version", "wanted"}
	var got []string
	for k := range m {
		got = append(got, k)
	}
	if len(got) != len(want) {
		t.Errorf("members = %v, want %v", got, want)
	}
	for _, k := range want {
		if _, ok := m[k]; !ok {
			t.Errorf("the plan has no member %q", k)
		}
	}
}

func TestTheSignaturesAreInTheOrderOfThePageAndAllDerived(t *testing.T) {
	for _, keys := range []int{1, 2, 3, 26} {
		t.Run(fmt.Sprintf("%d keys", keys), func(t *testing.T) {
			f := pfMustFind(t, pfFiles())
			f.Applies = pfApplies(keys)
			p, err := ceremony.MakePlan(f, pfEnv())
			if err != nil {
				t.Fatalf("MakePlan: %v", err)
			}
			m := pfDecode(t, p.JSON)
			sigs := pfList(m, "signatures")
			if len(sigs) != 2*keys+1 {
				t.Fatalf("%d signatures for %d keys, want %d", len(sigs), keys, 2*keys+1)
			}
			serials := map[string]bool{}
			for i, s := range sigs {
				o := s.(map[string]any)
				if fmt.Sprint(o["n"]) != fmt.Sprint(i+1) {
					t.Errorf("signature %d has n %v", i+1, o["n"])
				}
				if o["derived"] != true {
					t.Errorf("signature %d is not derived", i+1)
				}
				for _, k := range []string{"tbs_sha256", "key", "reason"} {
					if _, ok := o[k]; ok {
						t.Errorf("signature %d has the member %q", i+1, k)
					}
				}
				var kind, subject string
				switch {
				case i == 2*keys:
					kind, subject = "root-list", "A"
				case i%2 == 0:
					kind, subject = "root-certificate", string(rune('A'+i/2))
				default:
					kind, subject = "root-removal", string(rune('A'+i/2))
				}
				if o["kind"] != kind || o["subject"] != subject {
					t.Errorf("signature %d is %v for %v, want %s for %s", i+1, o["kind"], o["subject"], kind, subject)
				}
				if kind == "root-certificate" {
					s, _ := o["serial"].(string)
					n, ok := new(big.Int).SetString(s, 16)
					if !ok || n.Text(16) != s || pki.CheckSerial(n) != nil {
						t.Errorf("the serial %q is not lower-case hexadecimal without a leading zero, of the profile", s)
					}
					if serials[s] {
						t.Errorf("the serial %s is used twice", s)
					}
					serials[s] = true
					if o["not_before"] != "2026-11-20T10:00:00Z" || o["not_after"] != "2029-11-20T10:00:00Z" {
						t.Errorf("validity %v to %v", o["not_before"], o["not_after"])
					}
				} else {
					for _, k := range []string{"serial", "not_before", "not_after"} {
						if _, ok := o[k]; ok {
							t.Errorf("signature %d (%s) has %q", i+1, kind, k)
						}
					}
				}
			}
			if len(pfList(m, "births")) != keys || len(pfList(m, "applies")) != keys {
				t.Errorf("births %d, applies %d, want %d", len(pfList(m, "births")), len(pfList(m, "applies")), keys)
			}
		})
	}
}

// pfApplies is the creation of the first n keys of the root x509.
func pfApplies(n int) []ceremony.Change {
	out := make([]ceremony.Change, n)
	for i := range out {
		out[i] = ceremony.Change{Change: "create", Object: "x509/" + string(rune('A'+i))}
	}
	return out
}

func TestOneKeyOr26KeysAreAPlanAnd27AreNot(t *testing.T) {
	f := pfMustFind(t, pfFiles())
	f.Applies = pfApplies(26)
	p, err := ceremony.MakePlan(f, pfEnv())
	if err != nil {
		t.Fatalf("26 keys: %v", err)
	}
	if len(p.JSON) > 256*1024 {
		t.Errorf("a plan of 26 keys is %d bytes, more than the reader reads", len(p.JSON))
	}
	if _, err := ceremony.ReadPlanOut(p.JSON); err != nil {
		t.Errorf("the reader refuses the plan of 26 keys: %v", err)
	}
	f.Applies = pfApplies(27)
	if p, err := ceremony.MakePlan(f, pfEnv()); err == nil || p != nil {
		t.Errorf("27 keys = %v, %v; want an error and no plan", p, err)
	}
	f.Applies = pfApplies(1)
	one, err := ceremony.MakePlan(f, pfEnv())
	if err != nil || len(one.Signatures) != 3 || len(one.Births) != 1 {
		t.Errorf("one key = %+v, %v", one, err)
	}
}

func TestTheSameInputsGiveTheSameBytesAndAnotherInputGivesAnother(t *testing.T) {
	a := pfPlan(t, pfFiles())
	b := pfPlan(t, pfFiles())
	if !bytes.Equal(a.JSON, b.JSON) || a.SHA256 != b.SHA256 {
		t.Error("two runs with the same inputs gave two plans")
	}
	// A changed clock changes the name, the times and the digest.
	f := pfMustFind(t, pfFiles())
	env := pfEnv()
	env.Now = func() time.Time { return pfClock.Add(time.Second) }
	later, err := ceremony.MakePlan(f, env)
	if err != nil {
		t.Fatal(err)
	}
	if later.Name != "20261120T100001Z-apply" || later.SHA256 == a.SHA256 || !strings.Contains(string(later.JSON), "2026-11-20T10:00:01Z") {
		t.Errorf("a later plan: %s %s", later.Name, later.SHA256)
	}
	// Another source of random numbers gives other serials and another digest.
	env = pfEnv()
	env.Rand = io.MultiReader(bytes.NewReader(bytes.Repeat([]byte{0x11}, 20)), bytes.NewReader(bytes.Repeat([]byte{0x22}, 20)))
	other, err := ceremony.MakePlan(f, env)
	if err != nil {
		t.Fatal(err)
	}
	if other.SHA256 == a.SHA256 || !strings.Contains(string(other.JSON), "1111111111111111111111111111111111111111") || !strings.Contains(string(other.JSON), "2222222222222222222222222222222222222222") {
		t.Errorf("the serials were not taken from the source: %s", other.JSON)
	}
	// A changed wanted file changes its digest in the plan, and the digest of the plan.
	files2 := pfFiles()
	files2["ritueel.yaml"] = strings.Replace(pfSettings, "Example", "Example Two", 1)
	c := pfPlan(t, files2)
	if c.SHA256 == a.SHA256 || c.Wanted[0].SHA256 != sum([]byte(files2["ritueel.yaml"])) || c.Wanted[1].SHA256 != pfSumRoot {
		t.Errorf("a changed wanted file: %+v", c.Wanted)
	}
	// A root file with another name changes the objects and the path.
	files3 := map[string]string{"ritueel.yaml": pfSettings, "want/roots/acme-tls.yaml": pfX509Test}
	d := pfPlan(t, files3)
	if d.Applies[0].Object != "acme-tls/A" || d.Wanted[1].Path != "want/roots/acme-tls.yaml" || d.RootName != "acme-tls" {
		t.Errorf("a root with another name: %+v %q", d.Applies, d.RootName)
	}
}

func TestThePlanListsTheWantedFilesInPathOrderWhateverTheOrderOfTheFound(t *testing.T) {
	f := pfMustFind(t, pfFiles())
	f.Wanted[0], f.Wanted[1] = f.Wanted[1], f.Wanted[0]
	p, err := ceremony.MakePlan(f, pfEnv())
	if err != nil {
		t.Fatalf("MakePlan: %v", err)
	}
	if string(p.JSON) != pfGolden {
		t.Errorf("a Found with the files in the other order gives another plan:\n%s", p.JSON)
	}
}

func TestTheClockIsTakenOnceInWholeSecondsInUTC(t *testing.T) {
	calls := 0
	env := pfEnv()
	zone := time.FixedZone("far", 5*3600+1800)
	env.Now = func() time.Time {
		calls++
		return time.Date(2026, 11, 20, 15, 30, 0, 999_999_999, zone)
	}
	p, err := ceremony.MakePlan(pfMustFind(t, pfFiles()), env)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Errorf("the clock was read %d times, want once (record 0005, rule 7: drawn once)", calls)
	}
	if p.Name != pfName || !strings.Contains(string(p.JSON), `"made_at":"2026-11-20T10:00:00Z"`) {
		t.Errorf("a clock in another zone with a fraction: %s", p.JSON)
	}
}

func TestACertificateIsValidFor36CalendarMonths(t *testing.T) {
	cases := []struct{ now, notAfter string }{
		{"2026-11-20T10:00:00Z", "2029-11-20T10:00:00Z"},
		{"2026-01-31T00:00:00Z", "2029-01-31T00:00:00Z"},
		{"2028-02-29T12:30:45Z", "2031-02-28T12:30:45Z"},
		{"2026-12-31T23:59:59Z", "2029-12-31T23:59:59Z"},
		{"0001-01-01T00:00:00Z", "0004-01-01T00:00:00Z"},
		{"9996-12-31T00:00:00Z", "9999-12-31T00:00:00Z"},
	}
	for _, c := range cases {
		t.Run(c.now, func(t *testing.T) {
			now, err := time.Parse(time.RFC3339, c.now)
			if err != nil {
				t.Fatal(err)
			}
			env := pfEnv()
			env.Now = func() time.Time { return now }
			p, err := ceremony.MakePlan(pfMustFind(t, pfFiles()), env)
			if err != nil {
				t.Fatalf("MakePlan: %v", err)
			}
			if got := p.Signatures[0].NotAfter; got != c.notAfter {
				t.Errorf("not_after = %s, want %s", got, c.notAfter)
			}
			if _, err := ceremony.ReadPlanOut(p.JSON); err != nil {
				t.Errorf("the reader refuses the plan: %v", err)
			}
		})
	}
}

func TestAClockWhoseCertificateWouldEndPastYear9999IsAnError(t *testing.T) {
	for _, s := range []string{"9997-01-01T00:00:00Z", "9999-12-31T23:59:59Z"} {
		now, _ := time.Parse(time.RFC3339, s)
		env := pfEnv()
		env.Now = func() time.Time { return now }
		if p, err := ceremony.MakePlan(pfMustFind(t, pfFiles()), env); err == nil || p != nil {
			t.Errorf("a clock at %s: %v, %v", s, p, err)
		}
	}
}

func TestMakePlanRefusesWhatIsNotAFoundOfTheFirstApply(t *testing.T) {
	good := func() *ceremony.Found { return pfMustFind(t, pfFiles()) }
	cases := map[string]func() *ceremony.Found{
		"nil":  func() *ceremony.Found { return nil },
		"zero": func() *ceremony.Found { return &ceremony.Found{} },
		"nothing to apply": func() *ceremony.Found {
			f := good()
			f.Applies = nil
			return f
		},
		"no settings": func() *ceremony.Found {
			f := good()
			f.Settings = nil
			return f
		},
		"settings that the reader did not make": func() *ceremony.Found {
			f := good()
			f.Settings = &wanted.Settings{}
			return f
		},
		"no root": func() *ceremony.Found {
			f := good()
			f.Root = nil
			return f
		},
		"a root that the reader did not make": func() *ceremony.Found {
			f := good()
			f.Root = &wanted.Root{Name: "x509", Kind: wanted.RootX509, Test: true}
			return f
		},
		"a root of the kind openpgp": func() *ceremony.Found {
			f := good()
			r, err := wanted.ParseRoot("x509", []byte(pfOpenPGPTest))
			if err != nil {
				t.Fatal(err)
			}
			f.Root = r
			return f
		},
		"a root that is not a test root": func() *ceremony.Found {
			f := good()
			r, err := wanted.ParseRoot("x509", []byte(pfX509Real))
			if err != nil {
				t.Fatal(err)
			}
			f.Root = r
			return f
		},
		"a personal bundle": func() *ceremony.Found {
			f := good()
			s, err := wanted.ParseSettings("ritueel.yaml", []byte(pfPersonal))
			if err != nil {
				t.Fatal(err)
			}
			f.Settings = s
			return f
		},
		"the second key first": func() *ceremony.Found {
			f := good()
			f.Applies = []ceremony.Change{{Change: "create", Object: "x509/B"}, {Change: "create", Object: "x509/A"}}
			return f
		},
		"a change that is not create": func() *ceremony.Found {
			f := good()
			f.Applies[1].Change = "retire"
			return f
		},
		"an object of another root": func() *ceremony.Found {
			f := good()
			f.Applies[0].Object = "other/A"
			return f
		},
		"a label that is not the next letter": func() *ceremony.Found {
			f := good()
			f.Applies[1].Object = "x509/C"
			return f
		},
		"a third wanted file": func() *ceremony.Found {
			f := good()
			f.Wanted = append(f.Wanted, wanted.File{Path: "want/roots/other.yaml", Data: []byte("x")})
			return f
		},
		"one wanted file": func() *ceremony.Found {
			f := good()
			f.Wanted = f.Wanted[:1]
			return f
		},
		"no wanted file": func() *ceremony.Found {
			f := good()
			f.Wanted = nil
			return f
		},
		"the same wanted file twice": func() *ceremony.Found {
			f := good()
			f.Wanted[1] = f.Wanted[0]
			return f
		},
		"wanted files that are not the ones that were read": func() *ceremony.Found {
			f := good()
			f.Wanted[1].Path = "want/roots/else.yaml"
			return f
		},
		"a wanted path that breaks the rules of a path": func() *ceremony.Found {
			f := good()
			f.Wanted[1].Path = "want/roots/../x509.yaml"
			f.Root.File.Path = f.Wanted[1].Path
			return f
		},
		"27 keys": func() *ceremony.Found {
			f := good()
			f.Applies = pfApplies(27)
			return f
		},
	}
	for name, mk := range cases {
		t.Run(name, func(t *testing.T) {
			p, err := ceremony.MakePlan(mk(), pfEnv())
			if err == nil || p != nil {
				t.Errorf("MakePlan = %v, %v; want an error and no plan", p, err)
			}
		})
	}
}

func TestMakePlanRefusesAnEnvThatCannotRunACheck(t *testing.T) {
	f := pfMustFind(t, pfFiles())
	cases := map[string]ceremony.Env{
		"no clock":            {Rand: &pfCounter{}, Self: pfSelf},
		"a clock before 1":    {Now: func() time.Time { return time.Date(0, 6, 1, 0, 0, 0, 0, time.UTC) }, Self: pfSelf},
		"a clock past 9999":   {Now: func() time.Time { return time.Date(10000, 6, 1, 0, 0, 0, 0, time.UTC) }, Self: pfSelf},
		"a clock that panics": {Now: func() time.Time { panic("no clock") }, Self: pfSelf},
		"a program that cannot be described": {Now: pfEnv().Now, Self: func() (buildinfo.Program, error) {
			return buildinfo.Program{}, errors.New("no file")
		}},
		"a program that panics":                {Now: pfEnv().Now, Self: func() (buildinfo.Program, error) { panic("boom") }},
		"a source of serials that fails":       {Now: pfEnv().Now, Self: pfSelf, Rand: pfFailing{}},
		"a source that gives too few bytes":    {Now: pfEnv().Now, Self: pfSelf, Rand: bytes.NewReader([]byte{1, 2, 3})},
		"a source that gives only zeros":       {Now: pfEnv().Now, Self: pfSelf, Rand: bytes.NewReader(make([]byte, 100))},
		"a source that gives one serial twice": {Now: pfEnv().Now, Self: pfSelf, Rand: &pfSame{}},
		"a typed nil source":                   {Now: pfEnv().Now, Self: pfSelf, Rand: (*pfCounter)(nil)},
		"a program with a version of a space": {Now: pfEnv().Now, Self: func() (buildinfo.Program, error) {
			return buildinfo.Program{Version: "v1 2", OSArch: "linux/amd64", SHA256: strings.Repeat("a", 64)}, nil
		}},
		"a program with an empty version": {Now: pfEnv().Now, Self: func() (buildinfo.Program, error) {
			return buildinfo.Program{OSArch: "linux/amd64", SHA256: strings.Repeat("a", 64)}, nil
		}},
		"a program with a digest in capitals": {Now: pfEnv().Now, Self: func() (buildinfo.Program, error) {
			return buildinfo.Program{Version: "v1", OSArch: "linux/amd64", SHA256: strings.Repeat("A", 64)}, nil
		}},
		"a program with a system of one word": {Now: pfEnv().Now, Self: func() (buildinfo.Program, error) {
			return buildinfo.Program{Version: "v1", OSArch: "linux", SHA256: strings.Repeat("a", 64)}, nil
		}},
	}
	for name, env := range cases {
		t.Run(name, func(t *testing.T) {
			p, err := ceremony.MakePlan(f, env)
			if err == nil || p != nil {
				t.Errorf("MakePlan = %v, %v; want an error and no plan", p, err)
			}
		})
	}
}

type pfFailing struct{}

func (pfFailing) Read([]byte) (int, error) { return 0, errors.New("the source failed") }

// pfSame gives the same 20 bytes at every read of 20.
type pfSame struct{}

func (pfSame) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(i + 7)
	}
	return len(p), nil
}

func TestMakePlanChangesNeitherTheFoundNorTheSharedBytes(t *testing.T) {
	f := pfMustFind(t, pfFiles())
	wantApplies := append([]ceremony.Change(nil), f.Applies...)
	wantData := string(f.Wanted[0].Data)
	p, err := ceremony.MakePlan(f, pfEnv())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(f.Applies, wantApplies) || string(f.Wanted[0].Data) != wantData {
		t.Error("MakePlan changed the Found")
	}
	// A change of the Found after the plan was made does not reach the plan.
	f.Applies[0].Object = "x509/Z"
	f.Wanted[0].Data[0] ^= 0xff
	if p.Applies[0].Object != "x509/A" {
		t.Error("the plan shares the changes of the Found")
	}
	// A change of the bytes of the plan does not reach the digest or the typed values.
	again, err := ceremony.ReadPlanOut(p.JSON)
	if err != nil || again.SHA256 != p.SHA256 {
		t.Errorf("the plan read again: %v", err)
	}
}

func TestMakePlanWritesNothing(t *testing.T) {
	dir := pfWrite(t, pfFiles())
	before := tree(t, dir)
	f, err := pfFind(t, dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ceremony.MakePlan(f, pfEnv()); err != nil {
		t.Fatal(err)
	}
	sameTree(t, "MakePlan", before, tree(t, dir))
}

func TestTheRequestsOfALeavesOutAreInThePlanAndCountForNothingElse(t *testing.T) {
	files2 := pfFiles()
	files2["requests/acme-ca-2027/request.json"] = "x"
	files2["requests/mid/request.json"] = "x"
	p := pfPlan(t, files2)
	want := []ceremony.LeftOut{
		{Object: "requests/acme-ca-2027", Reason: pfLeftOutReason},
		{Object: "requests/mid", Reason: pfLeftOutReason},
	}
	if !reflect.DeepEqual(p.LeavesOut, want) {
		t.Errorf("LeavesOut = %+v", p.LeavesOut)
	}
	m := pfDecode(t, p.JSON)
	lo := pfList(m, "leaves_out")
	if len(lo) != 2 || pfObj(lo, 0)["object"] != "requests/acme-ca-2027" || pfObj(lo, 0)["reason"] != pfLeftOutReason || len(pfObj(lo, 0)) != 2 {
		t.Errorf("leaves_out = %v", lo)
	}
	if len(pfList(m, "applies")) != 2 || len(pfList(m, "wanted")) != 2 {
		t.Errorf("a request changed applies or wanted: %v", m)
	}
	again, err := ceremony.ReadPlanOut(p.JSON)
	if err != nil || !reflect.DeepEqual(again.LeavesOut, want) {
		t.Errorf("ReadPlanOut: %+v, %v", again, err)
	}
}

// ReadPlanOut.

func TestReadPlanOutGivesTheTypedValueThatMakePlanMade(t *testing.T) {
	for name, files2 := range map[string]map[string]string{
		"no request":   pfFiles(),
		"two requests": {"ritueel.yaml": pfSettings, "want/roots/x509.yaml": pfX509Test, "requests/a/x": "x", "requests/b/x": "x"},
	} {
		t.Run(name, func(t *testing.T) {
			made := pfPlan(t, files2)
			read, err := ceremony.ReadPlanOut(made.JSON)
			if err != nil {
				t.Fatalf("ReadPlanOut: %v", err)
			}
			if !reflect.DeepEqual(made, read) {
				t.Errorf("made %+v\nread %+v", made, read)
			}
			if canon, err := read.Plan.Canonical(); err != nil || !bytes.Equal(canon, made.JSON) {
				t.Errorf("Canonical = %q, %v", canon, err)
			}
			if read.SHA256 != sum(made.JSON) || read.Prefix != read.SHA256[:8] {
				t.Errorf("digest %s prefix %s", read.SHA256, read.Prefix)
			}
		})
	}
}

func TestReadPlanOutCopiesTheBytes(t *testing.T) {
	in := []byte(pfGolden)
	p, err := ceremony.ReadPlanOut(in)
	if err != nil {
		t.Fatal(err)
	}
	in[0] = '['
	if string(p.JSON) != pfGolden || p.SHA256 != pfGoldenDigest {
		t.Error("the plan shares the bytes of the caller")
	}
}

func TestAPlanEditedByOneByteAndReadAgainHasAnotherDigest(t *testing.T) {
	b := []byte(pfGolden)
	i := bytes.Index(b, []byte(pfSumSet))
	if i < 0 {
		t.Fatal("no digest in the plan")
	}
	b[i] = 'e'
	p, err := ceremony.ReadPlanOut(b)
	if err != nil {
		t.Fatalf("a plan with another digest of a wanted file is a plan: %v", err)
	}
	if p.SHA256 == pfGoldenDigest || p.SHA256 != sum(b) {
		t.Errorf("digest = %s", p.SHA256)
	}
}

func TestReadPlanOutRefusesAPlanWithAMemberWrong(t *testing.T) {
	type edit = func(m map[string]any)
	sig := func(m map[string]any, i int) map[string]any { return pfObj(pfList(m, "signatures"), i) }
	root := func(m map[string]any) map[string]any { return m["root"].(map[string]any) }
	cases := map[string]edit{}
	// A member that is missing.
	for _, k := range []string{"version", "ceremony", "command", "made_at", "ceremony_time", "ritueel", "wanted", "applies", "root", "signatures", "births", "trust_sequence"} {
		cases["no "+k] = func(m map[string]any) { delete(m, k) }
	}
	// A member of another type, and null.
	for k, v := range map[string]any{"version": "1", "ceremony": 1, "command": 1, "made_at": 1, "ceremony_time": []any{}, "ritueel": "x", "wanted": "x",
		"applies": map[string]any{}, "root": []any{}, "signatures": "x", "births": 1, "trust_sequence": "1", "leaves_out": "x"} {
		cases["a "+k+" of another type"] = func(m map[string]any) { m[k] = v }
	}
	for _, k := range []string{"ritueel", "applies", "root", "signatures", "births", "wanted", "made_at"} {
		cases["a null "+k] = func(m map[string]any) { m[k] = nil }
	}
	// A member that the first apply does not make.
	for k, v := range map[string]any{"tbs_sha256": strings.Repeat("a", 64), "key": strings.Repeat("a", 64), "touches": 0, "inputs": []any{},
		"arguments": map[string]any{}, "requests": []any{}, "base_sequence": 0, "last_record_sha256": strings.Repeat("a", 64), "root_reason": "x", "unknown": 1} {
		cases["an extra member "+k] = func(m map[string]any) { m[k] = v }
	}
	cases["an extra member in a signature: tbs_sha256"] = func(m map[string]any) { sig(m, 0)["tbs_sha256"] = strings.Repeat("a", 64) }
	cases["an extra member in a signature: key"] = func(m map[string]any) { sig(m, 4)["key"] = strings.Repeat("a", 64) }
	cases["an extra member in a signature: reason"] = func(m map[string]any) { sig(m, 1)["reason"] = "retired" }
	cases["an extra member in a birth: creation_time"] = func(m map[string]any) { pfObj(pfList(m, "births"), 0)["creation_time"] = "2026-11-20T10:00:00Z" }
	cases["an extra member in a change"] = func(m map[string]any) { pfObj(pfList(m, "applies"), 0)["extra"] = 1 }
	cases["an extra member in the root: x509"] = func(m map[string]any) { root(m)["x509"] = strings.Repeat("a", 64) }
	cases["an extra member in the root: openpgp"] = func(m map[string]any) { root(m)["openpgp"] = strings.Repeat("a", 40) }
	cases["an extra member in the program"] = func(m map[string]any) { m["ritueel"].(map[string]any)["extra"] = 1 }
	cases["an extra member in a wanted file"] = func(m map[string]any) { pfObj(pfList(m, "wanted"), 0)["extra"] = 1 }
	cases["a missing member in the program"] = func(m map[string]any) { delete(m["ritueel"].(map[string]any), "sha256") }
	// Values.
	cases["version 2"] = func(m map[string]any) { m["version"] = 2 }
	cases["command close"] = func(m map[string]any) { m["command"] = "close" }
	cases["trust_sequence 2"] = func(m map[string]any) { m["trust_sequence"] = 2 }
	cases["trust_sequence 0"] = func(m map[string]any) { m["trust_sequence"] = 0 }
	cases["made_at differs"] = func(m map[string]any) { m["made_at"] = "2026-11-20T10:00:01Z" }
	cases["ceremony_time differs"] = func(m map[string]any) { m["ceremony_time"] = "2026-11-20T10:00:01Z" }
	cases["a time with an offset"] = func(m map[string]any) {
		m["ceremony_time"], m["made_at"] = "2026-11-20T10:00:00+00:00", "2026-11-20T10:00:00+00:00"
	}
	cases["a time of lower-case letters"] = func(m map[string]any) {
		m["ceremony_time"], m["made_at"] = "2026-11-20t10:00:00z", "2026-11-20t10:00:00z"
	}
	cases["a time of year 0"] = func(m map[string]any) {
		m["ceremony_time"], m["made_at"] = "0000-01-01T00:00:00Z", "0000-01-01T00:00:00Z"
	}
	cases["a ceremony named with a suffix of the digest"] = func(m map[string]any) { m["ceremony"] = pfName + "-eb53b997" }
	cases["a ceremony of another time"] = func(m map[string]any) { m["ceremony"] = "20261120T100001Z-apply" }
	cases["a ceremony of another command"] = func(m map[string]any) { m["ceremony"] = "20261120T100000Z-close" }
	cases["a ceremony in lower case"] = func(m map[string]any) { m["ceremony"] = "20261120t100000z-apply" }
	cases["an empty ceremony"] = func(m map[string]any) { m["ceremony"] = "" }
	// wanted.
	cases["wanted in the other order"] = func(m map[string]any) {
		w := pfList(m, "wanted")
		w[0], w[1] = w[1], w[0]
	}
	cases["wanted with three files"] = func(m map[string]any) {
		m["wanted"] = append(pfList(m, "wanted"), map[string]any{"path": "want/roots/z.yaml", "sha256": strings.Repeat("a", 64)})
	}
	cases["wanted with one file"] = func(m map[string]any) { m["wanted"] = pfList(m, "wanted")[:1] }
	cases["wanted empty"] = func(m map[string]any) { m["wanted"] = []any{} }
	cases["a digest in capitals"] = func(m map[string]any) { pfObj(pfList(m, "wanted"), 0)["sha256"] = strings.Repeat("A", 64) }
	cases["a short digest"] = func(m map[string]any) { pfObj(pfList(m, "wanted"), 1)["sha256"] = strings.Repeat("a", 63) }
	cases["the first wanted file is not ritueel.yaml"] = func(m map[string]any) { pfObj(pfList(m, "wanted"), 0)["path"] = "a.yaml" }
	cases["the second wanted file is a delegation"] = func(m map[string]any) {
		pfObj(pfList(m, "wanted"), 1)["path"] = "want/delegations/x509.yaml"
	}
	cases["the second wanted file has a name in capitals"] = func(m map[string]any) {
		pfObj(pfList(m, "wanted"), 1)["path"] = "want/roots/X509.yaml"
	}
	cases["the second wanted file is not yaml"] = func(m map[string]any) { pfObj(pfList(m, "wanted"), 1)["path"] = "want/roots/x509.yml" }
	cases["the second wanted file is deeper"] = func(m map[string]any) { pfObj(pfList(m, "wanted"), 1)["path"] = "want/roots/a/x509.yaml" }
	// applies and births.
	cases["applies in the other order"] = func(m map[string]any) {
		a := pfList(m, "applies")
		a[0], a[1] = a[1], a[0]
	}
	cases["applies with a delete"] = func(m map[string]any) { pfObj(pfList(m, "applies"), 1)["change"] = "delete" }
	cases["applies for another root"] = func(m map[string]any) { pfObj(pfList(m, "applies"), 0)["object"] = "other/A" }
	cases["applies with a label that is not the next letter"] = func(m map[string]any) { pfObj(pfList(m, "applies"), 1)["object"] = "x509/C" }
	cases["applies with a lower-case label"] = func(m map[string]any) { pfObj(pfList(m, "applies"), 0)["object"] = "x509/a" }
	cases["applies empty"] = func(m map[string]any) { m["applies"] = []any{} }
	cases["applies longer than births"] = func(m map[string]any) {
		m["applies"] = append(pfList(m, "applies"), map[string]any{"change": "create", "object": "x509/C"})
	}
	cases["births shorter than applies"] = func(m map[string]any) { m["births"] = pfList(m, "births")[:1] }
	cases["births in the other order"] = func(m map[string]any) {
		b := pfList(m, "births")
		b[0], b[1] = b[1], b[0]
	}
	cases["a birth with another place"] = func(m map[string]any) { pfObj(pfList(m, "births"), 0)["place"] = "keys/x509-root-a" }
	cases["a birth with a place of another label"] = func(m map[string]any) { pfObj(pfList(m, "births"), 1)["place"] = "x509-root-a" }
	cases["a birth with another purpose"] = func(m map[string]any) { pfObj(pfList(m, "births"), 0)["purpose"] = "openpgp-primary" }
	cases["a birth in another store"] = func(m map[string]any) { pfObj(pfList(m, "births"), 0)["store"] = "piv" }
	// root.
	cases["a root of the label B"] = func(m map[string]any) { root(m)["label"] = "B" }
	cases["a root that is not a test root"] = func(m map[string]any) { root(m)["test"] = false }
	cases["a root that cannot be copied"] = func(m map[string]any) { root(m)["copyable"] = false }
	cases["a root in a card"] = func(m map[string]any) { root(m)["store"] = "piv" }
	cases["a root with no test member"] = func(m map[string]any) { delete(root(m), "test") }
	// ritueel.
	cases["a version with a space"] = func(m map[string]any) { m["ritueel"].(map[string]any)["version"] = "v1 2" }
	cases["an empty version"] = func(m map[string]any) { m["ritueel"].(map[string]any)["version"] = "" }
	cases["a version of 129 bytes"] = func(m map[string]any) { m["ritueel"].(map[string]any)["version"] = strings.Repeat("v", 129) }
	cases["a version with a control character"] = func(m map[string]any) { m["ritueel"].(map[string]any)["version"] = "v1\n" }
	cases["a system in capitals"] = func(m map[string]any) { m["ritueel"].(map[string]any)["os_arch"] = "Linux/amd64" }
	cases["a system of one word"] = func(m map[string]any) { m["ritueel"].(map[string]any)["os_arch"] = "linux" }
	cases["a system of three words"] = func(m map[string]any) { m["ritueel"].(map[string]any)["os_arch"] = "linux/amd64/v2" }
	cases["a system of 33 letters"] = func(m map[string]any) {
		m["ritueel"].(map[string]any)["os_arch"] = strings.Repeat("a", 33) + "/amd64"
	}
	cases["an architecture of 33 letters"] = func(m map[string]any) {
		m["ritueel"].(map[string]any)["os_arch"] = "linux/" + strings.Repeat("a", 33)
	}
	cases["an empty architecture"] = func(m map[string]any) { m["ritueel"].(map[string]any)["os_arch"] = "linux/" }
	cases["a program digest in capitals"] = func(m map[string]any) { m["ritueel"].(map[string]any)["sha256"] = strings.Repeat("AB", 32) }
	cases["a program digest that is short"] = func(m map[string]any) { m["ritueel"].(map[string]any)["sha256"] = "ab" }
	// signatures.
	cases["no signature"] = func(m map[string]any) { m["signatures"] = []any{} }
	cases["a signature too many"] = func(m map[string]any) {
		m["signatures"] = append(pfList(m, "signatures"), map[string]any{"n": 6, "kind": "root-list", "subject": "A", "derived": true})
	}
	cases["a signature too few"] = func(m map[string]any) { m["signatures"] = pfList(m, "signatures")[:4] }
	cases["the list first"] = func(m map[string]any) {
		s := pfList(m, "signatures")
		s[0], s[4] = s[4], s[0]
		for i := range s {
			pfObj(s, i)["n"] = i + 1
		}
	}
	cases["the removal before the certificate"] = func(m map[string]any) {
		s := pfList(m, "signatures")
		s[0], s[1] = s[1], s[0]
		for i := range s {
			pfObj(s, i)["n"] = i + 1
		}
	}
	cases["the keys in the other order"] = func(m map[string]any) {
		s := pfList(m, "signatures")
		s[0], s[2] = s[2], s[0]
		s[1], s[3] = s[3], s[1]
		for i := range s {
			pfObj(s, i)["n"] = i + 1
		}
	}
	cases["n out of order"] = func(m map[string]any) { sig(m, 2)["n"] = 7 }
	cases["n from 0"] = func(m map[string]any) {
		for i := range pfList(m, "signatures") {
			sig(m, i)["n"] = i
		}
	}
	cases["a kind that is not of the first apply"] = func(m map[string]any) { sig(m, 1)["kind"] = "subkey-binding" }
	cases["a certificate for a label that has no key"] = func(m map[string]any) { sig(m, 0)["subject"] = "C" }
	cases["the list signed by the second key"] = func(m map[string]any) { sig(m, 4)["subject"] = "B" }
	cases["a signature that is not derived"] = func(m map[string]any) { sig(m, 1)["derived"] = false }
	cases["a certificate that is not derived"] = func(m map[string]any) { delete(sig(m, 0), "derived") }
	cases["the list that is not derived"] = func(m map[string]any) { delete(sig(m, 4), "derived") }
	cases["a removal with a serial"] = func(m map[string]any) { sig(m, 1)["serial"] = pfSerialA }
	cases["a removal with a validity"] = func(m map[string]any) { sig(m, 1)["not_before"] = "2026-11-20T10:00:00Z" }
	cases["a list with a serial"] = func(m map[string]any) { sig(m, 4)["serial"] = pfSerialA }
	cases["a certificate with no serial"] = func(m map[string]any) { delete(sig(m, 0), "serial") }
	cases["a serial with a leading zero"] = func(m map[string]any) { sig(m, 0)["serial"] = "0" + pfSerialA }
	cases["a serial in capitals"] = func(m map[string]any) { sig(m, 0)["serial"] = strings.ToUpper(pfSerialA) }
	cases["a serial that is not hexadecimal"] = func(m map[string]any) { sig(m, 0)["serial"] = "g" + pfSerialA[1:] }
	cases["a serial of 16 digits"] = func(m map[string]any) { sig(m, 0)["serial"] = "2030405060708090" }
	cases["a serial of 41 digits"] = func(m map[string]any) { sig(m, 0)["serial"] = "11" + pfSerialA }
	cases["a serial with a sign"] = func(m map[string]any) { sig(m, 0)["serial"] = "+" + pfSerialA[1:] }
	cases["a serial that is empty"] = func(m map[string]any) { sig(m, 0)["serial"] = "" }
	cases["one serial twice"] = func(m map[string]any) { sig(m, 2)["serial"] = pfSerialA }
	cases["35 months"] = func(m map[string]any) { sig(m, 0)["not_after"] = "2029-10-20T10:00:00Z" }
	cases["37 months"] = func(m map[string]any) { sig(m, 0)["not_after"] = "2029-12-20T10:00:00Z" }
	cases["36 months less a second"] = func(m map[string]any) { sig(m, 2)["not_after"] = "2029-11-20T09:59:59Z" }
	cases["not_before is not the ceremony time"] = func(m map[string]any) { sig(m, 0)["not_before"] = "2026-11-20T09:00:00Z" }
	cases["no not_after"] = func(m map[string]any) { delete(sig(m, 2), "not_after") }
	// leaves_out.
	cases["an empty leaves_out"] = func(m map[string]any) { m["leaves_out"] = []any{} }
	cases["a left out that is not a request"] = func(m map[string]any) {
		m["leaves_out"] = []any{map[string]any{"object": "x509/C", "reason": pfLeftOutReason}}
	}
	cases["a left out with another reason"] = func(m map[string]any) {
		m["leaves_out"] = []any{map[string]any{"object": "requests/a", "reason": "later"}}
	}
	cases["a left out with no reason"] = func(m map[string]any) {
		m["leaves_out"] = []any{map[string]any{"object": "requests/a"}}
	}
	cases["a left out request that is not a plain name"] = func(m map[string]any) {
		m["leaves_out"] = []any{map[string]any{"object": "requests/a b", "reason": pfLeftOutReason}}
	}
	cases["left out in the wrong order"] = func(m map[string]any) {
		m["leaves_out"] = []any{
			map[string]any{"object": "requests/b", "reason": pfLeftOutReason},
			map[string]any{"object": "requests/a", "reason": pfLeftOutReason},
		}
	}
	cases["the same request left out twice"] = func(m map[string]any) {
		o := map[string]any{"object": "requests/a", "reason": pfLeftOutReason}
		m["leaves_out"] = []any{o, o}
	}
	cases["1001 requests left out"] = func(m map[string]any) {
		var l []any
		for i := 0; i <= wanted.MaxFiles; i++ {
			l = append(l, map[string]any{"object": fmt.Sprintf("requests/r%04d", i), "reason": pfLeftOutReason})
		}
		m["leaves_out"] = l
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			b := pfEdit(t, edit)
			p, err := ceremony.ReadPlanOut(b)
			if err == nil || p != nil {
				t.Errorf("ReadPlanOut accepted the plan %s", b)
			}
		})
	}
}

func TestReadPlanOutRefusesAPlanOfMoreKeysThanAListHolds(t *testing.T) {
	f := pfMustFind(t, pfFiles())
	f.Applies = pfApplies(26)
	p, err := ceremony.MakePlan(f, pfEnv())
	if err != nil {
		t.Fatal(err)
	}
	// The same plan with a 27th key by hand: the next letter after Z, which is no label.
	b := pfEncode(t, func() map[string]any {
		m := pfDecode(t, p.JSON)
		m["applies"] = append(pfList(m, "applies"), map[string]any{"change": "create", "object": "x509/["})
		m["births"] = append(pfList(m, "births"), map[string]any{"label": "[", "place": "[.x509.key.pem", "purpose": "x509-root", "store": "software"})
		sigs := pfList(m, "signatures")
		list := sigs[len(sigs)-1].(map[string]any)
		list["n"] = 2*27 + 1
		sigs = append(sigs[:len(sigs)-1],
			map[string]any{"derived": true, "kind": "root-certificate", "n": 2*26 + 1, "not_after": "2029-11-20T10:00:00Z", "not_before": "2026-11-20T10:00:00Z", "serial": "7fffffffffffffffffffffffffffffffffffffff", "subject": "["},
			map[string]any{"derived": true, "kind": "root-removal", "n": 2*26 + 2, "subject": "["},
			list)
		m["signatures"] = sigs
		return m
	}())
	if got, err := ceremony.ReadPlanOut(b); err == nil || got != nil {
		t.Errorf("ReadPlanOut accepted a plan of 27 keys")
	}
}

func TestReadPlanOutAcceptsTheOneThousandRequestsOfTheLimit(t *testing.T) {
	var l []any
	for i := range wanted.MaxFiles {
		l = append(l, map[string]any{"object": fmt.Sprintf("requests/r%04d", i), "reason": pfLeftOutReason})
	}
	b := pfEdit(t, func(m map[string]any) { m["leaves_out"] = l })
	p, err := ceremony.ReadPlanOut(b)
	if err != nil || len(p.LeavesOut) != wanted.MaxFiles {
		t.Fatalf("ReadPlanOut of 1000 requests: %v", err)
	}
}

func TestReadPlanOutRefusesAFileThatIsNotTheCanonicalBytesOfAPlan(t *testing.T) {
	pretty, err := json.MarshalIndent(pfDecode(t, []byte(pfGolden)), "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	// The same plan with the first two members swapped, by hand.
	iApplies, iBirths, iCeremony := strings.Index(pfGolden, `"applies":`), strings.Index(pfGolden, `"births":`), strings.Index(pfGolden, `"ceremony":`)
	swapped := "{" + pfGolden[iBirths:iCeremony] + pfGolden[iApplies:iBirths] + pfGolden[iCeremony:]
	cases := map[string][]byte{
		"indented":                       pretty,
		"a trailing line feed":           []byte(pfGolden + "\n"),
		"a leading space":                []byte(" " + pfGolden),
		"a byte order mark":              []byte("\xef\xbb\xbf" + pfGolden),
		"a space after a colon":          []byte(strings.Replace(pfGolden, `"version":1`, `"version": 1`, 1)),
		"a unicode escape for a name":    []byte(strings.Replace(pfGolden, `"label":"A"`, `"label":"`+"\\"+`u0041"`, 1)),
		"a number with a fraction":       []byte(strings.Replace(pfGolden, `"version":1`, `"version":1.0`, 1)),
		"a number with an exponent":      []byte(strings.Replace(pfGolden, `"version":1`, `"version":1e0`, 1)),
		"a minus zero":                   []byte(strings.Replace(pfGolden, `"n":1`, `"n":-0`, 1)),
		"members swapped":                []byte(swapped),
		"a member twice":                 []byte(strings.Replace(pfGolden, `"version":1,`, `"version":1,"version":1,`, 1)),
		"a member twice, last one lower": []byte(strings.Replace(pfGolden, `"command":"apply",`, `"command":"apply","command":"apply",`, 1)),
		"a null":                         []byte("null"),
		"an array":                       []byte("[]"),
		"an empty object":                []byte("{}"),
		"a string":                       []byte(`"x"`),
		"a number":                       []byte("1"),
		"empty":                          {},
		"nil":                            nil,
		"one byte":                       []byte("{"),
		"cut in the middle":              []byte(pfGolden[:len(pfGolden)/2]),
		"cut one byte short":             []byte(pfGolden[:len(pfGolden)-1]),
		"bytes that are not UTF-8":       []byte(strings.Replace(pfGolden, `"test":true`, "\"test\":true,\"x\":\"\xff\"", 1)),
		"a name with a lone surrogate":   []byte(strings.Replace(pfGolden, `"label":"A"`, `"label":"\ud800"`, 1)),
		"nesting past the limit":         []byte(strings.Repeat("[", 20000) + strings.Repeat("]", 20000)),
		"a huge number":                  []byte(strings.Replace(pfGolden, `"version":1`, `"version":1e400`, 1)),
		"a number past the exact range":  []byte(strings.Replace(pfGolden, `"trust_sequence":1`, `"trust_sequence":9007199254740993`, 1)),
		"two plans in one file":          []byte(pfGolden + pfGolden),
		"more than 256 KiB":              []byte(`{"version":1,"x":"` + strings.Repeat("a", 256*1024) + `"}`),
	}
	for name, b := range cases {
		t.Run(name, func(t *testing.T) {
			p, err := ceremony.ReadPlanOut(b)
			if err == nil || p != nil {
				t.Errorf("ReadPlanOut accepted %.100q", b)
			}
		})
	}
}

func TestReadPlanOutReadsAFileOfExactlyTheLimit(t *testing.T) {
	// A plan whose list of requests fills the file to just under 256 KiB is a plan, and one more
	// byte of padding is not read at all.
	var l []any
	for i := range wanted.MaxFiles {
		l = append(l, map[string]any{"object": fmt.Sprintf("requests/r%04d", i), "reason": pfLeftOutReason})
	}
	b := pfEdit(t, func(m map[string]any) { m["leaves_out"] = l })
	if len(b) > 256*1024 {
		t.Fatalf("the plan of 1,000 requests is %d bytes", len(b))
	}
	if _, err := ceremony.ReadPlanOut(b); err != nil {
		t.Fatal(err)
	}
	over := append(append([]byte(nil), b...), bytes.Repeat([]byte(" "), 256*1024)...)
	if p, err := ceremony.ReadPlanOut(over); err == nil || p != nil {
		t.Error("a file over the limit was read")
	}
}

func TestEveryErrorOfReadPlanOutIsPrintableAndOnOneLine(t *testing.T) {
	for _, in := range []string{"", "x", pfGolden + "\x00", strings.Replace(pfGolden, "x509/A", "x509/\xe2\x80\xae\x1b[31m", 1), `{"version":1,"ceremony":"\u0001\n"}`} {
		_, err := ceremony.ReadPlanOut([]byte(in))
		if err == nil {
			t.Errorf("accepted %.60q", in)
			continue
		}
		if !pfPrintable(err.Error()) {
			t.Errorf("the error for %.40q is not printable ASCII on one line: %+q", in, err.Error())
		}
	}
}

var pfDigest64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

func TestThePlanDigestIsTheSha256OfTheBytes(t *testing.T) {
	p := pfPlan(t, pfFiles())
	if !pfDigest64.MatchString(p.SHA256) || p.SHA256 != sum(p.JSON) || p.Prefix != p.SHA256[:8] {
		t.Errorf("SHA256 %q, Prefix %q", p.SHA256, p.Prefix)
	}
}
