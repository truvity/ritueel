//go:build linux || darwin

package history

import (
	"bytes"
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

// The page lists the findings in this order (docs/reference/ceremony-record.md, "The hash chain").
var pageOrder = []string{
	"chain-broken", "fork", "record-off-chain", "record-not-canonical", "record-version-unknown",
	"record-invalid", "transcript-digest", "file-digest", "file-missing", "trust-set-unlisted",
	"unfinished-ceremony", "anchor-unknown", "unexpected-name", "unexpected-file",
}

func TestCodesAreTheNamesOfThePageInTheOrderOfThePage(t *testing.T) {
	// The code file-unlisted has a place of its own, held in file_unlisted_test.go; the others keep the
	// order of the page.
	var got []string
	for _, c := range Codes() {
		if c != FileUnlisted {
			got = append(got, string(c))
		}
	}
	if !slices.Equal(got, pageOrder) {
		t.Errorf("Codes() = %v\n want %v", got, pageOrder)
	}
	// The returned list is a copy.
	l := Codes()
	l[0] = "x"
	if Codes()[0] != ChainBroken {
		t.Error("changing the list that Codes returns changes the codes")
	}
}

// "Every finding ends the command with exit code 3, except unfinished-ceremony and
// unexpected-file: they are notices."
func TestOnlyTwoCodesAreNotices(t *testing.T) {
	for _, c := range Codes() {
		notice := c == "unfinished-ceremony" || c == "unexpected-file"
		if c.Notice() != notice || c.Fails() == notice {
			t.Errorf("%s: Notice() = %v, Fails() = %v; want a notice: %v", c, c.Notice(), c.Fails(), notice)
		}
	}
}

// codeCase is the smallest bundle that gives one code.
type codeCase struct {
	name string
	// build makes the bundle and says what a check must find.
	build func(t *testing.T) (b *bundle, want []wf)
	// ignore lists the codes that are an open point for this bundle: they may or may not be there.
	ignore   []Code
	reasons  []Code
	warnings []Code
	records  int
}

func recordPath(r *rec) string { return "history/" + r.folder + "/record.json" }
func folderPath(r *rec) string { return "history/" + r.folder }
func setPath(r *rec) string    { return "trust/" + r.set }

var codeCases = []codeCase{
	{
		name: "chain-broken: a record names a record that is not there",
		build: func(t *testing.T) (*bundle, []wf) {
			b := newBundle(t)
			r := b.apply(noSet, prev(digestA))
			return b, []wf{{ChainBroken, folderPath(r)}}
		},
		reasons: []Code{ChainBroken}, records: 1,
	},
	{
		name: "fork: two records name one record",
		build: func(t *testing.T) (*bundle, []wf) {
			b := newBundle(t)
			a := b.apply()
			b.apply()
			b.apply(prev(a.digest))
			return b, []wf{{Fork, folderPath(a)}}
		},
		reasons: []Code{Fork}, records: 3,
	},
	{
		name: "record-off-chain: a record names one that is not on the chain",
		build: func(t *testing.T) (*bundle, []wf) {
			b := newBundle(t)
			b.apply(noSet)
			x := b.apply(noSet, prev(digestA))
			y := b.apply(noSet, prev(x.digest))
			return b, []wf{{ChainBroken, folderPath(x)}, {RecordOffChain, folderPath(y)}}
		},
		reasons: []Code{ChainBroken, RecordOffChain}, records: 3,
	},
	{
		name: "record-not-canonical: a line break after the record",
		build: func(t *testing.T) (*bundle, []wf) {
			b := newBundle(t)
			r := b.apply(noSet, recordAs(func(c []byte) []byte { return append(c, '\n') }))
			return b, []wf{{RecordNotCanonical, recordPath(r)}}
		},
		reasons: []Code{RecordNotCanonical}, records: 1,
	},
	{
		name: "record-version-unknown: version 2",
		build: func(t *testing.T) (*bundle, []wf) {
			b := newBundle(t)
			r := b.apply(noSet, recordAs(func([]byte) []byte { return []byte(`{"version":2,"x":{}}`) }))
			return b, []wf{{RecordVersionUnknown, recordPath(r)}}
		},
		ignore: []Code{RecordOffChain}, reasons: []Code{RecordVersionUnknown}, records: 1,
	},
	{
		name: "record-invalid: an unknown member",
		build: func(t *testing.T) (*bundle, []wf) {
			b := newBundle(t)
			r := b.apply(noSet, recordAs(func(c []byte) []byte {
				return append(bytes.TrimSuffix(c, []byte("}")), []byte(`,"zzz":1}`)...)
			}))
			return b, []wf{{RecordInvalid, recordPath(r)}}
		},
		ignore: []Code{RecordOffChain}, reasons: []Code{RecordInvalid}, records: 1,
	},
	{
		name: "record-invalid: a required member is missing",
		build: func(t *testing.T) (*bundle, []wf) {
			b := newBundle(t)
			r := b.apply(noSet, recordAs(func(c []byte) []byte {
				return bytes.Replace(c, []byte(`"outcome":"completed",`), nil, 1)
			}))
			return b, []wf{{RecordInvalid, recordPath(r)}}
		},
		ignore: []Code{RecordOffChain}, reasons: []Code{RecordInvalid}, records: 1,
	},
	{
		name: "transcript-digest: the transcript changed",
		build: func(t *testing.T) (*bundle, []wf) {
			b := newBundle(t)
			r := b.apply(noSet)
			b.put("history/"+r.folder+"/transcript.txt", []byte("another text\n"))
			return b, []wf{{TranscriptDigest, "history/" + r.folder + "/transcript.txt"}}
		},
		reasons: []Code{TranscriptDigest}, records: 1,
	},
	{
		name: "file-digest: a listed artifact changed",
		build: func(t *testing.T) (*bundle, []wf) {
			b := newBundle(t)
			r := b.apply()
			b.put("trust/"+r.set+"/keys.txt", []byte("other keys\n"))
			return b, []wf{{FileDigest, "trust/" + r.set + "/keys.txt"}}
		},
		reasons: []Code{FileDigest}, records: 1,
	},
	{
		name: "file-missing: a listed artifact is gone",
		build: func(t *testing.T) (*bundle, []wf) {
			b := newBundle(t)
			r := b.apply()
			b.remove("trust/" + r.set + "/keys.txt")
			return b, []wf{{FileMissing, "trust/" + r.set + "/keys.txt"}}
		},
		reasons: []Code{FileMissing}, records: 1,
	},
	{
		name: "trust-set-unlisted: a trust set that no record lists",
		build: func(t *testing.T) (*bundle, []wf) {
			b := newBundle(t)
			b.apply(noSet)
			b.mkdir("trust/9-3fa9c1d2")
			return b, []wf{{TrustSetUnlisted, "trust/9-3fa9c1d2"}}
		},
		reasons: []Code{TrustSetUnlisted}, records: 1,
	},
	{
		name: "unfinished-ceremony: a trust set with an open attempt (a notice)",
		build: func(t *testing.T) (*bundle, []wf) {
			b := newBundle(t)
			b.apply()
			u := b.unfinished()
			return b, []wf{{UnfinishedCeremony, setPath(u)}}
		},
		warnings: []Code{UnfinishedCeremony}, records: 1,
	},
	{
		name: "anchor-unknown: the anchor of a root list is not a record",
		build: func(t *testing.T) (*bundle, []wf) {
			b := newBundle(t)
			r := b.apply(func(r *rec) {
				r.artifacts["trust/"+r.set+"/root-list.json"] = rootListBytes(digestB)
				r.refresh()
			})
			return b, []wf{{AnchorUnknown, "trust/" + r.set + "/root-list.json"}}
		},
		reasons: []Code{AnchorUnknown}, records: 1,
	},
	{
		name: "unexpected-name: a folder with a space in its name",
		build: func(t *testing.T) (*bundle, []wf) {
			b := newBundle(t)
			b.apply(noSet)
			b.mkdir("history/a b")
			return b, []wf{{UnexpectedName, "history/a" + bs + "x20b"}}
		},
		reasons: []Code{UnexpectedName}, records: 1,
	},
	{
		name: "unexpected-file: a stray file in a ceremony folder (a notice)",
		build: func(t *testing.T) (*bundle, []wf) {
			b := newBundle(t)
			r := b.apply(noSet)
			b.put("history/"+r.folder+"/notes.txt", []byte("x"))
			return b, []wf{{UnexpectedFile, "history/" + r.folder + "/notes.txt"}}
		},
		warnings: []Code{UnexpectedFile}, records: 1,
	},
	{
		name: "unexpected-file: a leftover temporary name (a notice)",
		build: func(t *testing.T) (*bundle, []wf) {
			b := newBundle(t)
			b.apply(noSet)
			b.mkdir("history/.rt-abcdefghijk")
			return b, []wf{{UnexpectedFile, "history/.rt-abcdefghijk"}}
		},
		warnings: []Code{UnexpectedFile}, records: 1,
	},
}

// Every code of the page has a bundle that gives it, and the report says what the page says: the
// code, the path, a line of the form "code path: detail", the exit meaning, the reasons and the
// warnings.
func TestEveryCodeHasTheSmallestBundleThatGivesIt(t *testing.T) {
	seen := map[Code]bool{}
	for _, c := range codeCases {
		t.Run(c.name, func(t *testing.T) {
			b, want := c.build(t)
			rep := b.run()
			wantFindings(t, rep, want, c.ignore...)
			wantReasons(t, rep, c.reasons, c.warnings, c.ignore...)
			if rep.Records != c.records {
				t.Errorf("Records = %d, want %d", rep.Records, c.records)
			}
			for _, w := range want {
				seen[w.code] = true
				var f Finding
				for _, g := range rep.Findings {
					if g.Code == w.code && g.Path == w.path {
						f = g
					}
				}
				if f.Code == "" {
					continue
				}
				notice := w.code == "unfinished-ceremony" || w.code == "unexpected-file"
				if f.Code.Notice() != notice || f.Code.Fails() == notice {
					t.Errorf("%s: Notice() = %v, Fails() = %v", f.Code, f.Code.Notice(), f.Code.Fails())
				}
				if !strings.HasPrefix(f.Line(), string(w.code)+" "+w.path+": ") {
					t.Errorf("the line %q does not begin with %q", f.Line(), string(w.code)+" "+w.path+": ")
				}
			}
			// A notice does not make the history unclean; a failing finding does.
			if clean := len(c.reasons) == 0; rep.Clean() != clean {
				t.Errorf("Clean() = %v, want %v", rep.Clean(), clean)
			}
			if len(rep.Failing())+len(rep.Notices()) != len(rep.Findings) {
				t.Errorf("Failing() and Notices() hold %d + %d findings of %d", len(rep.Failing()), len(rep.Notices()), len(rep.Findings))
			}
		})
	}
	for _, code := range Codes() {
		if code == FileUnlisted {
			continue // its case is in file_unlisted_test.go
		}
		if !seen[code] {
			t.Errorf("no case gives the code %s", code)
		}
	}
}

func TestEveryCodeCaseGivesAFailingRunOrANoticeAsTheCodeSays(t *testing.T) {
	for _, c := range codeCases {
		t.Run(c.name, func(t *testing.T) {
			b, _ := c.build(t)
			rep := b.run()
			if (len(rep.Reasons()) > 0) == rep.Clean() {
				t.Errorf("Reasons() = %v but Clean() = %v", rep.Reasons(), rep.Clean())
			}
			// The two members of the JSON object, as the command writes them.
			if _, err := json.Marshal(map[string]any{"reasons": rep.Reasons(), "warnings": rep.Warnings()}); err != nil {
				t.Error(err)
			}
		})
	}
}
