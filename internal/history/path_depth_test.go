//go:build linux || darwin

package history

import (
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/ceremony/files"
)

// The depth of a listed path. These tests name the constant and never write its number.

func pathOfElements(n int) string {
	elems := make([]string, n)
	for i := range elems {
		elems[i] = "d"
	}
	elems[n-1] = "f"
	return strings.Join(elems, "/")
}

// A path of the longest allowed depth is read, and one element more is a fault of the record.
func TestListedPathOfTheMostElementsIsReadAndOneMoreIsInvalid(t *testing.T) {
	deep := pathOfElements(files.MaxPathElements)
	b := newBundle(t)
	b.apply(noSet, func(r *rec) {
		r.artifacts[deep] = []byte("x")
		r.refresh()
	})
	wantFindings(t, b.run(), nil)

	tooDeep := pathOfElements(files.MaxPathElements + 1)
	b2 := newBundle(t)
	r := b2.apply(noSet, func(r *rec) {
		r.record.Artifacts = []files.FileRef{{Path: tooDeep, SHA256: digestA}}
	})
	b2.put(tooDeep, []byte("x"))
	rep, log := b2.runSpied()
	has(t, rep, RecordInvalid, recordPath(r))
	for p := range log.reads {
		if !strings.HasSuffix(p, "record.json") {
			t.Errorf("the check read %s", p)
		}
	}
}

// A hostile record lists paths that are thousands of elements deep: each is refused at once, and
// no file is looked for.
func TestRecordThatListsVeryDeepPathsIsInvalidAtOnce(t *testing.T) {
	b := newBundle(t)
	r := b.apply(noSet, func(r *rec) {
		for i := 0; i < 60; i++ {
			p := strings.Repeat("d/", 1000) + string(rune('a'+i%26)) + strings.Repeat("x", i)
			r.record.Artifacts = append(r.record.Artifacts, files.FileRef{Path: p, SHA256: digestA})
		}
	})
	rep, log := b.runSpied()
	has(t, rep, RecordInvalid, recordPath(r))
	if len(log.reads) != 1 || log.reads["history/"+r.folder+"/record.json"] != 1 {
		t.Errorf("reads: %v; want only the record", log.reads)
	}
	if len(log.opens) > 3 {
		t.Errorf("%d folders were opened", len(log.opens))
	}
}
