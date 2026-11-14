package files_test

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/ceremony/files"
)

// Which members a record must have, and how deep a listed path may be. The depth is the constant,
// never its number.

func pathOfElements(n int, elem string) string {
	e := make([]string, n)
	for i := range e {
		e[i] = elem
	}
	return strings.Join(e, "/")
}

func TestCheckPathAllowsTheMostElementsAndRefusesOneMore(t *testing.T) {
	for _, elem := range []string{"a", strings.Repeat("a", 255)} {
		if err := files.CheckPath(pathOfElements(files.MaxPathElements, elem)); err != nil {
			t.Errorf("a path of %d elements of %d bytes: %v", files.MaxPathElements, len(elem), err)
		}
		err := files.CheckPath(pathOfElements(files.MaxPathElements+1, elem))
		if err == nil {
			t.Errorf("a path of %d elements of %d bytes is accepted", files.MaxPathElements+1, len(elem))
		} else if !printableASCII(err.Error()) || len(err.Error()) > 200 {
			t.Errorf("the error is not short and plain: %.100q", err)
		}
	}
}

func TestEveryListOfFilesRefusesAPathOfMoreThanTheMostElements(t *testing.T) {
	tooDeep := pathOfElements(files.MaxPathElements+1, "d")
	deepRef := map[string]any{"path": tooDeep, "sha256": dg('5')}
	t.Run("artifacts", func(t *testing.T) {
		_, err := files.ReadRecord(encode(t, applyDoc(), set("artifacts", []any{deepRef})))
		wantMember(t, err, "artifacts[0].path")
	})
	t.Run("wanted", func(t *testing.T) {
		_, err := files.ReadRecord(encode(t, applyDoc(), set("wanted", []any{deepRef})))
		wantMember(t, err, "wanted[0].path")
	})
	t.Run("plan wanted", func(t *testing.T) {
		_, err := files.ReadPlan(encode(t, planDoc(), set("wanted", []any{deepRef})))
		wantMember(t, err, "wanted[0].path")
	})
	t.Run("plan inputs", func(t *testing.T) {
		_, err := files.ReadPlan(encode(t, planDoc(), set("inputs", []any{deepRef})))
		wantMember(t, err, "inputs[0].path")
	})
	t.Run("the most elements is read", func(t *testing.T) {
		ok := map[string]any{"path": pathOfElements(files.MaxPathElements, "d"), "sha256": dg('5')}
		if _, err := files.ReadRecord(encode(t, applyDoc(), set("artifacts", []any{ok}))); err != nil {
			t.Error(err)
		}
	})
}

func wantMember(t *testing.T, err error, member string) {
	t.Helper()
	var fe *files.FormatError
	if !errors.As(err, &fe) || fe.Member != member {
		t.Errorf("err = %v, want a *FormatError for %s", err, member)
	}
}

// Required for apply: plan_sha256 and a wanted list that is not empty. Required for close:
// closes.ceremony and closes.attempt_sha256.
func TestMembersThatCheckHistoryReadsAreRequiredOfApplyAndClose(t *testing.T) {
	t.Run("plan_sha256 of apply", func(t *testing.T) {
		_, err := files.ReadRecord(encode(t, applyDoc(), without("plan_sha256")))
		wantMember(t, err, "plan_sha256")
	})
	t.Run("wanted of apply, empty", func(t *testing.T) {
		_, err := files.ReadRecord(encode(t, applyDoc(), set("wanted", []any{})))
		wantMember(t, err, "wanted")
	})
	t.Run("closes.ceremony of close", func(t *testing.T) {
		_, err := files.ReadRecord(encode(t, closeDoc(), delIn("closes", "ceremony")))
		wantMember(t, err, "closes.ceremony")
	})
	t.Run("closes.attempt_sha256 of close", func(t *testing.T) {
		_, err := files.ReadRecord(encode(t, closeDoc(), delIn("closes", "attempt_sha256")))
		wantMember(t, err, "closes.attempt_sha256")
	})
}

func delIn(outer, name string) func(map[string]any) {
	return func(m map[string]any) { delete(m[outer].(map[string]any), name) }
}

// The time inside confirmation and advisory_review is checked when it is there, and is not required.
func TestTimeInsideConfirmationAndAdvisoryReviewIsOptional(t *testing.T) {
	m := applyDoc()
	m["confirmation"] = map[string]any{"by": "typed"}
	m["advisory_review"] = map[string]any{"note": "read them"}
	r, err := files.ReadRecord(encode(t, m, nil))
	if err != nil {
		t.Fatal(err)
	}
	if r.Confirmation == nil || r.Confirmation.At != "" || r.AdvisoryReview == nil || r.AdvisoryReview.At != "" {
		t.Errorf("confirmation %+v, advisory_review %+v", r.Confirmation, r.AdvisoryReview)
	}
	// Written back, the member is not there, and the bytes read back to the same record.
	c, err := r.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(c), `"at"`) {
		t.Errorf("an empty time is written: %s", c)
	}
	back, err := files.ReadRecord(c)
	if err != nil || !reflect.DeepEqual(back, r) {
		t.Errorf("round trip: %v, %+v", err, back)
	}
	// There, it has its form.
	m2 := applyDoc()
	m2["confirmation"] = map[string]any{"by": "typed", "at": "2026-11-14T10:00:00.5Z"}
	_, err = files.ReadRecord(encode(t, m2, nil))
	wantMember(t, err, "confirmation.at")
}
