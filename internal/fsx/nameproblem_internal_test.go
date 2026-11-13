package fsx

import "testing"

// nameProblem is called by checkPath and checkFiles, and neither calls it with an empty name:
// checkPath refuses an empty path and never splits one into an empty name (an empty element is
// refused by its own rule, and a leading separator is skipped), and checkFiles refuses an empty
// file name as "not one plain name" before it calls nameProblem. So no caller reaches this
// answer. The test calls it directly because the function once indexed the last byte of the
// name and would have panicked on an empty one; the guard is the only thing that stops that.
func TestNameProblemOfAnEmptyNameAnswersAndDoesNotPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("nameProblem(\"\") panicked: %v", r)
		}
	}()
	if got, want := nameProblem(""), "is not one plain name"; got != want {
		t.Fatalf("nameProblem(\"\") = %q, want %q", got, want)
	}
}
