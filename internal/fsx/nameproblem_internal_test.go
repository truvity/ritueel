package fsx

import "testing"

// nameProblem is called by parsePath for every element of a path, and by checkFiles for the name
// of every file of a set. parsePath never calls it with an empty name: it refuses an empty path
// itself, and an empty element ("a//b", a trailing separator) by its own rule, before it looks at
// the element. checkFiles does call it with an empty name: a NewFile with no Name reaches it, and
// its answer, "is not one plain name", is the text of that refusal. So the empty name is a real
// input, and the function must answer it and not index the last byte of it (it once did, and
// would have panicked).
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

// parsePath never hands nameProblem an empty element: each way to make one is refused first.
func TestParsePathNeverReachesNameProblemWithAnEmptyName(t *testing.T) {
	for _, p := range []string{"", "/", "a//b", "a/", "//a", "a//"} {
		if _, err := parsePath(p, false); err == nil {
			t.Errorf("parsePath(%q) accepted the path", p)
		}
	}
}

// checkFiles hands it the empty name of a file of a set, and the refusal says "is not one plain name".
func TestCheckFilesReachesNameProblemWithAnEmptyName(t *testing.T) {
	err := checkFiles([]NewFile{{Name: ""}})
	if err == nil {
		t.Fatal("checkFiles accepted an empty file name")
	}
	if got, want := err.Error(), `fsx: invalid argument: file name "" is not one plain name`; got != want {
		t.Fatalf("checkFiles: %q, want %q", got, want)
	}
}
