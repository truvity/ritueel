package openpgp

import "testing"

// A primary that holds no key has no mark, whatever its mark field says: the answer of TestMark is
// about a primary that a keyring file gave, and only such a primary holds a key.
func TestTestMarkOfAPrimaryWithNoKeyIsFalseWhateverTheFieldSays(t *testing.T) {
	if (&PrimaryKey{test: true}).TestMark() {
		t.Error("a primary with no key says it is a test primary")
	}
	var nilKey *PrimaryKey
	if nilKey.TestMark() {
		t.Error("a nil primary says it is a test primary")
	}
}
