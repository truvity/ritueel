//go:build linux || darwin

package fsx

// SetRenameNoReplaceCall puts call in the place of the one system call of the rename that refuses
// to replace, and returns the function that puts the original back. The tests that use it do not
// run in parallel with any test that reaches a rename (they do not call t.Parallel, and nothing
// in the package does), and they restore it with t.Cleanup.
func SetRenameNoReplaceCall(call func(dirfd int, oldName, newName string) error) (restore func()) {
	old := renameNoReplaceCall
	renameNoReplaceCall = call
	return func() { renameNoReplaceCall = old }
}

// RenameNoReplaceCall returns the call that is in place now.
func RenameNoReplaceCall() func(dirfd int, oldName, newName string) error {
	return renameNoReplaceCall
}
