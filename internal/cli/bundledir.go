package cli

import (
	"fmt"

	"ritueel.id/ritueel/internal/fsx"
)

// manifestName is the file that marks a folder as a bundle that a person can work in: the policy of
// the bundle (docs/reference/bundle.md). It is the one place of the name.
const manifestName = "ritueel.yaml"

// bundleDir returns the folder a command that reads a bundle works on. It is the folder of --dir
// when that flag was given (an empty value counts as not given). With no --dir it is the current
// folder, "." , when that folder holds ritueel.yaml as a regular file: an entry of exactly that
// name whose type is a regular file, so that a folder, a symbolic link or a FIFO of that name does
// not count (docs/reference/cli.md, the flag --dir). Otherwise it is a usage error that names
// --dir: a command started in the wrong folder must not read it as a bundle.
//
// With --dir the manifest is not required, because the copy of a bundle on a stick has none
// (record 0005, rule 30). The folder of --dir is not opened here; the command opens it with
// fsx.OpenFS. The current folder is listed through fsx, which follows no link and bounds the list
// at fsx.MaxDirEntries names: a folder with more names is an error (exit code 1), not a usage
// error.
func bundleDir(c *Call) (string, error) {
	if c.Global.Dir != "" {
		return c.Global.Dir, nil
	}
	here, err := fsx.OpenFS(".")
	if err != nil {
		return "", fmt.Errorf("cannot look at the current folder: %w", err)
	}
	defer func() {
		// The folder was opened to read it only; nothing was written, so a failed close loses nothing.
		_ = here.Close()
	}()
	ents, err := fsx.ReadDir(here, ".")
	if err != nil {
		return "", fmt.Errorf("cannot look at the current folder: %w", err)
	}
	for _, e := range ents {
		if e.Name() == manifestName && e.Type().IsRegular() {
			return ".", nil
		}
	}
	return "", UsageError{Msg: "no --dir was given and the current folder has no " + manifestName + ": give the bundle folder with --dir DIR"}
}
