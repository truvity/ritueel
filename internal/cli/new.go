package cli

import (
	"context"
	"errors"
	"fmt"
	"strings"

	ucli "github.com/urfave/cli/v3"

	"ritueel.id/ritueel/internal/bundle"
	"ritueel.id/ritueel/internal/jsonset"
)

// flagTestRoot is the name of the flag of new that marks the roots of the new bundle as test roots.
const flagTestRoot = "test-root"

// newSpec is the word new: it makes the folder of a bundle and the starter wanted files, and touches no card
// and no key (record 0005, rule 20).
var newSpec = spec{
	name:      "new",
	usage:     "make a bundle folder with starter wanted files; no key is made and no card is touched",
	argsUsage: "[--test-root] DIR",
	flags:     newFlags,
	run:       runNew,
}

func newFlags() []ucli.Flag {
	return []ucli.Flag{
		&ucli.BoolFlag{Name: flagTestRoot, Usage: "mark the roots of the new bundle as test roots (TEST ONLY) and let the policy allow the software store"},
	}
}

// runNew makes the folder DIR, which must not exist, and the starter wanted files in it (bundle.Create). DIR is
// the argument; the global --dir is not also given. It makes no key, reads no card and writes nowhere but
// into the new folder. A fault is exit code 1 and never a refusal: a bad DIR is a failure of the command and
// not a verdict of a check; so is a DIR that has a folder above it with a ritueel.yaml, because a bundle is not
// made inside a bundle (exit code 1, nothing written). After the first error nothing more is written, nothing is deleted, and the
// person is told which folder to remove.
func runNew(_ context.Context, c *Call) (*Result, error) {
	if len(c.Args) != 1 {
		return nil, UsageError{Msg: "new takes exactly one argument, the folder DIR of the new bundle"}
	}
	if c.FlagSet("dir") {
		return nil, UsageError{Msg: "the folder is the argument of new; do not also give --dir"}
	}
	dir := c.Args[0]
	files, err := bundle.Create(dir, bundle.StarterOptions{TestRoot: c.FlagBool(flagTestRoot)})
	if err != nil {
		var ce *bundle.CreateError
		if errors.As(err, &ce) && ce.Made {
			return nil, fmt.Errorf("%w; the folder %s is left as it is; remove it and run new again", err, jsonset.EscapeExact(dir))
		}
		return nil, err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "made the bundle %s\n", jsonset.EscapeExact(dir))
	for _, f := range files {
		fmt.Fprintf(&b, "%s  %s\n", f.SHA256, jsonset.EscapeExact(f.Path))
	}
	b.WriteString("no key was made and no card was touched; edit name and release_address in ritueel.yaml before the first apply\n")
	if c.FlagBool(flagTestRoot) {
		b.WriteString("this is a test bundle: its roots are marked TEST ONLY\n")
	}
	return &Result{ExitCode: ExitOK, Text: b.String()}, nil
}
