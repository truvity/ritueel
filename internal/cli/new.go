package cli

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	ucli "github.com/urfave/cli/v3"

	"ritueel.id/ritueel/internal/bundle"
	"ritueel.id/ritueel/internal/jsonset"
)

// The flags of new.
const (
	// flagTestRoot marks the roots of the new bundle as test roots.
	flagTestRoot = "test-root"
	// flagTemplate names the family of starter files.
	flagTemplate = "template"
)

// proposedTemplates are the names of templates that the page proposes and that are not built.
var proposedTemplates = []string{"two-cards", "cloud", "file"}

// newSpec is the word new: it makes the folder of a bundle and the starter wanted files, and touches no card
// and no key (record 0005, rule 20).
var newSpec = spec{
	name:      "new",
	usage:     "make a bundle folder with starter wanted files; no key is made and no card is touched",
	argsUsage: "[--template personal | --test-root] DIR",
	flags:     newFlags,
	run:       runNew,
}

func newFlags() []ucli.Flag {
	return []ucli.Flag{
		&ucli.StringFlag{Name: flagTemplate, Usage: "make the starter files of a `NAME`: personal is a bundle of a person, who adopts their own OpenPGP key; without it the starter is a company bundle"},
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
	// A flag that is given twice is a usage error and nothing is read: the library keeps the last value, so the
	// first would be dropped without a word (apply does the same).
	for _, name := range []string{flagTemplate, flagTestRoot} {
		if c.FlagCount(name) > 1 {
			return nil, UsageError{Msg: "--" + name + " is given once"}
		}
	}
	if len(c.Args) != 1 {
		return nil, UsageError{Msg: "new takes exactly one argument, the folder DIR of the new bundle"}
	}
	if c.FlagSet("dir") {
		return nil, UsageError{Msg: "the folder is the argument of new; do not also give --dir"}
	}
	opt := bundle.StarterOptions{TestRoot: c.FlagBool(flagTestRoot)}
	if c.FlagSet(flagTemplate) {
		switch name := c.FlagString(flagTemplate); {
		case name == bundle.TemplatePersonal:
			if opt.TestRoot {
				return nil, UsageError{Msg: "--test-root is for the roots of a company bundle; a personal bundle has none"}
			}
			opt.Template, opt.Now = name, c.Env.Now()
		case slices.Contains(proposedTemplates, name):
			return nil, UsageError{Msg: "the template " + name + " is proposed and not built; the template built is " + bundle.TemplatePersonal}
		default:
			return nil, UsageError{Msg: "the template is " + bundle.TemplatePersonal + "; no other template is built"}
		}
	}
	dir := c.Args[0]
	files, err := bundle.Create(dir, opt)
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
	if opt.Template == bundle.TemplatePersonal {
		b.WriteString("no key was made and no card was touched; edit person in ritueel.yaml, and write the fingerprint of your key and the day it expires in want/roots/openpgp.yaml, before apply: apply refuses the placeholder fingerprint\n")
	} else {
		b.WriteString("no key was made and no card was touched; edit name and release_address in ritueel.yaml before the first apply\n")
	}
	if c.FlagBool(flagTestRoot) {
		b.WriteString("this is a test bundle: its roots are marked TEST ONLY\n")
	}
	return &Result{ExitCode: ExitOK, Text: b.String()}, nil
}
