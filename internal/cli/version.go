package cli

import (
	"context"
	"fmt"
)

// runVersion prints the version and the commit of the build.
func runVersion(_ context.Context, c *Call) (*Result, error) {
	if len(c.Args) > 0 {
		return nil, UsageError{Msg: "version takes no arguments"}
	}
	b := c.Env.Build
	return &Result{
		Version: b.Version,
		Commit:  b.Commit,
		Text:    fmt.Sprintf("%s %s (commit %s)\n", programName, b.Version, b.Commit),
	}, nil
}
