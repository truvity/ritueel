// Command ritueel is the command line of ritueel. It is the one place that exits and holds the
// process's own streams; everything else is in internal/cli.
package main

import (
	"context"
	"os"
	"time"

	"ritueel.id/ritueel/internal/buildinfo"
	"ritueel.id/ritueel/internal/cli"
)

func main() {
	env := cli.Env{
		Stdin:  os.Stdin,
		Stdout: os.Stdout,
		Stderr: os.Stderr,
		Build:  buildinfo.Read(),
		Now:    time.Now,
	}
	os.Exit(int(cli.Run(context.Background(), os.Args[1:], env)))
}
