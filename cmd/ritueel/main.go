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
	ignoreBrokenPipe()
	env := cli.Env{
		Stdin:           os.Stdin,
		Stdout:          os.Stdout,
		Stderr:          os.Stderr,
		Build:           buildinfo.Read(),
		Now:             time.Now,
		StdinIsTerminal: stdinIsTerminal(),
	}
	os.Exit(int(cli.Run(context.Background(), os.Args[1:], env)))
}

// stdinIsTerminal reports whether standard input is a character device, which is what a terminal is. A
// pipe, a file and a closed standard input are not. It asks the process once and holds no state.
func stdinIsTerminal() bool {
	info, err := os.Stdin.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}
