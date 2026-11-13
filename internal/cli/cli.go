package cli

import (
	"context"
	"fmt"
	"io"

	ucli "github.com/urfave/cli/v3"
)

const programName = "ritueel"

// Global holds the flags every command accepts, before or after the command word.
type Global struct {
	// Dir is the bundle folder; empty when --dir was not given.
	Dir string
	// Output is the output mode, OutputText or OutputJSON.
	Output OutputMode
}

// Call is what a command gets.
type Call struct {
	Env    Env
	Global Global
	// Args are the arguments after the command word that are not flags.
	Args []string
}

// commandFunc is the body of one command. It returns the Result of a command that ended as
// it should, or an error; ExitFor maps the error to an exit code. It writes nothing to
// standard output itself in JSON mode: the object is written once, by Run.
type commandFunc func(ctx context.Context, c *Call) (*Result, error)

// spec is one command word.
type spec struct {
	name  string
	usage string
	run   commandFunc
}

// specs are the command words that exist. Usage lists only these.
var specs = []spec{
	{name: "version", usage: "print the version and the commit", run: runVersion},
}

// invocation is the state of one run, so that two runs share nothing.
type invocation struct {
	env     Env
	dir     string
	output  string // the raw value of --output
	command string // the word of the command being run, "" when none was named
	result  *Result
}

// Run runs ritueel with the arguments that follow the program name and returns the exit
// code. It writes only to env's streams and never exits. With --output json it writes
// exactly one JSON object to env.Stdout when the command ends; text for people goes to
// env.Stderr. The one exception is that no object is written when the arguments are so
// broken that the output mode is not known.
func Run(ctx context.Context, args []string, env Env) ExitCode {
	inv := &invocation{env: env.withDefaults()}
	err := inv.newRoot().Run(ctx, append([]string{programName}, args...))
	return inv.finish(err)
}

func (inv *invocation) newRoot() *ucli.Command {
	cmds := make([]*ucli.Command, 0, len(specs))
	for _, s := range specs {
		cmds = append(cmds, inv.newCommand(s))
	}
	return &ucli.Command{
		Name:            programName,
		Usage:           "make, check and use the roots of trust of a bundle",
		UsageText:       programName + " [--dir DIR] [--output text|json] COMMAND [ARGUMENTS]",
		Reader:          inv.env.Stdin,
		Writer:          inv.env.Stdout,
		ErrWriter:       inv.env.Stderr,
		HideHelpCommand: true, // --help is a flag; "help" is not a command word
		Flags:           inv.globalFlags(),
		Commands:        cmds,
		// The library must never exit by itself: Run maps the error to the code.
		ExitErrHandler: func(context.Context, *ucli.Command, error) {},
		OnUsageError:   inv.onUsageError,
		// The root's own action runs when no command word matched.
		Action: func(_ context.Context, cmd *ucli.Command) error {
			if cmd.NArg() == 0 {
				return UsageError{Msg: "no command given"}
			}
			return UsageError{Msg: fmt.Sprintf("unknown command %q", cmd.Args().First())}
		},
	}
}

// newCommand builds the library's command for one word.
func (inv *invocation) newCommand(s spec) *ucli.Command {
	return &ucli.Command{
		Name:         s.name,
		Usage:        s.usage,
		OnUsageError: inv.onUsageError,
		Action: func(ctx context.Context, cmd *ucli.Command) error {
			inv.command = s.name
			res, err := s.run(ctx, &Call{
				Env:    inv.env,
				Global: Global{Dir: inv.dir, Output: OutputMode(inv.output)},
				Args:   cmd.Args().Slice(),
			})
			if err != nil {
				return err
			}
			inv.result = res
			return nil
		},
	}
}

// onUsageError turns a bad flag, a flag without its value or a bad flag value into a usage
// error. The library prints nothing for it; finish does.
func (inv *invocation) onUsageError(_ context.Context, cmd *ucli.Command, err error, isSubcommand bool) error {
	if isSubcommand {
		inv.command = cmd.Name
	}
	return UsageError{Msg: err.Error()}
}

// finish writes what the end of the run needs and returns the exit code.
func (inv *invocation) finish(err error) ExitCode {
	mode, known := outputMode(inv.output)

	if err == nil {
		if inv.result == nil {
			return ExitOK // help was shown; it is not a command
		}
		res := inv.result
		res.Output = FormatVersion
		res.Command = inv.command
		if res.Outcome == "" {
			res.Outcome = OutcomeDone
		}
		if mode == OutputJSON {
			_ = writeJSON(inv.env.Stdout, res)
		} else if res.Text != "" {
			_, _ = io.WriteString(inv.env.Stdout, res.Text)
		}
		return res.ExitCode
	}

	code, outcome := ExitFor(err)
	_, _ = fmt.Fprintf(inv.env.Stderr, "%s: %s\n", programName, err)
	if outcome == OutcomeUsage {
		_, _ = fmt.Fprintf(inv.env.Stderr, "Run \"%s --help\" for the usage.\n", programName)
	}
	if known && mode == OutputJSON {
		_ = writeJSON(inv.env.Stdout, &Result{
			Output:   FormatVersion,
			Command:  inv.command,
			ExitCode: code,
			Outcome:  outcome,
			Reasons:  reasonsOf(err),
			Error:    err.Error(),
		})
	}
	return code
}
