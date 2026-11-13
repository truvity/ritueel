package cli

import (
	"context"
	"fmt"
	"io"
	"slices"
	"strings"

	ucli "github.com/urfave/cli/v3"

	"ritueel.id/ritueel/internal/jsonset"
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
	// Args are the arguments after the command word (after the second word, for a word with
	// second words) that are not flags.
	Args []string

	cmd   *ucli.Command // the library's command of the word that runs, for the flag accessors
	word  string        // the words that ran, for the text of a programmer error
	flags []string      // the flag names the word may read: its own, those of the words above it, and the global ones
}

// The accessors below are for the flags that the word that runs declares, those of the words
// above it, and the two global flags (dir and output). A name that none of them declares, and a
// Call that holds no command (one that was not made by Run), are a mistake of the programmer, so
// they panic with a text that says which; Run then ends with the exit code 1 and the text. A
// silent "" or false for a misspelt name would read as "no pin" or "not given".

// FlagString returns the value of the string flag name of the word that runs, or of a global
// flag. It is "" when the flag was not given and has no default.
func (c *Call) FlagString(name string) string { return c.declared(name).String(name) }

// FlagStrings returns the values of the repeatable string flag name in the order they were
// given on the command line; a comma is part of a value, not a separator. It is empty when the
// flag was not given.
func (c *Call) FlagStrings(name string) []string { return c.declared(name).StringSlice(name) }

// FlagBool returns the value of the boolean flag name; false when it was not given.
func (c *Call) FlagBool(name string) bool { return c.declared(name).Bool(name) }

// FlagSet reports whether the flag name was given on the command line.
func (c *Call) FlagSet(name string) bool { return c.declared(name).IsSet(name) }

// declared returns the library's command for the accessors, after it has checked the name.
func (c *Call) declared(name string) *ucli.Command {
	if c.cmd == nil {
		panic(fmt.Sprintf("cli: the flag %q was asked of a Call that holds no command; only the Call that Run gives to a command has flags", name))
	}
	if !slices.Contains(c.flags, name) {
		panic(fmt.Sprintf("cli: the word %q has no flag %q; the flags that can be asked are %q", c.word, name, c.flags))
	}
	return c.cmd
}

// commandFunc is the body of one command. It returns the Result of a command that ended as
// it should, or an error; ExitFor maps the error to an exit code. It never returns both nil: a
// command that has nothing to say still returns a Result (help is shown by the library, before the
// command runs). It writes nothing to
// standard output itself in JSON mode: the object is written once, by Run.
type commandFunc func(ctx context.Context, c *Call) (*Result, error)

// spec is one command word.
type spec struct {
	name      string
	usage     string
	argsUsage string // the usage line after the word, for help
	// flags makes the flags of this word only. It is a function because a flag of the library
	// keeps what it was given ("was set", its count) in the flag value itself, so every run
	// needs flag values of its own, not the ones a run before it has used.
	flags func() []ucli.Flag
	subs  []spec      // second words ("verify root-list"); a word with subs has no run
	run   commandFunc // a word without subs has one
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
	command string // the first word of the command being run, "" when none was named
	result  *Result
}

// Run runs ritueel with the arguments that follow the program name and returns the exit
// code. It writes only to env's streams and never exits. With --output json it writes
// exactly one JSON object to env.Stdout when the command ends; text for people goes to
// env.Stderr. The one exception is that no object is written when the arguments are so
// broken that the output mode is not known.
//
// What a command may rely on. Every error text that reaches a person or a script goes through
// jsonset.Escape in finish, the one place where it is written: the line on standard error and the
// "error" member of the JSON object hold printable ASCII only, a character outside it shown as
// \uXXXX. So a command may put a file name, a member name or a piece of a document into an error
// or a panic without escaping it, and may not rely on a line break inside the message (it is
// shown as \u000a); the newline that finish writes after the message stays. What a command puts
// in Result.Text is written as it is on standard output, and is the command's own to escape when
// it holds text from a document.
func Run(ctx context.Context, args []string, env Env) ExitCode {
	inv := &invocation{env: env.withDefaults()}
	return inv.finish(inv.execute(ctx, args))
}

// execute runs the command line library. A panic in a command or in the library ends the run
// like any other failure: it comes back as an error, so finish writes it through the same
// path and the exit code is ExitFailure, not the code of a usage error. The stack trace is
// not printed.
func (inv *invocation) execute(ctx context.Context, args []string) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("internal error: %v", r)
		}
	}()
	return inv.newRoot().Run(ctx, append([]string{programName}, args...))
}

func (inv *invocation) newRoot() *ucli.Command {
	cmds := make([]*ucli.Command, 0, len(specs))
	for _, s := range specs {
		cmds = append(cmds, inv.newCommand(s, nil, nil))
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
			return UsageError{Msg: fmt.Sprintf("unknown command %+q", cmd.Args().First())}
		},
	}
}

// reservedFlags are the flag names that no word may declare: the two global flags, which a word
// would shadow (Call.Global would then stay empty and --output json would be ignored), and the
// help flags of the library.
var reservedFlags = []string{"dir", "output", "help", "h"}

// newCommand builds the library's command for one word and, recursively, for its second
// words. parents are the words above it; the first of them, or its own name, is the word that
// the JSON object calls "command" (a second word does not change it). inherited are the flag
// names of the words above it. A flag name that is reserved, or that the word or a word above it
// declares already, is a mistake in the table of words, and newCommand panics with a text that
// says which; the first run of the program shows it, and a test that builds the table finds it.
func (inv *invocation) newCommand(s spec, parents, inherited []string) *ucli.Command {
	first := s.name
	if len(parents) > 0 {
		first = parents[0]
	}
	path := append(slices.Clone(parents), s.name)
	cmd := &ucli.Command{
		Name:      s.name,
		Usage:     s.usage,
		ArgsUsage: s.argsUsage,
		// A repeated flag is one value for each use; a comma is part of a value.
		DisableSliceFlagSeparator: true,
		HideHelpCommand:           true, // --help is a flag; "help" is not a command word
		OnUsageError: func(_ context.Context, _ *ucli.Command, err error, _ bool) error {
			inv.command = first
			return UsageError{Msg: err.Error()}
		},
	}
	askable := slices.Clone(inherited)
	if s.flags != nil {
		cmd.Flags = s.flags()
		for _, f := range cmd.Flags {
			for _, name := range f.Names() {
				switch {
				case slices.Contains(reservedFlags, name):
					panic(fmt.Sprintf("cli: the word %q declares the flag %q, which is reserved for the program (dir, output) and for help (help, h); choose another name", strings.Join(path, " "), name))
				case slices.Contains(askable, name):
					panic(fmt.Sprintf("cli: the word %q declares the flag %q twice, or a word above it declares it already; choose another name", strings.Join(path, " "), name))
				}
				askable = append(askable, name)
			}
		}
	}
	if len(s.subs) > 0 {
		for _, sub := range s.subs {
			cmd.Commands = append(cmd.Commands, inv.newCommand(sub, path, askable))
		}
		cmd.Action = func(_ context.Context, c *ucli.Command) error {
			inv.command = first
			if c.NArg() == 0 {
				return UsageError{Msg: fmt.Sprintf("%s needs a second word", strings.Join(path, " "))}
			}
			return UsageError{Msg: fmt.Sprintf("%s: unknown command %+q", strings.Join(path, " "), c.Args().First())}
		}
		return cmd
	}
	cmd.Action = func(ctx context.Context, c *ucli.Command) error {
		inv.command = first
		res, err := s.run(ctx, &Call{
			Env:    inv.env,
			Global: Global{Dir: inv.dir, Output: OutputMode(inv.output)},
			Args:   c.Args().Slice(),
			cmd:    c,
			word:   strings.Join(path, " "),
			flags:  append(slices.Clone(askable), "dir", "output"),
		})
		if err != nil {
			// The panic of a code and an outcome that disagree must happen here, inside the run
			// that turns a panic into exit code 1, and not in finish.
			_, _ = ExitFor(err)
			return err
		}
		if res == nil {
			// Help is shown by the library before the action runs, so no command returns nothing
			// on purpose; a command that does has forgotten its result.
			panic(fmt.Sprintf("cli: the command %q returned neither a result nor an error", strings.Join(path, " ")))
		}
		res.Outcome = agreed(res.ExitCode, res.Outcome)
		inv.result = res
		return nil
	}
	return cmd
}

// onUsageError turns a bad flag, a flag without its value or a bad flag value of the root into
// a usage error. The library prints nothing for it; finish does. The commands have their own,
// which also names the command.
func (inv *invocation) onUsageError(_ context.Context, _ *ucli.Command, err error, _ bool) error {
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
		var werr error
		if mode == OutputJSON {
			werr = writeJSON(inv.env.Stdout, res)
		} else if res.Text != "" {
			_, werr = io.WriteString(inv.env.Stdout, res.Text)
		}
		if werr != nil {
			// The result did not reach the caller, so the run did not succeed.
			_, _ = fmt.Fprintf(inv.env.Stderr, "%s: write the result: %s\n", programName, jsonset.Escape(werr.Error()))
			return ExitFailure
		}
		return res.ExitCode
	}

	code, outcome := ExitFor(err)
	// The one place where the text of an error is written: standard error and the "error" member.
	msg := jsonset.Escape(err.Error())
	_, _ = fmt.Fprintf(inv.env.Stderr, "%s: %s\n", programName, msg)
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
			Error:    msg,
		})
	}
	return code
}
