package cli

import (
	"fmt"

	ucli "github.com/urfave/cli/v3"
)

// outputMode reads the raw value of --output. The second result is false for a value that is
// neither "text" nor "json": the mode is then not known and no JSON object is written. An
// empty value (the flag was never reached) is the default, text.
func outputMode(raw string) (OutputMode, bool) {
	switch OutputMode(raw) {
	case "", OutputText:
		return OutputText, true
	case OutputJSON:
		return OutputJSON, true
	default:
		return OutputText, false
	}
}

// globalFlags are declared on the root. A flag of the library is persistent unless it is
// marked Local, so every command inherits these and accepts them before or after its word.
func (inv *invocation) globalFlags() []ucli.Flag {
	return []ucli.Flag{
		&ucli.StringFlag{
			Name:        "dir",
			Usage:       "the bundle folder `DIR`",
			Destination: &inv.dir,
		},
		&ucli.StringFlag{
			Name:        "output",
			Usage:       "`MODE` is text (for people, the default) or json (one JSON object)",
			Value:       string(OutputText),
			Destination: &inv.output,
			Validator: func(v string) error {
				if _, ok := outputMode(v); !ok || v == "" {
					return fmt.Errorf("must be %q or %q", OutputText, OutputJSON)
				}
				return nil
			},
		},
	}
}
