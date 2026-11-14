package wanted

import (
	"errors"
	"strings"
)

// ValidName reports whether name is the form of the name of an object (a root, a delegation): the file name
// without ".yaml", lower-case letters, digits and hyphens, 1 to 63 characters, starting with a letter or a digit
// (the pattern ^[a-z0-9][a-z0-9-]{0,62}$ of docs/reference/bundle.md). It returns nil or an error whose text is
// fixed words, so it is safe to print. A name that has a period (a ".yaml" or ".yml" ending), an upper-case
// letter, a path separator or any other character is an error, and so is the prefix ".rt-" of a leftover.
func ValidName(name string) error {
	if name == "" || len(name) > 63 {
		return errors.New("a name has 1 to 63 characters")
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c == '-' && i > 0:
		default:
			return errors.New("a name has lower-case letters, digits and hyphens only, and starts with a letter or a digit; give it without .yaml")
		}
	}
	return nil
}

// breakGlassPrefix starts the names that the SSH CA key list uses for its break-glass keys.
const breakGlassPrefix = "break-glass-"

// delegationNameProblem is the fault of a name that cannot be a delegation, or "" when there is none.
func delegationNameProblem(name string) string {
	if err := ValidName(name); err != nil {
		return err.Error()
	}
	if strings.HasPrefix(name, breakGlassPrefix) {
		return "a delegation name does not begin with " + breakGlassPrefix + ": the SSH CA key list uses those names"
	}
	return ""
}
