package files

import (
	"fmt"
	"strings"

	"ritueel.id/ritueel/internal/fsx"
	"ritueel.id/ritueel/internal/strictjson"
)

// checker applies the rules of the page that strictjson cannot know, for one kind of file, and
// returns the first fault.
type checker struct{ what string }

func (c checker) missing(member string) error {
	return formatError(c.what, member, "is required and missing")
}

// name is a ceremony name: the name of a ceremony folder, which passes fsx.CheckName.
func (c checker) name(member, s string, required bool) error {
	if s == "" {
		if required {
			return c.missing(member)
		}
		return nil
	}
	if err := fsx.CheckName(s); err != nil {
		return formatError(c.what, member, "%s is not a plain name of a ceremony folder (record 0006, rule 38)", shown(s))
	}
	return nil
}

// digest is a SHA-256 digest in lower-case hexadecimal.
func (c checker) digest(member, s string, required bool) error {
	if s == "" {
		if required {
			return c.missing(member)
		}
		return nil
	}
	if !IsDigest(s) {
		return formatError(c.what, member, "%s is not a SHA-256 digest of 64 lower-case hexadecimal characters", shown(s))
	}
	return nil
}

// time is a time of the form YYYY-MM-DDThh:mm:ssZ.
func (c checker) time(member, s string, required bool) error {
	if s == "" {
		if required {
			return c.missing(member)
		}
		return nil
	}
	if err := CheckTime(s); err != nil {
		return formatError(c.what, member, "%s is %s", shown(s), err)
	}
	return nil
}

// oneOf is a value of a list of words the page gives.
func (c checker) oneOf(member, s string, words ...string) error {
	if s == "" {
		return c.missing(member)
	}
	for _, w := range words {
		if s == w {
			return nil
		}
	}
	return formatError(c.what, member, "%s is not one of the values the page gives", shown(s))
}

// refs checks a list of files with digests, "path" and "sha256" each.
func (c checker) refs(member string, list []FileRef) error {
	for i, f := range list {
		at := fmt.Sprintf("%s[%d]", member, i)
		if f.Path == "" {
			return c.missing(at + ".path")
		}
		if err := CheckPath(f.Path); err != nil {
			return formatError(c.what, at+".path", "the path %s", err)
		}
		if err := c.digest(at+".sha256", f.SHA256, true); err != nil {
			return err
		}
	}
	return nil
}

// readVersioned reads the version first and alone, then fills v under the rules of strictjson,
// then refuses an empty text for each of the optional members named in noEmpty (a path of member
// names, "a.b" for the member b of a). A Go string cannot tell a member that is absent from one
// that holds "", and the tags say omitempty, so without this check "prev_record_sha256": "" would
// read as no predecessor: a file that ritueel never writes and that a reader must not take for
// the first one.
func readVersioned(data []byte, what string, v any, noEmpty ...string) error {
	n, ok, err := strictjson.PeekInt(data, "version", strictjson.DefaultMaxBytes)
	if err != nil {
		return err
	}
	if !ok {
		return formatError(what, "version", "is required and missing")
	}
	if n != FormatVersion {
		return &VersionError{What: what, Version: n}
	}
	if err := strictjson.Unmarshal(data, v, strictjson.Options{MaxBytes: strictjson.DefaultMaxBytes}); err != nil {
		return err
	}
	root, err := strictjson.Parse(data, strictjson.DefaultMaxBytes)
	if err != nil {
		return err
	}
	for _, path := range noEmpty {
		if emptyText(root, strings.Split(path, ".")) {
			return formatError(what, path, "is an empty text: leave the member out, or give it a value")
		}
	}
	return nil
}

// emptyText reports whether the member at path (names from the top) is there and is the empty
// string.
func emptyText(v *strictjson.Value, path []string) bool {
	for _, name := range path {
		if v.Kind != strictjson.Object {
			return false
		}
		var next *strictjson.Value
		for i := range v.Members {
			if v.Members[i].Name == name {
				next = &v.Members[i].Value
				break
			}
		}
		if next == nil {
			return false
		}
		v = next
	}
	return v.Kind == strictjson.String && v.Str == ""
}
