package cli

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

var errWrite = errors.New("disk full")

// failingWriter fails every write and takes nothing.
type failingWriter struct{ err error }

func (w failingWriter) Write([]byte) (int, error) { return 0, w.err }

// partialWriter takes the first limit bytes, then fails.
type partialWriter struct {
	limit int
	err   error
	buf   bytes.Buffer
}

func (w *partialWriter) Write(p []byte) (int, error) {
	room := max(w.limit-w.buf.Len(), 0)
	if room >= len(p) {
		return w.buf.Write(p)
	}
	w.buf.Write(p[:room])
	return room, w.err
}

// If the result does not reach standard output the run did not succeed: exit code 1 and a
// message on standard error.
func TestFailedWriteOfTheResultEndsWithTheFailureCode(t *testing.T) {
	want := "ritueel: write the result: disk full\n"
	for _, args := range [][]string{{"version"}, {"--output", "json", "version"}} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			var stderr bytes.Buffer
			code := Run(t.Context(), args, Env{Stdout: failingWriter{err: errWrite}, Stderr: &stderr, Build: testBuild})
			if code != ExitFailure {
				t.Errorf("exit code = %d, want 1", int(code))
			}
			if stderr.String() != want {
				t.Errorf("stderr = %q, want %q", stderr.String(), want)
			}
		})
	}
}

// A writer that takes part of the result and then fails ends the same way.
func TestPartialWriteOfTheResultEndsWithTheFailureCode(t *testing.T) {
	want := "ritueel: write the result: disk full\n"
	for _, args := range [][]string{{"version"}, {"--output", "json", "version"}} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			stdout := &partialWriter{limit: 5, err: errWrite}
			var stderr bytes.Buffer
			code := Run(t.Context(), args, Env{Stdout: stdout, Stderr: &stderr, Build: testBuild})
			if code != ExitFailure {
				t.Errorf("exit code = %d, want 1", int(code))
			}
			if stderr.String() != want {
				t.Errorf("stderr = %q, want %q", stderr.String(), want)
			}
			if stdout.buf.Len() != 5 {
				t.Errorf("the writer took %d bytes, want 5", stdout.buf.Len())
			}
		})
	}
}

// A working standard output still gives exit code 0 and nothing on standard error; the
// failing writers above are not what makes the code 1.
func TestWorkingWriteOfTheResultEndsWithOK(t *testing.T) {
	for _, args := range [][]string{{"version"}, {"--output", "json", "version"}} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			if r := run(t, args...); r.code != ExitOK || r.stderr != "" {
				t.Errorf("(%d, %q), want (0, empty)", int(r.code), r.stderr)
			}
		})
	}
}
