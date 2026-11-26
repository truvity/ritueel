// Package atoomsoftware links the software key driver of atoom into the process, for the keys of a test
// root (record 0012, rules 1 and 2). The driver keeps one file for each purpose in a folder of its own,
// and ritueel names that folder: [keydir.TestOnlyFolder] inside the key directory. The folder's name is what
// marks the keys as test-only.
//
// The link is the in-process one of atoom: the client dials an in-memory pipe and the driver's handler
// answers on the other end. No program is started, no socket is made and no port is opened, so it works on
// a machine with no network at all. The package imports no net/http itself; the types of that package
// stay inside the libraries of atoom.
//
// The driver writes its log lines through the logger that it is given. This package gives it one that
// discards them, so that the process-wide logger is not touched and a ceremony prints only its own
// lines.
//
// The package makes nothing before [Open] is called, and [Open] is called late: after the person
// confirmed the plan, and before the attempt is written.
package atoomsoftware

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sync"

	"github.com/truvity/atoom/common/call"
	"github.com/truvity/atoom/key/gen/atoom/key/v1alpha1/keyv1alpha1connect"
	"github.com/truvity/atoom/key/purpose"
	"github.com/truvity/atoom/key/software"
	"github.com/truvity/atoom/socket"

	"ritueel.id/ritueel/internal/keydir"
)

// The refusals of [Open].
var (
	// ErrFolderExists marks an entry test-only-keys that stands in the key directory already and is not an empty folder: the keys of
	// an earlier use are never adopted.
	ErrFolderExists = errors.New("atoomsoftware: the folder of the test keys exists already")
	// ErrStateRefused marks a state folder that the driver refuses: its mode, its owner, or an entry in
	// it that does not belong. The text holds no path, which the driver's own text does.
	ErrStateRefused = errors.New("atoomsoftware: the key driver refuses its state folder (its mode, its owner or an entry in it that does not belong)")
)

// stateMode is the mode of the state folder: the driver requires exactly this one.
const stateMode = 0o700

// Link is a running driver and the client that reaches it. It is safe for concurrent use.
type Link struct {
	client keyv1alpha1connect.KeyStoreServiceClient
	stop   func()
	once   sync.Once
}

// Open makes the folder [keydir.TestOnlyFolder] in dir with the mode 0700, and starts the software
// driver on it, with one purpose for each name: an ES384 key that allows sign. dir is the resolved key
// directory that [keydir.Dir.Path] gives. A folder that stands already and is empty is used as it is,
// without a change of its mode; any other entry of that name is an [ErrFolderExists], and nothing is
// changed in it. A folder that the driver refuses is an [ErrStateRefused]. Nothing is deleted.
// The caller closes the Link.
func Open(dir string, purposes []string) (*Link, error) {
	decls := make([]purpose.Declaration, len(purposes))
	for i, name := range purposes {
		decls[i] = purpose.Declaration{Name: name, Algorithm: purpose.ES384, Operations: []purpose.Operation{purpose.Sign}}
	}
	state := filepath.Join(dir, keydir.TestOnlyFolder)
	if err := os.Mkdir(state, stateMode); err != nil {
		if !errors.Is(err, fs.ErrExist) {
			return nil, fmt.Errorf("atoomsoftware: the folder %s cannot be made in the key directory: %s", keydir.TestOnlyFolder, reason(err))
		}
		// A folder that an earlier run left is used as it is when it is a real folder and empty (a key in it
		// is never adopted). Its mode and owner are the driver's to judge: it refuses what it does not accept.
		if !emptyFolder(state) {
			return nil, ErrFolderExists
		}
	} else if err := os.Chmod(state, stateMode); err != nil { // the umask may have narrowed it
		return nil, fmt.Errorf("atoomsoftware: the folder %s cannot be set to the mode 0700: %s", keydir.TestOnlyFolder, reason(err))
	}
	svc, err := software.New(software.Options{
		StateDir: state,
		Purposes: decls,
		Logger:   slog.New(slog.DiscardHandler),
	})
	if err != nil {
		var problems *software.Problems
		if errors.As(err, &problems) {
			return nil, ErrStateRefused
		}
		return nil, &startError{cause: err}
	}
	path, h := svc.Handler()
	hc, stop := socket.InProcess(path, h)
	return &Link{
		client: keyv1alpha1connect.NewKeyStoreServiceClient(hc, "http://key", call.ClientOptions()...),
		stop:   stop,
	}, nil
}

// Client is the generated client of the key port, linked to the driver.
func (l *Link) Client() keyv1alpha1connect.KeyStoreServiceClient { return l.client }

// Close stops the in-process link: a call after it fails. A second Close does nothing. The state folder and
// the keys in it stay.
func (l *Link) Close() error {
	if l == nil {
		return nil
	}
	l.once.Do(func() {
		if l.stop != nil {
			l.stop()
		}
	})
	return nil
}

// startError is a start of the driver that failed for a reason that is not a refused state folder. The driver
// puts paths into the text of such errors ("create ...", "chmod ..."), so this error says fixed words and
// keeps the original only for errors.Is: it has no Unwrap, so the text cannot be reached through it.
type startError struct{ cause error }

func (*startError) Error() string {
	return "atoomsoftware: the key driver cannot start, for a reason whose text is not shown because it can hold a path"
}

// Is reports whether the original error is, or wraps, target.
func (e *startError) Is(target error) bool { return errors.Is(e.cause, target) }

// emptyFolder reports whether path is a real folder (not a link) that holds nothing.
func emptyFolder(path string) bool {
	fi, err := os.Lstat(path)
	if err != nil || !fi.IsDir() {
		return false
	}
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	names, err := f.Readdirnames(1)
	return len(names) == 0 && errors.Is(err, io.EOF)
}

// reason is the text of the operating system's error without the path that the error holds.
func reason(err error) string {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Err.Error()
	}
	return "the operating system refused"
}
