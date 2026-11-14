//go:build linux || darwin

package history

import (
	"context"
	"errors"
	"io/fs"
	"testing"

	"ritueel.id/ritueel/internal/fsx"
)

// cancelAfterFolder ends the context when the folder named folder has been listed.
type cancelAfterFolder struct {
	fsx.FS
	here, folder string
	cancel       context.CancelFunc
}

func (c cancelAfterFolder) OpenDir(name string) (fsx.FS, error) {
	d, err := c.FS.OpenDir(name)
	if err != nil {
		return nil, err
	}
	return cancelAfterFolder{d, name, c.folder, c.cancel}, nil
}

func (c cancelAfterFolder) ReadDir() ([]fs.DirEntry, error) {
	ents, err := c.FS.ReadDir()
	if c.here == c.folder {
		c.cancel()
	}
	return ents, err
}

// The walk of a trust set looks at its context before each folder it lists: a context that ends in the
// middle of a set stops the run with the error of the context and no report.
func TestContextEndedWhileATrustSetIsWalkedStopsTheRun(t *testing.T) {
	b, r := threeRecords(t)
	b.put("trust/"+r[0].set+"/keyring/._x", []byte("x"))
	root, err := fsx.OpenFS(b.dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rep, err := Check(ctx, cancelAfterFolder{FS: root, folder: r[0].set, cancel: cancel})
	if !errors.Is(err, context.Canceled) || rep != nil {
		t.Errorf("Check = %v, %v; want context.Canceled", rep, err)
	}
}

// The root of the bundle holds ritueel.yaml as a regular file or the folder is no bundle: a folder, a
// link or a FIFO with that name does not make a bundle of a folder that has no history/.
func TestManifestThatIsNotAFileDoesNotMakeABundle(t *testing.T) {
	for _, kind := range []string{"folder", "link", "FIFO"} {
		t.Run(kind, func(t *testing.T) {
			b := newBundle(t)
			b.remove("ritueel.yaml")
			b.remove("history")
			switch kind {
			case "folder":
				b.mkdir("ritueel.yaml")
			case "link":
				b.symlink("elsewhere", "ritueel.yaml")
			case "FIFO":
				b.fifo("ritueel.yaml")
			}
			rep, err := runDirErr(t, b.dir)
			if !errors.Is(err, ErrNotBundle) || rep != nil {
				t.Errorf("Check = %v, %v; want ErrNotBundle", rep, err)
			}
		})
	}
}
