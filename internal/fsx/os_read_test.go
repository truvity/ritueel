//go:build linux || darwin

package fsx_test

// The three readers on the real file system: a regular file, a link, a FIFO (which must not
// block), a device, a socket, a folder, a missing name, a file of exactly MaxReadSize and one a
// byte more, a file that grows while it is read, and a name that is swapped between the looks the
// reader takes at it.

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"ritueel.id/ritueel/internal/fsx"
)

// within runs f and fails the test when it does not return in time. A read that waits on a FIFO
// would otherwise hang the run.
func within[T any](t *testing.T, d time.Duration, what string, f func() T) T {
	t.Helper()
	done := make(chan T, 1)
	go func() { done <- f() }()
	select {
	case v := <-done:
		return v
	case <-time.After(d):
		t.Fatalf("%s did not return within %v: it is waiting on a FIFO or a device", what, d)
		panic("unreachable")
	}
}

type readResult struct {
	data []byte
	err  error
}

func readFileWithin(t *testing.T, root fsx.FS, p string) readResult {
	t.Helper()
	return within(t, 10*time.Second, "ReadFile "+p, func() readResult {
		b, err := fsx.ReadFile(root, p)
		return readResult{b, err}
	})
}

func TestOSReadFileOfEachKindOfName(t *testing.T) {
	wd := newWorld(t)
	wd.mkdir("d/sub")
	write := func(name string, n int) {
		t.Helper()
		f, err := os.Create(filepath.Join(wd.root, "d", name))
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = f.Close() }()
		if err := f.Truncate(int64(n)); err != nil { // holes: no 8 MiB written to the disk
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(wd.root, "d", "regular"), []byte("data\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	write("empty", 0)
	write("exact", fsx.MaxReadSize)
	write("over", fsx.MaxReadSize+1)
	write("huge", 1<<40) // a terabyte of holes: no memory is asked for
	wd.mkfifo("d/pipe")
	wd.symlink("regular", "d/link")
	wd.symlink("nothing", "d/dangling")
	root := openFSIn(t, wd.root)

	for _, c := range []struct {
		name string
		is   error
		not  []error
		want int
	}{
		{"regular", nil, nil, 5},
		{"empty", nil, nil, 0},
		{"exact", nil, nil, fsx.MaxReadSize},
		{"over", fsx.ErrTooLarge, []error{fsx.ErrNotRegular, fsx.ErrLink}, 0},
		{"huge", fsx.ErrTooLarge, nil, 0},
		{"pipe", fsx.ErrNotRegular, []error{fsx.ErrLink, fsx.ErrTooLarge}, 0},
		{"sub", fsx.ErrNotRegular, []error{fsx.ErrLink}, 0},
		{"link", fsx.ErrLink, []error{fsx.ErrNotRegular, fs.ErrNotExist}, 0},
		{"dangling", fsx.ErrLink, []error{fs.ErrNotExist}, 0},
		{"none", fs.ErrNotExist, []error{fsx.ErrLink, fsx.ErrNotRegular}, 0},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := readFileWithin(t, root, "d/"+c.name)
			if c.is == nil {
				if r.err != nil || len(r.data) != c.want {
					t.Fatalf("%d bytes, %v, want %d bytes", len(r.data), r.err, c.want)
				}
				return
			}
			if !errors.Is(r.err, c.is) {
				t.Fatalf("%v, want %v", r.err, c.is)
			}
			for _, n := range c.not {
				if errors.Is(r.err, n) {
					t.Fatalf("%v must not be %v", r.err, n)
				}
			}
			if r.data != nil {
				t.Fatalf("%d bytes came back with the error: never a cut-off read", len(r.data))
			}
			fe := asError(t, r.err)
			if fe.Step != fsx.StepRead || fe.Path != "d/"+c.name {
				t.Fatalf("%v, want a read error at d/%s", r.err, c.name)
			}
			if c.name == "over" && !strings.Contains(r.err.Error(), "8388609 bytes, more than 8388608") {
				t.Fatalf("%v: a file that is already too long at the look says how long it is", r.err)
			}
			requirePrintableASCII(t, r.err.Error()) // the text of the system's own error holds nothing raw
		})
	}

	// the same through ReadJournal
	for _, name := range []string{"exact", "over", "pipe", "link", "sub", "none"} {
		type jr struct {
			lines [][]byte
			part  []byte
			err   error
		}
		r := within(t, 10*time.Second, "ReadJournal "+name, func() jr {
			l, p, err := fsx.ReadJournal(root, "d/"+name)
			return jr{l, p, err}
		})
		switch name {
		case "exact":
			if r.err != nil || len(r.lines) != 0 || len(r.part) != fsx.MaxReadSize {
				t.Errorf("ReadJournal of exactly MaxReadSize: %d lines, %d partial, %v", len(r.lines), len(r.part), r.err)
			}
		default:
			if r.err == nil || r.lines != nil || r.part != nil {
				t.Errorf("ReadJournal %s: %v with %d lines: want an error and no data", name, r.err, len(r.lines))
			}
		}
	}
}

// TestOSReadFileOfADeviceAndASocketIsRefusedWithoutOpeningThem: /dev/null, /dev/zero (which would
// never end), and a socket.
func TestOSReadFileOfADeviceAndASocketIsRefusedWithoutOpeningThem(t *testing.T) {
	dev := openFSIn(t, "/dev")
	for _, name := range []string{"null", "zero"} {
		if _, err := os.Stat("/dev/" + name); err != nil {
			t.Skipf("no /dev/%s here: %v", name, err)
		}
		r := readFileWithin(t, dev, name)
		if !errors.Is(r.err, fsx.ErrNotRegular) || r.data != nil {
			t.Errorf("ReadFile of /dev/%s: %d bytes, %v, want ErrNotRegular", name, len(r.data), r.err)
		}
	}
	dir := t.TempDir()
	t.Chdir(dir) // a short path for the socket
	l, err := net.Listen("unix", "sock")
	if err != nil {
		t.Skipf("no unix socket here: %v", err)
	}
	defer func() { _ = l.Close() }()
	root := openFSIn(t, dir)
	r := readFileWithin(t, root, "sock")
	if !errors.Is(r.err, fsx.ErrNotRegular) || r.data != nil {
		t.Errorf("ReadFile of a socket: %d bytes, %v, want ErrNotRegular", len(r.data), r.err)
	}
	ents, err := fsx.ReadDir(root, ".")
	if err != nil || len(ents) != 1 || ents[0].Type() != fs.ModeSocket {
		t.Errorf("ReadDir lists the socket as %v (%v)", ents, err)
	}
}

// TestOSReadFileOfAFifoWithAWriterIsStillRefused: a FIFO that has a writer waiting is not read
// either (the open would succeed at once, and the read would then take what the writer gives).
func TestOSReadFileOfAFifoWithAWriterIsStillRefused(t *testing.T) {
	wd := newWorld(t)
	wd.mkfifo("pipe")
	p := filepath.Join(wd.root, "pipe")
	// a reader end that is open, so that a writer can open without waiting, then a writer that holds it
	rd, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rd.Close() }()
	wr, err := os.OpenFile(p, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = wr.Close() }()
	if _, err := wr.WriteString("data from a pipe\n"); err != nil {
		t.Fatal(err)
	}
	root := openFSIn(t, wd.root)
	r := readFileWithin(t, root, "pipe")
	if !errors.Is(r.err, fsx.ErrNotRegular) || r.data != nil {
		t.Fatalf("ReadFile of a FIFO with data in it: %q, %v, want ErrNotRegular and no data", r.data, r.err)
	}
}

// TestOSReadFileOfAFileThatGrowsWhileItIsRead: a file of exactly MaxReadSize passes the look at
// its size, and a writer that appends to it while the reader reads it must not make the reader
// return more than the limit, nor the first MaxReadSize bytes of a file that has grown: the answer
// is the whole file or ErrTooLarge, never a longer one, never a cut-off one.
//
// A read of 8 MiB takes some milliseconds, and the writer starts a few hundred microseconds into
// it (the delays differ from round to round), so the first appended bytes are in the file well
// before the reader reaches the end. The writer notes when its first write was done; a read that
// returns without an error although that was more than 0.8 ms before it returned is a read that
// did not look beyond the limit (the reader's last look is within microseconds of its return).
func TestOSReadFileOfAFileThatGrowsWhileItIsRead(t *testing.T) {
	wd := newWorld(t)
	p := filepath.Join(wd.root, "grow")
	root := openFSIn(t, wd.root)
	delays := []time.Duration{0, 30 * time.Microsecond, 100 * time.Microsecond, 300 * time.Microsecond}
	const margin = 800 * time.Microsecond
	sawTooLarge, sawWhole, rounds := 0, 0, 40
	for round := 0; round < rounds; round++ {
		if err := os.WriteFile(p, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Truncate(p, fsx.MaxReadSize); err != nil {
			t.Fatal(err)
		}
		delay := delays[round%len(delays)]
		start := time.Now()
		var firstDone atomic.Int64 // nanoseconds since start; 0: no write done yet
		stop := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			f, err := os.OpenFile(p, os.O_WRONLY|os.O_APPEND, 0)
			if err != nil {
				return
			}
			defer func() { _ = f.Close() }()
			for time.Since(start) < delay { // wait, spinning: a sleep is too coarse
			}
			chunk := make([]byte, 64<<10)
			for {
				select {
				case <-stop:
					return
				default:
				}
				if _, err := f.Write(chunk); err != nil {
					return
				}
				firstDone.CompareAndSwap(0, int64(time.Since(start))+1)
			}
		}()
		r := readFileWithin(t, root, "grow")
		returned := time.Since(start)
		close(stop)
		wg.Wait()
		switch {
		case r.err == nil:
			if len(r.data) > fsx.MaxReadSize {
				t.Fatalf("round %d: ReadFile returned %d bytes, more than the limit of %d, with no error", round, len(r.data), fsx.MaxReadSize)
			}
			if len(r.data) != fsx.MaxReadSize {
				t.Fatalf("round %d: ReadFile returned %d bytes of a file that was at least %d long: a cut-off read", round, len(r.data), fsx.MaxReadSize)
			}
			if fd := time.Duration(firstDone.Load()); fd != 0 && fd < returned-margin {
				t.Fatalf("round %d: the file had grown %v before ReadFile returned %d bytes with no error: a read that does not look beyond the limit", round, returned-fd, len(r.data))
			}
			sawWhole++
		case errors.Is(r.err, fsx.ErrTooLarge):
			if r.data != nil {
				t.Fatalf("round %d: %d bytes came back with ErrTooLarge", round, len(r.data))
			}
			sawTooLarge++
		default:
			t.Fatalf("round %d: %v", round, r.err)
		}
	}
	if sawTooLarge == 0 {
		t.Fatalf("in %d rounds the file never grew under the reader (%d whole reads): the test does not look at what it means to", rounds, sawWhole)
	}
}

// TestOSANameSwappedBetweenTheLooksIsNeverFollowedOrWaitedOn: the reader looks at a name, opens it,
// and looks at the open file. A process that can write into the root swaps the name among a
// regular file, a link to a file outside and a FIFO as fast as it can; the reader must return the
// content of the regular file, or an error, and never what stands behind the link, and never wait
// on the FIFO. Whether the swap lands between two looks is a matter of luck on each try, and the
// loop makes it certain in practice.
func TestOSANameSwappedBetweenTheLooksIsNeverFollowedOrWaitedOn(t *testing.T) {
	for _, swap := range []struct {
		name string
		kind string // what the name is swapped to besides a regular file
	}{{"a link to a file outside", "link"}, {"a FIFO", "fifo"}} {
		t.Run(swap.name, func(t *testing.T) {
			wd := newWorld(t)
			target := filepath.Join(wd.root, "name")
			if err := os.WriteFile(target, []byte("inside\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			// the handle is closed in the background: a read that hangs holds the lock that Close
			// waits for, and the test must fail by its deadline, not wait for that read
			root, err := fsx.OpenFS(wd.root)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { go func() { _ = root.Close() }() })
			stop := make(chan struct{})
			var once sync.Once
			stopAll := func() { once.Do(func() { close(stop) }) }
			t.Cleanup(stopAll)
			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				defer wg.Done()
				tmp := filepath.Join(wd.root, "tmp-swap")
				for i := 0; ; i++ {
					select {
					case <-stop:
						return
					default:
					}
					_ = os.Remove(tmp)
					switch i % 2 {
					case 0:
						if swap.kind == "link" {
							_ = os.Symlink(filepath.Join(wd.outside, "secret"), tmp)
						} else {
							_ = syscall.Mkfifo(tmp, 0o600)
						}
					default:
						_ = os.WriteFile(tmp, []byte("inside\n"), 0o600)
					}
					_ = os.Rename(tmp, target)
				}
			}()
			deadline := time.Now().Add(1500 * time.Millisecond)
			reads, refused, bareLoop := 0, 0, 0
			for time.Now().Before(deadline) {
				r := readFileWithin(t, root, "name")
				reads++
				if r.err != nil {
					// what the name was when the reader met it says which refusal it gets
					want := fsx.ErrLink
					if swap.kind == "fifo" {
						want = fsx.ErrNotRegular
					}
					// a link that is a regular file again by the time the open is classified is
					// still refused, with the bare ELOOP of the open
					if !errors.Is(r.err, want) && (swap.kind != "link" || !errors.Is(r.err, syscall.ELOOP)) {
						stopAll()
						wg.Wait()
						t.Fatalf("ReadFile of a name that is swapped to %s: %v, want an error that wraps %v", swap.name, r.err, want)
					}
					refused++
					if swap.kind == "link" && !errors.Is(r.err, fsx.ErrLink) {
						bareLoop++
					}
					continue
				}
				if string(r.data) != "inside\n" {
					stopAll()
					wg.Wait()
					t.Fatalf("ReadFile returned %q: what stands behind the link, or something that is not the regular file", r.data)
				}
			}
			stopAll()
			wg.Wait()
			if reads < 1000 {
				t.Fatalf("only %d reads in the time: too few to meet a swap", reads)
			}
			t.Logf("%d reads, %d refused, %d with a bare ELOOP", reads, refused, bareLoop)
			// A read that opens a name that is a link gets ELOOP and asks again what the name is: it
			// is a link, and the error says so. A bare ELOOP is the rare swap back to a regular file
			// between the two (a few in 400,000 refusals); without the second look every such open is
			// bare (about 2% of the refusals).
			if bareLoop*200 > refused {
				t.Fatalf("%d of %d refusals have a bare ELOOP: the open that met a link did not name it", bareLoop, refused)
			}
		})
	}
}

// TestOSReadDirOfTheRealFolder: sorted by name, with the type, the permission bits and the size
// of each entry as the folder holds them, a link as a link; the name that is gone between the
// listing and the look is left out (not modelled: it cannot be made to happen on purpose here).
func TestOSReadDirOfTheRealFolder(t *testing.T) {
	wd := newWorld(t)
	wd.mkdir("d/sub")
	if err := os.WriteFile(filepath.Join(wd.root, "d", "b-file"), []byte("12345"), 0o640); err != nil {
		t.Fatal(err)
	}
	wd.symlink("b-file", "d/a-link")
	wd.symlink(filepath.Join("..", "outside"), "d/c-dirlink")
	wd.mkfifo("d/d-pipe")
	root := openFSIn(t, wd.root)
	ents, err := fsx.ReadDir(root, "d")
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, e := range ents {
		info, err := e.Info()
		if err != nil {
			t.Fatal(err)
		}
		if info.Name() != e.Name() || info.Mode().Type() != e.Type() || !info.ModTime().IsZero() {
			t.Errorf("%s: the info %v does not say what the entry says", e.Name(), info)
		}
		got = append(got, fmt.Sprintf("%s %v %d", e.Name(), e.Type(), info.Size()))
	}
	want := []string{
		fmt.Sprintf("a-link L--------- %d", len("b-file")),
		"b-file ---------- 5",
		fmt.Sprintf("c-dirlink L--------- %d", len(filepath.Join("..", "outside"))),
		"d-pipe p--------- 0",
		"sub d--------- ",
	}
	// the size of a folder is the system's own: only its type is pinned
	if len(got) != 5 || !strings.HasPrefix(got[4], "sub d--------- ") {
		t.Fatalf("ReadDir lists %q", got)
	}
	if !slices.Equal(got[:4], want[:4]) {
		t.Fatalf("ReadDir lists\n  %q\nwant\n  %q", got[:4], want[:4])
	}
	if info, _ := ents[1].Info(); info.Mode().Perm() != 0o640 {
		t.Errorf("the permission bits of b-file: %v, want 0640", info.Mode().Perm())
	}
	// the root, and the list of a file
	if _, err := fsx.ReadDir(root, "."); err != nil {
		t.Errorf("ReadDir(.): %v", err)
	}
	if _, err := fsx.ReadDir(root, "d/b-file"); err == nil || errors.Is(err, fsx.ErrLink) || errors.Is(err, fs.ErrNotExist) {
		t.Errorf("ReadDir of a file: %v", err)
	}
	// a big folder: every name once, in order
	big := filepath.Join(wd.root, "big")
	if err := os.Mkdir(big, 0o700); err != nil {
		t.Fatal(err)
	}
	var wantNames []string
	for i := 0; i < 700; i++ {
		n := fmt.Sprintf("n%04d", i)
		wantNames = append(wantNames, n)
		if err := os.WriteFile(filepath.Join(big, n), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	ents, err = fsx.ReadDir(root, "big")
	if err != nil || len(ents) != 700 {
		t.Fatalf("ReadDir of a big folder: %d entries, %v", len(ents), err)
	}
	for i, e := range ents {
		if e.Name() != wantNames[i] {
			t.Fatalf("entry %d is %s, want %s", i, e.Name(), wantNames[i])
		}
	}
}

// TestOSReadsAreNotConfusedByTheDescriptorTable: a read of a file does not leave the descriptor
// in blocking or non-blocking mode that another reader would find (each read opens its own).
func TestOSTheDataOfAReadBelongsToTheCaller(t *testing.T) {
	wd := newWorld(t)
	if err := os.WriteFile(filepath.Join(wd.root, "f"), []byte("aa\nbb\ncc"), 0o600); err != nil {
		t.Fatal(err)
	}
	root := openFSIn(t, wd.root)
	a, _ := fsx.ReadFile(root, "f")
	b, _ := fsx.ReadFile(root, "f")
	a[0] = 'X'
	if !bytes.Equal(b, []byte("aa\nbb\ncc")) {
		t.Fatalf("a change to one result changed another: %q", b)
	}
	lines, partial, err := fsx.ReadJournal(root, "f")
	if err != nil {
		t.Fatal(err)
	}
	_ = append(lines[0], 'X')
	_ = append(partial, 'Y')
	if string(lines[1]) != "bb" || string(partial) != "cc" {
		t.Fatalf("an append to one slice changed another: %q %q", lines[1], partial)
	}
}

// TestOSOpenedRootHasNoDescriptorThatSurvivesAnExec: every descriptor is opened with O_CLOEXEC.
func TestOSDescriptorsAreCloseOnExec(t *testing.T) {
	wd := newWorld(t)
	w := wd.open()
	j, err := w.CreateJournal("j")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = j.Close() }()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Skipf("no /proc/self/fd: %v", err)
	}
	seen := 0
	for _, e := range entries {
		target, err := os.Readlink("/proc/self/fd/" + e.Name())
		if err != nil || !strings.HasPrefix(target, wd.root) {
			continue
		}
		seen++
		var fd int
		_, _ = fmt.Sscan(e.Name(), &fd)
		flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
		if err != nil {
			continue
		}
		if flags&unix.FD_CLOEXEC == 0 {
			t.Errorf("the descriptor %d (%s) survives an exec", fd, target)
		}
	}
	if seen < 2 {
		t.Skipf("only %d descriptors of the root were found", seen)
	}
}

// TestOSAHostileRootNeverAppearsRawInTheTextOfOpen: the root path is the caller's, and the error
// that names it quotes it.
func TestOSAHostileRootNeverAppearsRawInTheTextOfOpen(t *testing.T) {
	base := t.TempDir()
	for _, s := range controlHostile {
		p := filepath.Join(base, "no-such-"+s)
		for what, err := range map[string]error{
			"Open":   func() error { w, err := fsx.Open(p); _ = w; return err }(),
			"OpenFS": func() error { f, err := fsx.OpenFS(p); _ = f; return err }(),
		} {
			if err == nil {
				t.Errorf("%s(%q) succeeded", what, p)
				continue
			}
			text := err.Error()
			for i := 0; i < len(text); i++ {
				if text[i] < 0x20 || text[i] > 0x7e {
					t.Errorf("%s with %q: the text %q holds the raw byte %#x", what, s, text, text[i])
					break
				}
			}
		}
	}
}
