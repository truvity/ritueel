package ceremonytest

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/ceremony"
	"ritueel.id/ritueel/internal/fsx"
	"ritueel.id/ritueel/internal/keystore"
)

// The pieces that make a stop: the counter of changing calls, the file system that fails the nth,
// the store that fails a birth, the journal that fails a line, and the clock and the source of
// random bytes that make two runs write one plan.

func TestCounterFailsOnlyTheCallThatIsNamed(t *testing.T) {
	c := &counter{failAt: 3}
	var got []error
	for range 5 {
		got = append(got, c.op())
	}
	for i, err := range got {
		if want := i == 2; (err != nil) != want {
			t.Errorf("call %d: %v", i+1, err)
		}
	}
	if !errors.Is(got[2], errStop) {
		t.Errorf("the failing call returned %v, want errStop", got[2])
	}
	if c.count() != 5 || !c.hit() {
		t.Errorf("count %d, hit %v", c.count(), c.hit())
	}
	none := &counter{}
	for range 4 {
		if err := none.op(); err != nil {
			t.Fatalf("a counter that fails none failed: %v", err)
		}
	}
	if none.count() != 4 || none.hit() {
		t.Errorf("count %d, hit %v", none.count(), none.hit())
	}
	// A cut that is past the calls is never hit.
	far := &counter{failAt: 10}
	for range 3 {
		_ = far.op()
	}
	if far.hit() {
		t.Error("a cut past the calls was hit")
	}
	// The counter is safe to share: 1000 calls from 8 goroutines are counted, and one fails.
	shared := &counter{failAt: 500}
	var wg sync.WaitGroup
	var mu sync.Mutex
	failed := 0
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 125 {
				if err := shared.op(); err != nil {
					mu.Lock()
					failed++
					mu.Unlock()
				}
			}
		}()
	}
	wg.Wait()
	if shared.count() != 1000 || failed != 1 {
		t.Errorf("count %d, failed %d", shared.count(), failed)
	}
}

func openTemp(t *testing.T, c *counter) (*cutFS, string) {
	t.Helper()
	dir := t.TempDir()
	in, err := fsx.OpenFS(dir)
	if err != nil {
		t.Fatal(err)
	}
	// OpenFS gives a read-only view; the writer opens its own.
	_ = in.Close()
	w, err := fsx.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.Close() })
	return &cutFS{in: w.FS, c: c}, dir
}

// cutFS counts the calls that change a bundle (Mkdir, CreateExcl, RenameNoReplace, Sync of a folder,
// Write and Sync of a file), and counts none of the calls that read.
func TestCutFSCountsChangesAndNotReads(t *testing.T) {
	c := &counter{}
	f, dir := openTemp(t, c)
	if err := f.Mkdir("a", 0o755); err != nil { // 1
		t.Fatal(err)
	}
	file, err := f.CreateExcl("x", 0o644) // 2
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte("hello")); err != nil { // 3
		t.Fatal(err)
	}
	if err := file.Sync(); err != nil { // 4
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.RenameNoReplace("x", "y"); err != nil { // 5
		t.Fatal(err)
	}
	if err := f.Sync(); err != nil { // 6
		t.Fatal(err)
	}
	if got := c.count(); got != 6 {
		t.Errorf("the six changing calls were counted as %d", got)
	}
	sub, err := f.OpenDir("a") // a read
	if err != nil {
		t.Fatal(err)
	}
	if err := sub.Mkdir("b", 0o755); err != nil { // 7, through a folder opened from it
		t.Fatal(err)
	}
	if _, err := f.ReadFile("y"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.ReadDir(); err != nil {
		t.Fatal(err)
	}
	if got := c.count(); got != 7 {
		t.Errorf("after reads and a call through a sub-folder: %d, want 7", got)
	}
	if err := sub.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "a", "b")); err != nil {
		t.Errorf("the call through the sub-folder did not make the folder: %v", err)
	}
	if _, err := f.OpenDir("missing"); err == nil {
		t.Error("OpenDir of a missing folder gave no error")
	}
}

// Each kind of changing call can be the one that fails, and a call that fails does nothing, except
// a write, which writes the first half of its data.
func TestCutFSFailsEachKindOfCall(t *testing.T) {
	type op struct {
		name string
		run  func(f *cutFS) error
		done func(dir string) bool // true when the call did something
	}
	exists := func(rel string) func(string) bool {
		return func(dir string) bool { _, err := os.Lstat(filepath.Join(dir, rel)); return err == nil }
	}
	ops := []op{
		{"Mkdir", func(f *cutFS) error { return f.Mkdir("d", 0o755) }, exists("d")},
		{"CreateExcl", func(f *cutFS) error { _, err := f.CreateExcl("c", 0o644); return err }, exists("c")},
		{"RenameNoReplace", func(f *cutFS) error { return f.RenameNoReplace("src", "dst") }, exists("dst")},
		{"Sync", func(f *cutFS) error { return f.Sync() }, func(string) bool { return false }},
	}
	for _, o := range ops {
		t.Run(o.name, func(t *testing.T) {
			c := &counter{failAt: 1}
			f, dir := openTemp(t, c)
			if err := os.WriteFile(filepath.Join(dir, "src"), []byte("s"), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := o.run(f); !errors.Is(err, errStop) {
				t.Fatalf("the call returned %v, want errStop", err)
			}
			if o.done(dir) {
				t.Errorf("a failed %s did its work", o.name)
			}
			if !c.hit() {
				t.Error("the cut was not hit")
			}
		})
	}
	t.Run("Write", func(t *testing.T) {
		c := &counter{failAt: 2} // CreateExcl is 1, Write is 2
		f, dir := openTemp(t, c)
		file, err := f.CreateExcl("w", 0o644)
		if err != nil {
			t.Fatal(err)
		}
		n, err := file.Write([]byte("abcdefgh"))
		if !errors.Is(err, errStop) || n != 4 {
			t.Errorf("Write = %d, %v; want 4 and errStop", n, err)
		}
		_ = file.Close()
		if data, _ := os.ReadFile(filepath.Join(dir, "w")); string(data) != "abcd" {
			t.Errorf("the file holds %q, want the first half", data)
		}
		// An odd length gives the lower half, and one byte gives none.
		c2 := &counter{failAt: 2}
		f2, dir2 := openTemp(t, c2)
		file2, _ := f2.CreateExcl("w", 0o644)
		if n, err := file2.Write([]byte("a")); n != 0 || !errors.Is(err, errStop) {
			t.Errorf("Write of one byte = %d, %v", n, err)
		}
		_ = file2.Close()
		if data, _ := os.ReadFile(filepath.Join(dir2, "w")); len(data) != 0 {
			t.Errorf("the file holds %q", data)
		}
	})
	t.Run("file Sync", func(t *testing.T) {
		c := &counter{failAt: 3} // CreateExcl 1, Write 2, Sync 3
		f, _ := openTemp(t, c)
		file, err := f.CreateExcl("w", 0o644)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := file.Write([]byte("x")); err != nil {
			t.Fatal(err)
		}
		if err := file.Sync(); !errors.Is(err, errStop) {
			t.Errorf("Sync = %v, want errStop", err)
		}
		_ = file.Close()
	})
}

func TestStopStoreFailsTheNamedBirthBeforeTheKeyIsMade(t *testing.T) {
	var births []string
	inner := &fakeStore{birth: func(label string) (keystore.Key, error) { births = append(births, label); return nil, nil }}
	s := &stopStore{RootStore: inner, birthAt: 2}
	ctx := context.Background()
	if _, err := s.Birth(ctx, "A"); err != nil {
		t.Fatalf("the first birth: %v", err)
	}
	if s.hit() {
		t.Error("hit after the first birth")
	}
	if _, err := s.Birth(ctx, "B"); !errors.Is(err, errStop) {
		t.Fatalf("the second birth: %v", err)
	}
	if !s.hit() {
		t.Error("not hit after the second birth")
	}
	if !slices.Equal(births, []string{"A"}) {
		t.Errorf("the store made %v: the failed birth must not reach it", births)
	}
	// A store with no stop passes everything.
	pass := &stopStore{RootStore: inner}
	for _, l := range []string{"A", "B", "C"} {
		if _, err := pass.Birth(ctx, l); err != nil {
			t.Fatal(err)
		}
	}
	if pass.hit() {
		t.Error("a store with no stop was hit")
	}
	// Once the stop is passed, later births are the store's again.
	if _, err := s.Birth(ctx, "C"); err != nil {
		t.Errorf("a birth after the stop: %v", err)
	}
}

// fakeStore is a RootStore whose Birth is a function; the other methods are never called.
type fakeStore struct {
	ceremony.RootStore
	birth func(label string) (keystore.Key, error)
}

func (f *fakeStore) Birth(_ context.Context, label string) (keystore.Key, error) {
	return f.birth(label)
}

func TestStopJournalKeepsWhatItAcceptedAndFailsTheNamedLine(t *testing.T) {
	inner := &memJournal{}
	j := &stopJournal{inner: inner, failAt: 3}
	for _, l := range []string{"one", "two"} {
		if err := j.Append([]byte(l)); err != nil {
			t.Fatal(err)
		}
	}
	line := []byte("three")
	if err := j.Append(line); !errors.Is(err, errStop) {
		t.Fatalf("the third line: %v", err)
	}
	if !j.hit() {
		t.Error("not hit")
	}
	if got := inner.lines; !slices.Equal(got, []string{"one", "two"}) {
		t.Errorf("the journal holds %v: the failed line must not reach it", got)
	}
	if got := j.accepted(); len(got) != 2 || string(got[0]) != "one" || string(got[1]) != "two" {
		t.Errorf("accepted = %q", got)
	}
	// What was accepted is a copy: a change of the caller's bytes or of the list changes nothing.
	buf := []byte("mutable")
	k := &stopJournal{inner: &memJournal{}}
	if err := k.Append(buf); err != nil {
		t.Fatal(err)
	}
	buf[0] = 'X'
	a := k.accepted()
	if string(a[0]) != "mutable" {
		t.Errorf("accepted line is %q after the caller changed its buffer", a[0])
	}
	a = append(a[:0], []byte("replaced"))
	if len(a) != 1 || len(k.accepted()) != 1 || string(k.accepted()[0]) != "mutable" {
		t.Error("a change of the list that accepted gave changes the journal's own list")
	}
	// A line after the stop goes through again.
	if err := j.Append([]byte("four")); err != nil {
		t.Errorf("a line after the stop: %v", err)
	}
	// A journal with no file behind it is a fault, not a stop.
	bare := &stopJournal{}
	if err := bare.Append([]byte("x")); err == nil || errors.Is(err, errStop) {
		t.Errorf("a journal with no file: %v", err)
	}
	// The error of the journal is the journal's.
	boom := errors.New("boom")
	f := &stopJournal{inner: &memJournal{err: boom}}
	if err := f.Append([]byte("x")); !errors.Is(err, boom) {
		t.Errorf("the journal's error: %v", err)
	}
	if len(f.accepted()) != 0 {
		t.Error("a line that the journal refused was kept as accepted")
	}
}

type memJournal struct {
	lines []string
	err   error
}

func (m *memJournal) Append(line []byte) error {
	if m.err != nil {
		return m.err
	}
	m.lines = append(m.lines, string(line))
	return nil
}

func TestStopTraceHasTwoJournals(t *testing.T) {
	tr := newStopTrace(2)
	a, b := &memJournal{}, &memJournal{}
	tr.use(fakeTrace{a, b})
	if tr.Births() == tr.Signatures() {
		t.Fatal("one journal for both")
	}
	if err := tr.Births().Append([]byte("b1")); err != nil {
		t.Fatal(err)
	}
	if err := tr.Births().Append([]byte("b2")); err != nil {
		t.Fatal(err)
	}
	if err := tr.Signatures().Append([]byte("s1")); err != nil {
		t.Fatal(err)
	}
	if err := tr.Signatures().Append([]byte("s2")); !errors.Is(err, errStop) {
		t.Fatalf("the second line of signatures: %v", err)
	}
	if !slices.Equal(a.lines, []string{"b1", "b2"}) || !slices.Equal(b.lines, []string{"s1"}) {
		t.Errorf("births %v, signatures %v", a.lines, b.lines)
	}
	if tr.births.hit() || !tr.sigs.hit() {
		t.Errorf("births hit %v, signatures hit %v", tr.births.hit(), tr.sigs.hit())
	}
	// No stop at all.
	none := newStopTrace(0)
	none.use(fakeTrace{&memJournal{}, &memJournal{}})
	for range 5 {
		if err := none.Signatures().Append([]byte("x")); err != nil {
			t.Fatal(err)
		}
	}
}

type fakeTrace struct{ b, s *memJournal }

func (f fakeTrace) Births() ceremony.Journal     { return f.b }
func (f fakeTrace) Signatures() ceremony.Journal { return f.s }

func TestClockRunsOneSecondAtACall(t *testing.T) {
	base := time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)
	c := newClock(base)
	for i := 1; i <= 5; i++ {
		if got, want := c.now(), base.Add(time.Duration(i)*time.Second); !got.Equal(want) {
			t.Errorf("call %d: %v, want %v", i, got, want)
		}
	}
	// Safe from several goroutines: every second 1..400 is given once.
	d := newClock(base)
	var wg sync.WaitGroup
	var mu sync.Mutex
	seen := map[time.Time]int{}
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 100 {
				v := d.now()
				mu.Lock()
				seen[v]++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if len(seen) != 400 {
		t.Errorf("%d different times from 400 calls", len(seen))
	}
}

func TestCounterRandIsTheSameStreamEveryTime(t *testing.T) {
	read := func(sizes ...int) []byte {
		r := &counterRand{}
		var out []byte
		for _, n := range sizes {
			p := make([]byte, n)
			got, err := r.Read(p)
			if err != nil || got != n {
				t.Fatalf("Read(%d) = %d, %v", n, got, err)
			}
			out = append(out, p...)
		}
		return out
	}
	a, b := read(300), read(10, 100, 190)
	if !slices.Equal(a, b) {
		t.Error("the stream depends on how it is read")
	}
	if !slices.Equal(a[:5], []byte{2, 3, 4, 5, 6}) {
		t.Errorf("the stream starts %v", a[:5])
	}
	for i, v := range a {
		if v == 0 {
			t.Fatalf("a zero byte at %d: a source of serials must not give one", i)
		}
	}
	// The stream has a period of 251 bytes.
	if a[251] != a[0] || a[250] == a[0] {
		t.Errorf("a[0] %d a[250] %d a[251] %d: the period is not 251", a[0], a[250], a[251])
	}
	if n, err := (&counterRand{}).Read(nil); n != 0 || err != nil {
		t.Errorf("Read(nil) = %d, %v", n, err)
	}
}

func TestFoldersMakesTheKeyDirectory(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		dir, key := folders(t, Options{})
		if filepath.Base(dir) != "ca" || filepath.Base(key) != "keys" || filepath.Dir(dir) == filepath.Dir(key) {
			t.Errorf("dir %s, key %s", dir, key)
		}
		fi, err := os.Stat(key)
		if err != nil || !fi.IsDir() || fi.Mode().Perm() != 0o700 {
			t.Errorf("key directory: %v %v", fi, err)
		}
		if _, err := os.Stat(dir); err == nil {
			t.Error("the bundle folder was made: bundle.Create makes it")
		}
	})
	t.Run("given", func(t *testing.T) {
		root := t.TempDir()
		dir, key := folders(t, Options{Dir: filepath.Join(root, "b"), KeyDir: filepath.Join(root, "x", "y", "k")})
		if dir != filepath.Join(root, "b") || key != filepath.Join(root, "x", "y", "k") {
			t.Errorf("dir %s, key %s", dir, key)
		}
		if fi, err := os.Stat(key); err != nil || fi.Mode().Perm() != 0o700 {
			t.Errorf("key directory: %v %v", fi, err)
		}
	})
	t.Run("a key directory that is a file", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "f")
		if err := os.WriteFile(p, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if msg := failing(t, func(tb testing.TB) { folders(tb, Options{KeyDir: p}) }); !strings.Contains(msg, "key directory") {
			t.Errorf("message %q", msg)
		}
	})
}

func TestNextLabelIsTheLetterAfterTheHighest(t *testing.T) {
	mk := func(names ...string) string {
		dir := t.TempDir()
		if err := os.Mkdir(filepath.Join(dir, "roots"), 0o755); err != nil {
			t.Fatal(err)
		}
		for _, n := range names {
			if err := os.Mkdir(filepath.Join(dir, "roots", n), 0o755); err != nil {
				t.Fatal(err)
			}
		}
		return dir
	}
	cases := []struct {
		names []string
		want  string
	}{
		{nil, "A"},
		{[]string{"A"}, "B"},
		{[]string{"A", "B"}, "C"},
		{[]string{"B", "A"}, "C"},
		{[]string{"A", "C"}, "D"}, // after the highest, not the first free
	}
	for _, c := range cases {
		if got := nextLabel(t, mk(c.names...)); got != c.want {
			t.Errorf("%v: %s, want %s", c.names, got, c.want)
		}
	}
	// A name that is not one capital letter is no label.
	if got := nextLabel(t, mk("A", "ab", "z", "1", "AB", "-")); got != "B" {
		t.Errorf("with names that are no labels: %s, want B", got)
	}
	// The letter Z is a label.
	upToY := make([]string, 0, 25)
	for c := 'A'; c <= 'Y'; c++ {
		upToY = append(upToY, string(c))
	}
	if got := nextLabel(t, mk(upToY...)); got != "Z" {
		t.Errorf("after Y: %s, want Z", got)
	}
	// After Z there is no letter left.
	all := make([]string, 0, 26)
	for c := 'A'; c <= 'Z'; c++ {
		all = append(all, string(c))
	}
	if msg := failing(t, func(tb testing.TB) { nextLabel(tb, mk(all...)) }); !strings.Contains(msg, "after Z") {
		t.Errorf("message %q", msg)
	}
	if msg := failing(t, func(tb testing.TB) { nextLabel(tb, t.TempDir()) }); !strings.Contains(msg, "roots/") {
		t.Errorf("a bundle with no roots/: message %q", msg)
	}
}

func TestMkdirIfAbsentMakesAFolderOnce(t *testing.T) {
	dir := t.TempDir()
	w, err := fsx.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = w.Close() }()
	if err := mkdirIfAbsent(w, "x"); err != nil {
		t.Fatal(err)
	}
	if err := mkdirIfAbsent(w, "x"); err != nil {
		t.Errorf("a folder that is there: %v", err)
	}
	if fi, err := os.Stat(filepath.Join(dir, "x")); err != nil || !fi.IsDir() {
		t.Errorf("x: %v %v", fi, err)
	}
	// A file of that name is a fault, and stops the writer.
	if err := os.WriteFile(filepath.Join(dir, "f"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := mkdirIfAbsent(w, "f"); err == nil {
		t.Error("a file where a folder belongs gave no error")
	}
}

// failing runs f with a testing.TB that records a failure and stops the goroutine, as Fatalf does.
func failing(t *testing.T, f func(tb testing.TB)) string {
	t.Helper()
	ft := &failTB{TB: t}
	done := make(chan struct{})
	go func() {
		defer close(done)
		f(ft)
	}()
	<-done
	if ft.msg == "" {
		t.Fatal("the call did not fail the test")
	}
	return ft.msg
}

type failTB struct {
	testing.TB
	msg string
}

func (f *failTB) Fatalf(format string, args ...any) {
	f.msg = fmt.Sprintf(format, args...)
	runtime.Goexit()
}
func (f *failTB) Fatal(args ...any) { f.msg = fmt.Sprint(args...); runtime.Goexit() }
func (f *failTB) Helper()           {}
