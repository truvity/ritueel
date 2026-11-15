package software

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/fsx"
)

// Each case below pins one guard of the passphrase files that the other tests of the package pass
// without reaching.

func TestTheFileThatTheWriterMakesIsLookedAtWithTheCheckOfTheReaderBeforeItIsReturned(t *testing.T) {
	// The work factor that is written (9) is below the lowest that is read (10): the header of the
	// file that the library makes is then a file that this package would refuse to open, and the
	// writer says so instead of returning it.
	old, oldLow := workFactorWritten, workFactorLowest
	workFactorWritten, workFactorLowest = 9, 10
	defer func() { workFactorWritten, workFactorLowest = old, oldLow }()
	file, err := ageFormat{}.wrapWith([]byte(testPass), FileX509, []byte("a payload"))
	if file != nil {
		t.Error("a file came with the error")
	}
	wantRefusal(t, err, ErrKeyFile, "key-file")
	// through the Store: nothing is written
	s, _, keys := openPassStore(t, newPassSource(testPass))
	k := mustGenerate(t)
	if err := s.SaveX509("A", k); !errors.Is(err, ErrKeyFile) {
		t.Errorf("a save: %v", err)
	}
	if k.Saved() || len(dirNames(t, keys)) != 0 {
		t.Errorf("Saved %v, files %v", k.Saved(), dirNames(t, keys))
	}
}

func TestAnAgeFileWithAnEmptyPayloadIsErrKeyFile(t *testing.T) {
	lowWork(t)
	src := newPassSource(testPass)
	s, _, keys := openPassStore(t, src)
	writeKeyFile(t, keys, "A.removal.jws.age", libraryFile(t, testPass, 10, nil))
	got, err := s.ReadRemoval(bg(), "A")
	if got != nil {
		t.Error("a payload came")
	}
	wantRefusal(t, err, ErrKeyFile, "key-file")
	if src.calls() != 1 {
		t.Errorf("asked %d times", src.calls())
	}
	if _, err := (ageFormat{}).unwrapWith([]byte(testPass), FileRemoval, libraryFile(t, testPass, 10, nil)); !errors.Is(err, ErrKeyFile) {
		t.Errorf("unwrapWith: %v", err)
	}
}

func TestAPayloadThatFitsButWhoseFileWouldNotIsRefusedBeforeAnyWrite(t *testing.T) {
	lowWork(t)
	src := newPassSource(testPass)
	s, _, keys := openPassStore(t, src)
	rec := record(s)
	// the payload is under the limit, and the file with its header and tags is over it
	payload := bytes.Repeat([]byte{'a'}, MaxKeyFileSize-50)
	s.mu.Lock()
	err := s.write(FileRemoval, "A", "", payload, func([]byte) error { return nil }, nil)
	s.mu.Unlock()
	wantRefusal(t, err, ErrKeyFile, "key-file")
	if rec.calls() != 0 || len(dirNames(t, keys)) != 0 {
		t.Errorf("writes %d, files %v", rec.calls(), dirNames(t, keys))
	}
	// and the writer is not stopped by it: the name is free
	if err := s.SaveRemoval("A", jwsOf("YQ", "Yg", "Yw")); err != nil {
		t.Errorf("a save after the refusal: %v", err)
	}
}

// sparseReader gives an empty read before each byte.
type sparseReader struct {
	data  []byte
	empty bool
}

func (r *sparseReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, errors.New("end")
	}
	r.empty = !r.empty
	if r.empty {
		return 0, nil
	}
	p[0] = r.data[0]
	r.data = r.data[1:]
	return 1, nil
}

func TestReaderSourceCountsEmptyReadsInARowAndNotAllOfThem(t *testing.T) {
	line := strings.Repeat("s", 400)
	got, err := readOne(t, &sparseReader{data: []byte(line + "\n")})
	if err != nil || string(got) != line {
		t.Fatalf("%d bytes, %v", len(got), err)
	}
}

// cancelFS cancels a context when a file is read.
type cancelFS struct {
	staticFS
	cancel context.CancelFunc
}

func (c cancelFS) ReadFile(name string) ([]byte, error) {
	c.cancel()
	return c.staticFS.ReadFile(name)
}

func TestAContextCancelledWhileTheFileIsReadStopsBeforeTheHeaderIsLookedAt(t *testing.T) {
	src := newPassSource(testPass)
	ctx, cancel := context.WithCancel(context.Background())
	st := &Store{
		mode: ModePassphrase, w: refuseWriter{t}, source: src,
		fsys: cancelFS{staticFS: staticFS{files: map[string][]byte{"A.x509.key.age": headerOf(scryptStanza("18"))}}, cancel: cancel},
	}
	rf := &recAge{}
	st.format = rf
	_, err := st.OpenX509(ctx, "A")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("%v", err)
	}
	if rf.inspects != 0 || src.calls() != 0 || rf.unwraps != 0 {
		t.Errorf("inspected %d, asked %d, scrypt %d", rf.inspects, src.calls(), rf.unwraps)
	}
}

func TestAFileOfExactlyTheLimitIsLookedAtAndAskedForInTheStoreAndOneByteMoreIsNot(t *testing.T) {
	lowWork(t)
	overhead := len(libraryFile(t, testPass, 10, []byte("x"))) - 1
	atLimit := libraryFile(t, testPass, 10, bytes.Repeat([]byte{'x'}, MaxKeyFileSize-overhead))
	over := libraryFile(t, testPass, 10, bytes.Repeat([]byte{'x'}, MaxKeyFileSize-overhead+1))
	if len(atLimit) != MaxKeyFileSize || len(over) != MaxKeyFileSize+1 {
		t.Fatalf("the files are %d and %d bytes", len(atLimit), len(over))
	}
	for name, c := range map[string]struct {
		file     []byte
		inspects int
		asked    int
	}{"at the limit": {atLimit, 1, 1}, "over the limit": {over, 0, 0}} {
		t.Run(name, func(t *testing.T) {
			src := newPassSource(testPass)
			s, _, keys := openPassStore(t, src)
			rf := recordAge(t, s)
			writeKeyFile(t, keys, "A.x509.key.age", c.file)
			_, err := s.OpenX509(bg(), "A") // the payload is not a key: the file is refused after it opened
			if !errors.Is(err, ErrKeyFile) {
				t.Errorf("%v", err)
			}
			if rf.inspects != c.inspects || src.calls() != c.asked {
				t.Errorf("inspected %d times and asked %d times, want %d and %d", rf.inspects, src.calls(), c.inspects, c.asked)
			}
		})
	}
}

func TestASaveAsksTheSourceOnceAlthoughScryptRunsTwice(t *testing.T) {
	// a save asks the source once although the file is written and read back (two runs of scrypt)
	lowWork(t)
	src := newPassSource(testPass)
	s, _, _ := openPassStore(t, src)
	rf := recordAge(t, s)
	if err := s.SaveX509("A", mustGenerate(t)); err != nil {
		t.Fatal(err)
	}
	if src.calls() != 1 || rf.wraps != 1 || rf.unwraps != 1 {
		t.Errorf("asked %d times, wrapped %d, unwrapped %d", src.calls(), rf.wraps, rf.unwraps)
	}
	if _, err := s.OpenX509(bg(), "A"); err != nil {
		t.Fatal(err)
	}
	if src.calls() != 2 || rf.inspects != 1 { // the read back of a save does not go through the look at the header
		t.Errorf("asked %d times, inspected %d", src.calls(), rf.inspects)
	}
}

// ---- a store with a source that returns more than a passphrase ----

func TestTheReadsOfTheStoreUseTheContextThatTheyAreGiven(t *testing.T) {
	lowWork(t)
	var seen context.Context
	src := newPassSource(testPass)
	src.hook = func(ctx context.Context, _ Purpose) { seen = ctx }
	s, _, _ := openPassStore(t, src)
	if err := s.SaveX509("A", mustGenerate(t)); err != nil {
		t.Fatal(err)
	}
	type key struct{}
	ctx := context.WithValue(context.Background(), key{}, "value")
	if _, err := s.OpenX509(ctx, "A"); err != nil {
		t.Fatal(err)
	}
	if seen == nil || seen.Value(key{}) != "value" {
		t.Error("the source is not given the context of the open")
	}
}

func TestTheWriterOfAPassphraseStoreIsGivenTheFinalNameAndNoTemporaryFileStands(t *testing.T) {
	lowWork(t)
	s, _, keys := openPassStore(t, newPassSource(testPass))
	rec := record(s)
	if err := s.SaveX509("A", mustGenerate(t)); err != nil {
		t.Fatal(err)
	}
	if len(rec.writes) != 1 || rec.writes[0].name != "A.x509.key.age" {
		t.Fatalf("%v", rec.writes)
	}
	if strings.HasPrefix(rec.writes[0].name, fsx.TempPrefix) {
		t.Error("the writer is given a temporary name")
	}
	for _, n := range dirNames(t, keys) {
		if strings.HasPrefix(n, fsx.TempPrefix) {
			t.Errorf("a temporary file stands: %s", n)
		}
	}
}
