package software

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/openpgp"
)

// ---- the mode and the format of a Store agree before a file is written ----

// saveCalls is the four calls that write a file, each with valid arguments, so that a refusal
// comes from the mode and the format and from nothing else.
func saveCalls(t *testing.T, s *Store, k *Key) map[string]func() error {
	t.Helper()
	cert := certFor(t, k)
	rev := revocationFor(t, k, openpgp.Superseded)
	jws := jwsOf("a", "b", "c")
	return map[string]func() error{
		"SaveX509":       func() error { return s.SaveX509("A", k) },
		"SaveOpenPGP":    func() error { return s.SaveOpenPGP("A", k, cert) },
		"SaveRevocation": func() error { return s.SaveRevocation("A", "superseded", rev) },
		"SaveRemoval":    func() error { return s.SaveRemoval("A", jws) },
	}
}

// mismatches are Stores that were put together wrongly: the mode and the format do not agree. The
// source is set where a mode that reads a passphrase would ask it, so that a write that got past
// the check would find a source to ask.
func mismatches(src PassphraseSource) map[string]struct {
	mode   Mode
	format format
	source PassphraseSource
} {
	type m = struct {
		mode   Mode
		format format
		source PassphraseSource
	}
	return map[string]m{
		"the passphrase mode with the plain format":                     {ModePassphrase, plainFormat{}, src},
		"the passphrase mode with the plain format and no source":       {ModePassphrase, plainFormat{}, nil},
		"the test mode with the age format and a source":                {ModeTest, ageFormat{}, src},
		"the test mode with the age format and no source":               {ModeTest, ageFormat{}, nil},
		"the passphrase mode with a wrapper that hides the age methods": {ModePassphrase, &recFormat{inner: ageFormat{}}, src},
		"the test mode with a wrapper that forwards the age methods":    {ModeTest, &recAge{}, src},
		"a mode that is neither, with the plain format":                 {Mode(99), plainFormat{}, src},
		"a mode that is neither, with the age format":                   {Mode(99), ageFormat{}, src},
	}
}

func TestAStoreWhoseModeAndFormatDisagreeWritesNothingAndIsErrParams(t *testing.T) {
	lowWork(t)
	for name, c := range mismatches(nil) {
		for _, call := range []string{"SaveX509", "SaveOpenPGP", "SaveRevocation", "SaveRemoval"} {
			t.Run(name+"/"+call, func(t *testing.T) {
				src := newPassSource(testPass)
				s, _, keys := openStore(t)
				k := mustGenerate(t)
				s.mode, s.format = c.mode, c.format
				if c.source != nil {
					s.source = src
				}
				rec := record(s)
				secrets := keysOf(t, k, certFor(t, k)).with(passphraseCanaries(testPass))

				err := saveCalls(t, s, k)[call]()
				if err == nil {
					t.Fatal("a Store whose mode and format disagree wrote")
				}
				if !errors.Is(err, ErrParams) {
					t.Errorf("the error does not wrap ErrParams: %v", err)
				}
				for _, other := range []error{ErrWrongMode, ErrKeyExists, ErrKeyFile, ErrPassphrase, ErrWrongPassphrase, ErrNotBuilt} {
					if errors.Is(err, other) {
						t.Errorf("the error also wraps %v: %v", other, err)
					}
				}
				if Code(err) != "" {
					t.Errorf("the code is %q: a fault of the caller has none", Code(err))
				}
				if bad := secrets.find([]byte(err.Error())); bad != "" {
					t.Errorf("the error holds the %s", bad)
				}
				if rec.calls() != 0 {
					t.Errorf("the writer was called %d times", rec.calls())
				}
				if names := dirNames(t, keys); len(names) != 0 {
					t.Errorf("the key folder holds %v", names)
				}
				if src.calls() != 0 {
					t.Errorf("the source was asked %d times", src.calls())
				}
				if k.Saved() {
					t.Error("the key says it was saved")
				}
				if s.stop != nil {
					t.Errorf("the writer was stopped: %v", s.stop)
				}
				switch f := c.format.(type) {
				case *recFormat:
					if f.wraps != 0 || f.unwraps != 0 {
						t.Errorf("the wrapper was used: %d wraps %d unwraps", f.wraps, f.unwraps)
					}
				case *recAge:
					if f.wraps+f.unwraps+f.plain+f.inspects != 0 {
						t.Errorf("the wrapper was used: %+v", f)
					}
				}
			})
		}
	}
}

// After a refused write the Store is not stopped: put right, it writes.
func TestAStoreThatWasPutRightAfterAMismatchStillWrites(t *testing.T) {
	lowWork(t)
	cases := []struct {
		name   string
		wrong  func(s *Store)
		right  func(s *Store)
		header string
	}{
		{"the passphrase mode", func(s *Store) { s.format = plainFormat{} }, func(s *Store) { s.format = ageFormat{} }, "age-encryption.org/v1\n"},
		{"the test mode", func(s *Store) { s.format = ageFormat{}; s.source = newPassSource(testPass) }, func(s *Store) { s.format = plainFormat{}; s.source = nil }, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var s *Store
			var keys string
			if c.header != "" {
				s, _, keys = openPassStore(t, newPassSource(testPass))
			} else {
				s, _, keys = openStore(t)
			}
			k := mustGenerate(t)
			c.wrong(s)
			if err := s.SaveX509("A", k); !errors.Is(err, ErrParams) {
				t.Fatalf("the first save: %v", err)
			}
			c.right(s)
			if err := s.SaveX509("A", k); err != nil {
				t.Fatalf("the save after it was put right: %v", err)
			}
			if !k.Saved() {
				t.Error("the key does not say it was saved")
			}
			names := dirNames(t, keys)
			if c.header != "" {
				if len(names) != 1 || names[0] != "A.x509.key.age" {
					t.Fatalf("the key folder holds %v", names)
				}
				if got := readKeyFile(t, keys, names[0]); !bytes.HasPrefix(got, []byte(c.header)) {
					t.Error("the file does not start with the age header line")
				}
			} else if len(names) != 1 || names[0] != "A.x509.key.pem" {
				t.Fatalf("the key folder holds %v", names)
			}
		})
	}
}

// A file of the other mode in the folder still gives ErrWrongMode first, and a taken name gives
// ErrParams and not ErrKeyExists: the mode and the format are checked before the name is looked at.
func TestAMismatchedStoreAnswersAFileOfTheOtherModeFirstAndATakenNameAfter(t *testing.T) {
	lowWork(t)
	cases := []struct {
		name   string
		mode   Mode
		format format
		other  string // a file of the other mode
		taken  string // a file of this mode under the name that a save wants
	}{
		{"the passphrase mode with the plain format", ModePassphrase, plainFormat{}, "A.x509.key.pem", "A.x509.key.age"},
		{"the test mode with the age format", ModeTest, ageFormat{}, "A.x509.key.age", "A.x509.key.pem"},
	}
	for _, c := range cases {
		t.Run(c.name+"/the other mode", func(t *testing.T) {
			s, _, keys := openStore(t)
			s.mode, s.format, s.source = c.mode, c.format, newPassSource(testPass)
			rec := record(s)
			k := mustGenerate(t)
			writeKeyFile(t, keys, c.other, []byte("not read"))
			for call, f := range saveCalls(t, s, k) {
				if err := f(); !errors.Is(err, ErrWrongMode) || errors.Is(err, ErrParams) {
					t.Errorf("%s: %v", call, err)
				}
			}
			if rec.calls() != 0 || len(dirNames(t, keys)) != 1 {
				t.Errorf("writes %d, folder %v", rec.calls(), dirNames(t, keys))
			}
		})
		t.Run(c.name+"/a taken name", func(t *testing.T) {
			s, _, keys := openStore(t)
			s.mode, s.format, s.source = c.mode, c.format, newPassSource(testPass)
			rec := record(s)
			k := mustGenerate(t)
			writeKeyFile(t, keys, c.taken, []byte("stays as it is"))
			if err := s.SaveX509("A", k); !errors.Is(err, ErrParams) || errors.Is(err, ErrKeyExists) {
				t.Errorf("SaveX509: %v", err)
			}
			if rec.calls() != 0 || string(readKeyFile(t, keys, c.taken)) != "stays as it is" {
				t.Error("the file was touched or a write was made")
			}
		})
	}
}

// A Store that Open made has the format of its mode, so the check refuses none of the four saves.
func TestAStoreThatOpenMadeSavesAllFourFilesInEitherMode(t *testing.T) {
	lowWork(t)
	for _, passphrase := range []bool{false, true} {
		t.Run(fmt.Sprintf("passphrase %v", passphrase), func(t *testing.T) {
			var s *Store
			var keys string
			if passphrase {
				s, _, keys = openPassStore(t, newPassSource(testPass))
			} else {
				s, _, keys = openStore(t)
			}
			k := mustGenerate(t)
			for call, f := range saveCalls(t, s, k) {
				if err := f(); err != nil {
					t.Errorf("%s: %v", call, err)
				}
			}
			if names := dirNames(t, keys); len(names) != 4 {
				t.Errorf("the key folder holds %v", names)
			}
		})
	}
}

// The rule of the check as a table, for the cases that a Store cannot reach: a zero mode is
// stopped before it, and a mode that is neither has a name that is looked at first.
func TestModeAndFormatAgreeIsTheTableOfThePage(t *testing.T) {
	for _, c := range []struct {
		mode   Mode
		secret bool
		want   bool
	}{
		{ModePassphrase, true, true}, {ModePassphrase, false, false},
		{ModeTest, false, true}, {ModeTest, true, false},
		{0, false, false}, {0, true, false},
		{Mode(99), false, false}, {Mode(99), true, false},
		{Mode(-1), false, false}, {Mode(-1), true, false},
	} {
		if got := modeAndFormatAgree(c.mode, c.secret); got != c.want {
			t.Errorf("mode %d, age format %v: %v, want %v", c.mode, c.secret, got, c.want)
		}
	}
}

// ---- the source of ReaderSource prints fixed words ----

const sourceWords = "software.ReaderSource"

// printCanaries is the forms that the bytes of a reader take when a formatter prints it: the text,
// its hex, its Base64 and a list of decimal numbers (a list of bytes printed with %v).
func printCanaries(text string) canaries {
	b := []byte(text)
	nums := make([]string, len(b))
	for i, c := range b {
		nums[i] = strconv.Itoa(int(c))
	}
	return canaries{
		{"the text", b},
		{"a window of the text", []byte(text[3:11])},
		{"the hex", []byte(hex.EncodeToString(b))},
		{"the HEX", []byte(strings.ToUpper(hex.EncodeToString(b)))},
		{"the spaced hex", []byte(fmt.Sprintf("% x", b))},
		{"the Base64", []byte(base64.StdEncoding.EncodeToString(b))},
		{"the decimal list", []byte(strings.Join(nums, " "))},
		{"the first decimals", []byte(strings.Join(nums[:6], " "))},
	}
}

var printVerbs = []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%t", "%c", "%U", "%e", "%08.3f", "%10s", "%-40v", "%+q", "% x", "%#x", "%#q", "%[1]v", "%!", "%z"}

const readerText = "plover quartz-lamp hedgerow tumbles"

func TestAReaderSourcePrintsFixedWordsWithEveryVerb(t *testing.T) {
	secrets := printCanaries(readerText)
	readers := map[string]func() io.Reader{
		"a bytes reader":   func() io.Reader { return bytes.NewReader([]byte(readerText + "\n")) },
		"a strings reader": func() io.Reader { return strings.NewReader(readerText + "\n") },
		"a counting one":   func() io.Reader { return &countReader{r: strings.NewReader(readerText + "\n")} },
		"no reader":        func() io.Reader { return nil },
	}
	for rname, mk := range readers {
		for _, verb := range printVerbs {
			t.Run(rname+"/"+verb, func(t *testing.T) {
				out := fmt.Sprintf(verb, ReaderSource(mk()))
				if bad := secrets.find([]byte(out)); bad != "" {
					t.Fatalf("%s prints %s: %q", verb, bad, out)
				}
				if verb != "%!" && verb != "%z" && !strings.Contains(out, sourceWords) {
					t.Errorf("%s prints %q, not the fixed words", verb, out)
				}
			})
		}
	}
}

func TestAReaderSourcePrintsExactlyTheFixedWordsWithThePlainVerbs(t *testing.T) {
	src := ReaderSource(strings.NewReader(readerText))
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%t", "%c"} {
		if got := fmt.Sprintf(verb, src); got != sourceWords {
			t.Errorf("%s prints %q", verb, got)
		}
	}
	if got := fmt.Sprint(src); got != sourceWords {
		t.Errorf("Sprint prints %q", got)
	}
	if got := fmt.Sprintln(src); got != sourceWords+"\n" {
		t.Errorf("Sprintln prints %q", got)
	}
	if got := fmt.Sprint(src, src); !strings.HasPrefix(got, sourceWords) || strings.Count(got, sourceWords) != 2 {
		t.Errorf("Sprint of two prints %q", got)
	}
	if st, ok := src.(fmt.Stringer); !ok || st.String() != sourceWords {
		t.Error("the source has no String with the fixed words")
	}
	if _, ok := src.(fmt.Formatter); !ok {
		t.Error("the source has no Format")
	}
	var b bytes.Buffer
	if _, err := fmt.Fprintf(&b, "%v|%s|%q", src, src, src); err != nil {
		t.Fatal(err)
	}
	if b.String() != strings.Repeat(sourceWords+"|", 2)+sourceWords {
		t.Errorf("Fprintf wrote %q", b.String())
	}
}

// %T and %p are answered by fmt before a Formatter is asked: they print the type and an address,
// never the bytes of the reader.
func TestAReaderSourcePrintsNoBytesWithTheVerbsThatFmtAnswersItself(t *testing.T) {
	secrets := printCanaries(readerText)
	src := ReaderSource(bytes.NewReader([]byte(readerText)))
	for _, verb := range []string{"%T", "%p", "%#p"} {
		if bad := secrets.find([]byte(fmt.Sprintf(verb, src))); bad != "" {
			t.Errorf("%s prints %s", verb, bad)
		}
	}
}

func TestATypedNilReaderSourcePrintsTheFixedWordsAndDoesNotPanic(t *testing.T) {
	var s *readerSource
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%d"} {
		if got := fmt.Sprintf(verb, s); got != sourceWords {
			t.Errorf("%s prints %q", verb, got)
		}
	}
	if got := s.String(); got != sourceWords {
		t.Errorf("String gives %q", got)
	}
	var src PassphraseSource = s
	if got := fmt.Sprint(src); got != sourceWords {
		t.Errorf("Sprint gives %q", got)
	}
}

// A source inside another value: a Config, a list and a map print no bytes of the reader, and a
// Store that holds the source prints none with any verb.
func TestAReaderSourceInsideOtherValuesPrintsNoBytesOfItsReader(t *testing.T) {
	secrets := printCanaries(readerText)
	mk := func() PassphraseSource { return ReaderSource(bytes.NewReader([]byte(readerText + "\n"))) }
	s, bundle, keys := openPassStore(t, mk())
	values := map[string]any{
		"a Config":     Config{KeyDir: keys, BundleDir: bundle, Mode: ModePassphrase, Passphrases: mk()},
		"a Config ptr": &Config{KeyDir: keys, BundleDir: bundle, Mode: ModePassphrase, Passphrases: mk()},
		"a list":       []PassphraseSource{mk(), mk()},
		"a map":        map[string]PassphraseSource{"A": mk()},
		"a struct":     struct{ S PassphraseSource }{mk()},
		"a Store":      s,
	}
	for name, v := range values {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%d"} {
			if bad := secrets.find([]byte(fmt.Sprintf(verb, v))); bad != "" {
				t.Errorf("%s with %s prints %s", name, verb, bad)
			}
		}
	}
}

// The errors of a Store that holds a ReaderSource never print the source.
func TestTheErrorsOfAStoreWithAReaderSourceHoldNoBytesOfItsReader(t *testing.T) {
	lowWork(t)
	secrets := printCanaries(readerText).with(passphraseCanaries(readerText))
	// the reader holds the passphrase of the first key and then a refused line
	s, _, keys := openPassStore(t, ReaderSource(strings.NewReader(readerText+"\nshort\n")))
	k := mustGenerate(t)
	var all []error
	all = append(all, s.SaveX509("A", k))
	k2 := mustGenerate(t)
	all = append(all, s.SaveX509("B", k2), s.SaveX509("C", k2))
	_, err := s.OpenX509(bg(), "A")
	all = append(all, err)
	if all[0] != nil {
		t.Fatalf("the first save: %v", all[0])
	}
	if all[1] == nil || all[2] == nil || err == nil {
		t.Fatalf("a refusal is missing: %v", all)
	}
	for _, e := range all[1:] {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
			if bad := secrets.find([]byte(fmt.Sprintf(verb, e))); bad != "" {
				t.Errorf("%s of %v prints %s", verb, e, bad)
			}
		}
	}
	for _, n := range dirNames(t, keys) {
		if n != "A.x509.key.age" {
			t.Errorf("an unexpected file %s", n)
		}
	}
}

// Printing a source does not read its reader: the next call still gets the first line.
func TestPrintingAReaderSourceDoesNotReadItsReader(t *testing.T) {
	cr := &countReader{r: strings.NewReader(readerText + "\n")}
	src := ReaderSource(cr)
	for _, verb := range printVerbs {
		_ = fmt.Sprintf(verb, src)
	}
	_ = fmt.Sprint(src)
	if cr.n != 0 || cr.closed {
		t.Fatalf("printing read %d bytes, closed %v", cr.n, cr.closed)
	}
	got, err := src.Passphrase(bg(), Purpose{Label: "A", File: FileX509})
	if err != nil || string(got) != readerText {
		t.Errorf("the line is %q, %v", got, err)
	}
}

// ---- what the doc says (points 1 and 2 of the fix are words) ----

// docOf returns the doc comment of the package and of each function or method of the package,
// with every run of white space made one space.
func docOf(t *testing.T) (pkg string, funcs map[string]string, fset *token.FileSet, files map[string]*ast.File) {
	t.Helper()
	fset = token.NewFileSet()
	files = map[string]*ast.File{}
	funcs = map[string]string{}
	paths, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range paths {
		if strings.HasSuffix(p, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, p, nil, parser.ParseComments)
		if err != nil {
			t.Fatal(err)
		}
		files[p] = f
		if f.Doc != nil {
			pkg += " " + f.Doc.Text()
		}
		for _, d := range f.Decls {
			if fd, ok := d.(*ast.FuncDecl); ok && fd.Doc != nil {
				funcs[fd.Name.Name] = squash(fd.Doc.Text())
			}
		}
	}
	return squash(pkg), funcs, fset, files
}

func squash(s string) string { return strings.Join(strings.Fields(s), " ") }

func TestTheDocOfThePackageSaysWhatAFileAtTheHighestWorkFactorCosts(t *testing.T) {
	if _, err := os.Stat("doc.go"); err != nil {
		t.Skip("no source beside the test")
	}
	pkg, _, _, _ := docOf(t)
	for _, want := range []string{
		"4 GiB", "7 to 9 seconds", "at every open", "wrong passphrase", "whose payload is damaged",
		"256 MiB", "above 22",
		"buffers of the age library", "64 KiB each", "cannot clear those either",
	} {
		if !strings.Contains(pkg, want) {
			t.Errorf("the package doc does not say %q", want)
		}
	}
}

func TestTheDocOfReaderSourceSaysWhatItDoesNotDo(t *testing.T) {
	if _, err := os.Stat("passphrase.go"); err != nil {
		t.Skip("no source beside the test")
	}
	_, funcs, _, _ := docOf(t)
	doc, ok := funcs["ReaderSource"]
	if !ok {
		t.Fatal("ReaderSource has no doc")
	}
	for _, want := range []string{
		"over the limit is refused", "stay in the reader", "next call reads that tail as a line",
		"A Read that blocks is not interrupted", "context before its first read", "not while a read waits",
		"Close waits", "in its own goroutine", "fixed words", "never the bytes of its reader",
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("the doc of ReaderSource does not say %q", want)
		}
	}
}

// The doc of WriteWorkFactor carries the same figures as the package doc.
func TestTheDocOfTheWriteWorkFactorNamesThe22Cost(t *testing.T) {
	data, err := os.ReadFile("age.go")
	if err != nil {
		t.Skip("no source beside the test")
	}
	if !strings.Contains(squash(string(data)), "4 GiB and 7 to 9 seconds at 22") {
		t.Error("the comment of WriteWorkFactor does not give the cost at 22")
	}
}

// The check of the payload size in unwrapWith cannot be reached, and the line above it says so.
func TestTheUnreachableSizeCheckInUnwrapWithIsSaidToBeUnreachable(t *testing.T) {
	if _, err := os.Stat("age.go"); err != nil {
		t.Skip("no source beside the test")
	}
	_, _, fset, files := docOf(t)
	f := files["age.go"]
	var fn *ast.FuncDecl
	for _, d := range f.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok && fd.Name.Name == "unwrapWith" {
			fn = fd
		}
	}
	if fn == nil {
		t.Fatal("no unwrapWith")
	}
	var check *ast.IfStmt
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if is, ok := n.(*ast.IfStmt); ok {
			if be, ok := is.Cond.(*ast.BinaryExpr); ok && be.Op == token.GTR {
				if id, ok := be.Y.(*ast.Ident); ok && id.Name == "MaxKeyFileSize" {
					check = is
				}
			}
		}
		return true
	})
	if check == nil {
		t.Fatal("the check of the payload size is gone: the page says it stays")
	}
	line := fset.Position(check.Pos()).Line
	found := false
	for _, cg := range f.Comments {
		if fset.Position(cg.End()).Line == line-1 && strings.Contains(cg.Text(), "cannot be reached") {
			found = true
		}
	}
	if !found {
		t.Errorf("the line above the check (line %d) does not say that it cannot be reached", line)
	}
}
