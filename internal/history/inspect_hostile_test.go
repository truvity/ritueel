//go:build linux || darwin

package history

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"

	"ritueel.id/ritueel/internal/fsx"
)

// Hostile input for Inspect: size, count, depth, wrong types, bytes that are not UTF-8, links, pipes
// and folders in place of files, a cancelled context, a read that fails. In every case Inspect ends,
// never panics, says the same as Check, returns nothing half built, and gives no State unless the
// report is clean and the order is sure.

// inspectLimited runs the walk of Inspect with lowered limits and the same keeping of bytes.
func inspectLimited(t testing.TB, fsys fsx.FS, lim limits) error {
	t.Helper()
	_, err := runCheck(context.Background(), fsys, lim, true)
	return err
}

func baseLimits() limits {
	return limits{readBytes: MaxReadBytes, fileReads: MaxFileReads, perCode: MaxFindingsPerCode}
}

// A nil file system, as for Check.
func TestInspectNilFileSystem(t *testing.T) {
	in, err := Inspect(context.Background(), nil)
	if !errors.Is(err, fsx.ErrNoRoot) || in != nil {
		t.Errorf("Inspect(nil) = %v, %v; want fsx.ErrNoRoot and no Inspection", in, err)
	}
}

// A context that ended before the run, and a context that ends during it, at every read: an error,
// no Inspection, and never a State from half a walk.
func TestInspectCancelledContext(t *testing.T) {
	b := numbered(t, true, 4)
	b.unfinished(withSet(setN(5), keyList(5, kA)))
	t.Run("before the run", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		in, err := Inspect(ctx, memFS{b.mem})
		if !errors.Is(err, context.Canceled) || in != nil {
			t.Errorf("Inspect = %v, %v; want context.Canceled and no Inspection", in, err)
		}
	})
	t.Run("a deadline that has passed", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 0)
		defer cancel()
		in, err := Inspect(ctx, memFS{b.mem})
		if !errors.Is(err, context.DeadlineExceeded) || in != nil {
			t.Errorf("Inspect = %v, %v", in, err)
		}
	})
	t.Run("at each read", func(t *testing.T) {
		total := countCalls(t, memFS{b.mem})
		if total < 10 {
			t.Fatalf("only %d calls", total)
		}
		ended := 0
		for n := 1; n <= total+1; n++ {
			ctx, cancel := context.WithCancel(context.Background())
			in, err := Inspect(ctx, &cancelAfter{FS: memFS{b.mem}, cancel: cancel, after: n, calls: new(int)})
			cancel()
			switch {
			case err != nil:
				ended++
				if !errors.Is(err, context.Canceled) || in != nil {
					t.Fatalf("after %d calls: Inspect = %v, %v", n, in, err)
				}
			case in == nil || in.State == nil:
				t.Fatalf("after %d calls: no error and no State: %v", n, in)
			}
		}
		if ended == 0 {
			t.Error("no run ended with the context")
		}
	})
}

// cancelAfter cancels a context at the nth call of ReadFile, OpenDir or ReadDir, and counts calls.
type cancelAfter struct {
	fsx.FS
	cancel func()
	after  int
	calls  *int
}

func (c *cancelAfter) tick() {
	*c.calls++
	if *c.calls == c.after {
		c.cancel()
	}
}

func (c *cancelAfter) ReadFile(name string) ([]byte, error) {
	c.tick()
	return c.FS.ReadFile(name)
}

func (c *cancelAfter) ReadDir() ([]fs.DirEntry, error) {
	c.tick()
	return c.FS.ReadDir()
}

func (c *cancelAfter) OpenDir(name string) (fsx.FS, error) {
	c.tick()
	d, err := c.FS.OpenDir(name)
	if err != nil {
		return nil, err
	}
	return &cancelAfter{FS: d, cancel: c.cancel, after: c.after, calls: c.calls}, nil
}

// countCalls counts the calls that one Inspect makes.
func countCalls(t testing.TB, fsys fsx.FS) int {
	t.Helper()
	n := new(int)
	in, err := Inspect(context.Background(), &cancelAfter{FS: fsys, cancel: func() {}, after: -1, calls: n})
	if err != nil || in == nil {
		t.Fatalf("Inspect: %v, %v", in, err)
	}
	return *n
}

// A read that fails ends the run with the error: the bundle was not inspected. It is never a
// finding and never a State.
func TestInspectAReadThatFailsIsAnError(t *testing.T) {
	boom := errors.New("input or output error")
	for _, where := range []string{
		listPathOf(setN(3)),
		listPathOf(setN(1)),
		"history/" + numbered(t, true, 3).recs[1].folder + "/record.json",
		"history",
		"trust",
	} {
		t.Run(where, func(t *testing.T) {
			b := numbered(t, true, 3)
			if n := b.mem.get(where); n != nil {
				n.readErr = boom
			} else {
				// A path with the folder name of this bundle's own ceremony.
				path := "history/" + b.recs[1].folder + "/record.json"
				b.mem.get(path).readErr = boom
			}
			in, err := inspectFS(t, memFS{b.mem})
			if !errors.Is(err, boom) || in != nil {
				t.Errorf("Inspect = %v, %v; want the error of the read and no Inspection", in, err)
			}
		})
	}
}

// The limits of Check hold for Inspect: ErrTooMuch and no Inspection, never a report that is clean.
func TestInspectLimitsOfCheckHold(t *testing.T) {
	t.Run("the entries of roots, with the limit of the package", func(t *testing.T) {
		m := manyEntries(MaxRootEntries + 1)
		in, err := inspectFS(t, memFS{m})
		if !errors.Is(err, ErrTooMuch) || in != nil {
			t.Errorf("Inspect = %v, %v; want ErrTooMuch and no Inspection", in, err)
		}
	})
	t.Run("exactly the entries of the limit", func(t *testing.T) {
		m := manyEntries(MaxRootEntries)
		in, err := inspectFS(t, memFS{m})
		if err != nil || in == nil || in.State != nil {
			t.Fatalf("Inspect = %v, %v", in, err)
		}
		want, err := runMem(t, m)
		if err != nil {
			t.Fatal(err)
		}
		sameReport(t, in.Report, want)
		if want.Omitted == 0 {
			t.Error("the bundle was meant to have findings that are not shown")
		}
	})
	t.Run("the entries of roots, lowered", func(t *testing.T) {
		b := numbered(t, true, 3)
		lim := baseLimits()
		lim.rootEntries = 2
		if err := inspectLimited(t, memFS{b.mem}, lim); !errors.Is(err, ErrTooMuch) {
			t.Errorf("err = %v", err)
		}
		lim.rootEntries = 3
		if err := inspectLimited(t, memFS{b.mem}, lim); err != nil {
			t.Errorf("at the limit: %v", err)
		}
	})
	t.Run("the places, lowered", func(t *testing.T) {
		b := placesBundle(t, 3, 3)
		lim := baseLimits()
		lim.setPlaces = 8
		if err := inspectLimited(t, memFS{b.mem}, lim); !errors.Is(err, ErrTooMuch) {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("the bytes read, lowered", func(t *testing.T) {
		b := numbered(t, true, 3)
		lim := baseLimits()
		lim.readBytes = 100
		if err := inspectLimited(t, memFS{b.mem}, lim); !errors.Is(err, ErrTooMuch) {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("the files listed, lowered", func(t *testing.T) {
		b := numbered(t, true, 3)
		lim := baseLimits()
		lim.fileReads = 2
		if err := inspectLimited(t, memFS{b.mem}, lim); !errors.Is(err, ErrTooMuch) {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("the names looked at, lowered", func(t *testing.T) {
		b := numbered(t, true, 3)
		lim := baseLimits()
		lim.walkEntries = 3
		if err := inspectLimited(t, memFS{b.mem}, lim); !errors.Is(err, ErrTooMuch) {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("a folder of too many names", func(t *testing.T) {
		b := numbered(t, true, 2)
		for i := 0; i <= fsx.MaxDirEntries; i++ {
			b.mem.get("history").kids[fmt.Sprintf("n%06d", i)] = &mnode{kind: "dir", kids: map[string]*mnode{}}
		}
		in, err := inspectFS(t, memFS{b.mem})
		if err == nil || in != nil {
			t.Errorf("Inspect = %v, %v; want an error", in, err)
		}
	})
}

// manyEntries is a bundle of root lists that hold total entries in all, 26 for each list.
func manyEntries(total int) *mnode {
	lists := map[string][]byte{}
	left, i := total, 1
	for left > 0 {
		k := min(26, left)
		es := make([]ent, k)
		for j := range es {
			es[j] = ent{"A", pinOf(100000 + i*26 + j), ""}
		}
		lists[setN(i)] = rootsJSON(0, es...)
		left -= k
		i++
	}
	return memBundle(lists)
}

// A root list of 250,000 bytes is read: a list that can be read has at most 256 KiB. A State keeps
// the bytes of the lists that it read, up to MaxStateBytes in all.
func TestInspectKeepsTheBytesOfALargeNewestList(t *testing.T) {
	pad := strings.Repeat("x", 250000)
	big := func(seq int64) []byte {
		return []byte(fmt.Sprintf(`{"pad":%q,"roots":[{"label":"A","x509_spki_sha256":%q}],"sequence":%d,"version":1}`, pad, pa, seq))
	}
	b := chainBundle(t, true, cset{setN(1), big(1)}, cset{setN(2), big(2)})
	in := b.inspect()
	st := wantState(t, in, setN(1), setN(2))
	if !bytes.Equal(st.Newest.ListJSON, b.mem.get(listPathOf(setN(2))).data) {
		t.Error("ListJSON is not the file")
	}
}

// A root list that is larger than 256 KiB cannot be read (anchor-unknown): no State, whatever its
// size, and the same report as Check.
func TestInspectAListThatIsTooLargeToReadHasNoState(t *testing.T) {
	for _, size := range []int{256 << 10, 300 << 10, fsx.MaxReadSize} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			pad := strings.Repeat("x", size)
			list := []byte(`{"pad":"` + pad + `","roots":[],"sequence":2,"version":1}`)
			b := chainBundle(t, true, cset{setN(1), keyList(1, kA)}, cset{setN(2), list})
			in := b.inspect()
			if in.State != nil || in.Report.Clean() {
				t.Errorf("State %v, clean %v", in.State, in.Report.Clean())
			}
			has(t, in.Report, AnchorUnknown, listPathOf(setN(2)))
		})
	}
	t.Run("longer than 8 MiB", func(t *testing.T) {
		b := numbered(t, true, 2)
		b.mem.get(listPathOf(setN(2))).long = true
		in := b.inspect()
		if in.State != nil || in.Report.Clean() {
			t.Errorf("State %v, clean %v", in.State, in.Report.Clean())
		}
	})
}

// The bytes that a State keeps are bounded by MaxStateBytes, in all the root lists of a walk. When
// the lists that the walk read come to exactly that many bytes the newest list is kept, and one list
// more makes the newest list one that was not kept: a clean bundle then ends with ErrTooMuch and no
// Inspection, where Check of the same bundle is clean.
func TestInspectTheBytesThatAStateKeepsAreBoundedExactly(t *testing.T) {
	if testing.Short() {
		t.Skip("builds 64 MiB of root lists")
	}
	const each = 256 << 10
	n := MaxStateBytes / each
	if n*each != MaxStateBytes {
		t.Fatalf("MaxStateBytes %d is not a whole number of lists of 256 KiB", MaxStateBytes)
	}
	// The anchors of these lists are made by the builder: every list but the first has the anchor
	// that the builder puts in, so build the sets with lists that are exactly full after it.
	b := chainBundle(t, true)
	for i := 1; i <= n; i++ {
		i := i
		b.apply(func(r *rec) {
			delete(r.artifacts, "trust/"+r.set+"/root-list.json")
			delete(r.artifacts, "trust/"+r.set+"/keys.txt")
			r.set = setN(i)
			sk := func(pad int) []byte {
				return []byte(fmt.Sprintf(`{"pad":"%s","roots":[{"label":"A","x509_spki_sha256":%q}],"sequence":%d,"version":1}`, strings.Repeat("x", pad), pa, i))
			}
			list := anchored(sk(0), r.record.PrevRecordSHA256)
			list = anchored(sk(each-len(list)), r.record.PrevRecordSHA256)
			if len(list) != each {
				t.Fatalf("the list %d has %d bytes", i, len(list))
			}
			r.artifacts["trust/"+r.set+"/root-list.json"] = list
			r.artifacts["trust/"+r.set+"/keys.txt"] = []byte("keys")
			r.refresh()
		})
	}
	want, err := runMem(t, b.mem)
	if err != nil || !want.Clean() {
		t.Fatalf("Check = %v, %v; the bundle is meant to be clean", want, err)
	}
	t.Run("exactly the bytes of the budget", func(t *testing.T) {
		in, err := inspectFS(t, memFS{b.mem})
		if err != nil || in == nil || in.State == nil {
			t.Fatalf("Inspect = %v, %v", in, err)
		}
		if got := len(in.State.Newest.ListJSON); got != each {
			t.Errorf("the newest list has %d bytes, want %d", got, each)
		}
		if !bytes.Equal(in.State.Newest.ListJSON, b.mem.get(listPathOf(setN(n))).data) {
			t.Error("ListJSON is not the file")
		}
	})
	t.Run("one list more", func(t *testing.T) {
		b.apply(withSet(setN(n+1), keyList(int64(n+1), kA)))
		in, err := inspectFS(t, memFS{b.mem})
		if !errors.Is(err, ErrTooMuch) || in != nil {
			t.Errorf("Inspect = %v, %v; want ErrTooMuch and no Inspection", in, err)
		}
		if rep, cerr := runMem(t, b.mem); cerr != nil || !rep.Clean() {
			t.Errorf("Check = %v, %v; want a clean report", rep, cerr)
		}
	})
}

// Root lists that are bytes of every kind of hostile form: each one makes the report fail (the list
// cannot be read), and there is no State and no OrderErr.
func TestInspectHostileRootLists(t *testing.T) {
	deep := strings.Repeat("[", 20000) + strings.Repeat("]", 20000)
	lists := map[string]string{
		"not JSON":                       `{`,
		"empty":                          ``,
		"a number":                       `5`,
		"null":                           `null`,
		"an array":                       `[]`,
		"roots is a string":              `{"roots":"A","sequence":2,"version":1}`,
		"roots is an object":             `{"roots":{},"sequence":2,"version":1}`,
		"an entry is a string":           `{"roots":["A"],"sequence":2,"version":1}`,
		"an entry is null":               `{"roots":[null],"sequence":2,"version":1}`,
		"a pin that is a number":         `{"roots":[{"label":"A","x509_spki_sha256":5}],"sequence":2,"version":1}`,
		"a pin that is too short":        `{"roots":[{"label":"A","x509_spki_sha256":"abcd"}],"sequence":2,"version":1}`,
		"a pin that is not hex":          `{"roots":[{"label":"A","x509_spki_sha256":"` + strings.Repeat("zz", 32) + `"}],"sequence":2,"version":1}`,
		"an entry with no key":           `{"roots":[{"label":"A"}],"sequence":2,"version":1}`,
		"a label that is a number":       `{"roots":[{"label":5,"x509_spki_sha256":"` + pa + `"}],"sequence":2,"version":1}`,
		"a sequence that is a string":    `{"roots":[],"sequence":"2","version":1}`,
		"a sequence that is a float":     `{"roots":[],"sequence":2.5,"version":1}`,
		"a sequence in an exponent":      `{"roots":[],"sequence":2e0,"version":1}`,
		"a sequence beyond 2^53":         `{"roots":[],"sequence":9007199254740993,"version":1}`,
		"a sequence of 40 digits":        `{"roots":[],"sequence":` + strings.Repeat("9", 40) + `,"version":1}`,
		"the same member twice":          `{"roots":[],"roots":[],"sequence":2,"version":1}`,
		"the anchor twice":               `{"last_record_sha256":"` + digestA + `","last_record_sha256":"` + digestA + `","roots":[],"sequence":2,"version":1}`,
		"a byte order mark":              "\xef\xbb\xbf" + `{"roots":[],"sequence":2,"version":1}`,
		"a label that is not UTF-8":      "{\"roots\":[{\"label\":\"\xff\",\"x509_spki_sha256\":\"" + pa + "\"}],\"sequence\":2,\"version\":1}",
		"a name that is not UTF-8":       "{\"\xff\":1,\"roots\":[],\"sequence\":2,\"version\":1}",
		"a control byte in a string":     "{\"pad\":\"\x01\",\"roots\":[],\"sequence\":2,\"version\":1}",
		"nested arrays 20,000 deep":      `{"pad":` + deep + `,"roots":[],"sequence":2,"version":1}`,
		"27 entries":                     `{"roots":[` + strings.TrimSuffix(strings.Repeat(`{"label":"A","x509_spki_sha256":"`+pa+`"},`, 27), ",") + `],"sequence":2,"version":1}`,
		"text after the object":          `{"roots":[],"sequence":2,"version":1} x`,
		"a pin with a null byte":         "{\"roots\":[{\"label\":\"A\",\"x509_spki_sha256\":\"" + pa[:60] + "\\u0000ab\"}],\"sequence\":2,\"version\":1}",
		"the anchor is not a digest":     `{"last_record_sha256":"zz","roots":[],"sequence":2,"version":1}`,
		"an anchor in capitals":          `{"last_record_sha256":"` + strings.ToUpper(digestA) + `","roots":[],"sequence":2,"version":1}`,
		"an entry with an empty pin":     `{"roots":[{"label":"A","x509_spki_sha256":""}],"sequence":2,"version":1}`,
		"an entry with an empty label":   `{"roots":[{"label":"","x509_spki_sha256":""}],"sequence":2,"version":1}`,
		"an object where roots belongs":  `{"roots":[[]],"sequence":2,"version":1}`,
		"a very long label":              `{"roots":[{"label":"` + strings.Repeat("A", 100000) + `","x509_spki_sha256":""}],"sequence":2,"version":1}`,
		"an entry with a fingerprint 41": `{"roots":[{"label":"A","openpgp_fingerprint":"` + strings.Repeat("a", 41) + `"}],"sequence":2,"version":1}`,
	}
	names := make([]string, 0, len(lists))
	for n := range lists {
		names = append(names, n)
	}
	slices.Sort(names)
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			b := chainBundle(t, true, cset{setN(1), keyList(1, kA)}, cset{setN(2), []byte(lists[name])})
			in := b.inspect()
			if in.State != nil {
				t.Fatalf("a State for a root list that Check refuses: %q", name)
			}
			if in.Report.Clean() && in.OrderErr == nil {
				t.Error("clean with no OrderErr")
			}
		})
	}
}

// Hostile root lists that Check accepts: unknown members, odd white space, a different form of the
// pin. They give a State, and the State is what the walk read.
func TestInspectOddButAcceptedRootLists(t *testing.T) {
	lists := map[string]string{
		"an unknown member":     `{"zz":"hello","roots":[],"sequence":2,"version":1}`,
		"white space around":    "{ \n\"roots\" : [ ],\"sequence\":2,\"version\":1}\n\t ",
		"an unknown nested one": `{"zz":{"a":[1,2,{"b":true}]},"roots":[],"sequence":2,"version":1}`,
		"two unknown members":   `{"roots":[],"sequence":2,"version":1,"x":1}`,
	}
	for name, l := range lists {
		t.Run(name, func(t *testing.T) {
			b := chainBundle(t, true, cset{setN(1), keyList(1, kA)}, cset{setN(2), []byte(l)})
			in := b.inspect()
			if in.State == nil {
				t.Fatalf("no State: %v %v", findingsOf(in.Report), in.OrderErr)
			}
			if got, want := in.State.Newest.ListJSON, b.mem.get(listPathOf(setN(2))).data; !bytes.Equal(got, want) {
				t.Errorf("ListJSON %q, file %q", got, want)
			}
		})
	}
}

// What stands in place of a file or a folder of the bundle: a link, a pipe, a folder, a file that
// is too large. The report is the report of Check, there is no State, and nothing waits.
func TestInspectWhatStandsInPlaceOfAFile(t *testing.T) {
	kinds := []string{"link", "fifo", "dir", "file"}
	places := func(b *bundle) []string {
		return []string{
			listPathOf(setN(2)),
			"history/" + b.recs[1].folder + "/record.json",
			"history/" + b.recs[1].folder + "/plan.json",
			"history/" + b.recs[1].folder + "/attempt.json",
			"history/" + b.recs[1].folder + "/transcript.txt",
			"history/" + b.recs[1].folder + "/wanted",
			"history/" + b.recs[1].folder,
			"trust/" + setN(2),
			"trust/" + setN(2) + "/keys.txt",
			"history",
			"trust",
		}
	}
	probe := numbered(t, true, 3)
	for _, kind := range kinds {
		for _, where := range places(probe) {
			t.Run(kind+" at "+where, func(t *testing.T) {
				b := numbered(t, true, 3)
				n := &mnode{kind: kind, data: []byte("{}")}
				if kind == "dir" {
					n.kids = map[string]*mnode{"x": {kind: "file", data: []byte("{}")}}
				}
				b.mem.put(where, n)
				in, err := inspectFS(t, memFS{b.mem})
				if err != nil {
					// A bundle that is not a bundle, for a history that is no folder: the same as Check.
					if _, cerr := runFS(t, memFS{b.mem}, nil); cerr == nil || in != nil {
						t.Fatalf("Inspect = %v, %v; Check = %v", in, err, cerr)
					}
					return
				}
				want, cerr := runFS(t, memFS{b.mem}, nil)
				if cerr != nil {
					t.Fatalf("Check: %v", cerr)
				}
				sameReport(t, in.Report, want)
				checkInspection(t, in)
				if in.State != nil && !in.Report.Clean() {
					t.Error("State with a failing report")
				}
			})
		}
	}
}

// What stands in place of a file is a failing finding: no State, whatever kind of thing it is. A file
// of the kind that a ceremony folder or a set may hold, as a link, is not read.
func TestInspectALinkInPlaceOfTheRootListHasNoState(t *testing.T) {
	for _, kind := range []string{"link", "fifo", "dir"} {
		t.Run(kind, func(t *testing.T) {
			b := numbered(t, true, 3)
			b.mem.put(listPathOf(setN(3)), &mnode{kind: kind, kids: map[string]*mnode{}})
			in := b.inspect()
			if in.State != nil || in.Report.Clean() {
				t.Errorf("State %v, clean %v", in.State, in.Report.Clean())
			}
		})
	}
	t.Run("on disk", func(t *testing.T) {
		b := numbered(t, false, 3)
		b.remove(listPathOf(setN(3)))
		b.symlink("../"+setN(1)+"/root-list.json", listPathOf(setN(3)))
		in := b.inspect()
		if in.State != nil || in.Report.Clean() {
			t.Errorf("State %v, clean %v", in.State, in.Report.Clean())
		}
	})
	t.Run("a fifo on disk is not waited on", func(t *testing.T) {
		probe := numbered(t, false, 3)
		for _, where := range []string{
			listPathOf(setN(3)),
			"trust/" + setN(3),
			"history/" + probe.recs[2].folder,
			"history/" + probe.recs[2].folder + "/record.json",
			"history/" + probe.recs[2].folder + "/attempt.json",
		} {
			b := numbered(t, false, 3)
			b.remove(where)
			b.fifo(where)
			in := b.inspect()
			if in.State != nil || in.Report.Clean() {
				t.Errorf("a fifo at %s: State %v, clean %v", where, in.State, in.Report.Clean())
			}
		}
	})
	t.Run("a link to a folder outside the bundle in place of trust", func(t *testing.T) {
		b := numbered(t, false, 2)
		outside := t.TempDir()
		b.remove("trust")
		b.symlink(outside, "trust")
		in, err := inspectFS(t, mustOpen(t, b.dir))
		if err == nil && (in == nil || in.State != nil) {
			t.Errorf("Inspect = %v, %v", in, err)
		}
	})
}

func mustOpen(t testing.TB, dir string) fsx.FS {
	t.Helper()
	root, err := fsx.OpenFS(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	return root
}

// A name that breaks the rule for names (record 0006, rule 38) never reaches the State: a folder of
// history/ with such a name is not read, is a finding, and so there is no State. A name that is
// allowed does reach Unfinished, as it is.
func TestInspectHostileNamesNeverReachTheState(t *testing.T) {
	for _, h := range hostileNames() {
		for _, where := range []string{"history", "trust"} {
			t.Run(h.label+" in "+where, func(t *testing.T) {
				b := numbered(t, true, 2)
				// The entry holds an attempt, as an open ceremony does.
				b.mem.put(where+"/"+h.name+"/attempt.json", &mnode{kind: "file", data: []byte("{}")})
				b.mem.put(where+"/"+h.name+"/root-list.json", &mnode{kind: "file", data: keyList(9, kA)})
				in := b.inspect()
				if h.class == "invalid" && in.State != nil {
					t.Errorf("a State with the name %q (%s) in %s", h.name, h.label, where)
				}
				if h.class == "temp" && in.State != nil {
					if got := namesOfLists(in.State); slices.Contains(got, h.name) {
						t.Errorf("the lists hold the temporary name %q", h.name)
					}
				}
				if in.State != nil && h.class != "valid" {
					for _, u := range in.State.Unfinished {
						if strings.Contains(u, h.name) {
							t.Errorf("Unfinished holds %q", u)
						}
					}
				}
			})
		}
	}
}

// Many concurrent runs on one file system give the same answer and share nothing. The goroutines
// start behind a closed channel and are joined with a wait group.
func TestInspectConcurrentRunsAgree(t *testing.T) {
	b := numbered(t, true, 6)
	b.unfinished(withSet(setN(7), keyList(7, kA)))
	fsys := memFS{b.mem}
	const workers = 16
	start := make(chan struct{})
	results := make([]*Inspection, workers)
	errs := make([]error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			results[i], errs[i] = Inspect(context.Background(), fsys)
		}()
	}
	close(start)
	wg.Wait()
	for i := range results {
		if errs[i] != nil || results[i] == nil || results[i].State == nil {
			t.Fatalf("run %d: %v, %v", i, results[i], errs[i])
		}
		if !reflect.DeepEqual(results[i], results[0]) {
			t.Errorf("run %d differs from run 0", i)
		}
	}
	// A change of one result does not change another.
	results[0].State.Newest.ListJSON[0] = 'x'
	results[0].State.Lists[0].Name = "changed"
	if results[1].State.Newest.ListJSON[0] != '{' || results[1].State.Lists[0].Name != setN(1) {
		t.Error("two runs share memory")
	}
}

// A long chain: the order of 300 ceremonies whose names run against the chain.
func TestInspectALongChainInTheOrderOfTheChain(t *testing.T) {
	const n = 300
	sets := make([]cset, n)
	names := make([]string, n)
	for i := range sets {
		num := 5000 - 3*i
		names[i] = setN(num)
		sets[i] = cset{names[i], keyList(int64(num), kA)}
	}
	b := chainBundle(t, true, sets...)
	st := wantState(t, b.inspect(), names...)
	if st.Records != n || st.End != b.recs[n-1].digest {
		t.Errorf("Records %d, End %s", st.Records, st.End)
	}
}

// Many open attempts in one bundle: the names come out in order, once each.
func TestInspectManyUnfinishedAreSortedOnce(t *testing.T) {
	b := newBundle(t)
	var want []string
	for i := 0; i < 40; i++ {
		u := b.unfinished(noSet)
		want = append(want, u.folder)
	}
	in := b.inspect()
	if in.State == nil {
		t.Fatalf("no State: %v %v", in.OrderErr, findingsOf(in.Report))
	}
	slices.Sort(want)
	if !slices.Equal(in.State.Unfinished, want) {
		t.Errorf("Unfinished = %v\n want %v", in.State.Unfinished, want)
	}
}
