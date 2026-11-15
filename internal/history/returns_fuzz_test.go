//go:build linux || darwin

package history

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
)

// FuzzRootReturnsLists takes bytes as the content of four root lists, in four trust sets whose
// numbers the fuzz bytes pick, and holds what is true of every report: no error, no panic, every
// text printable ASCII, every finding in the fixed order, and a finding of root-returns names a
// root list of a set that exists and has the form of the page.
func FuzzRootReturnsLists(f *testing.F) {
	seed := func(a, b, c, d []byte, pick uint8) { f.Add(a, b, c, d, pick) }
	l1 := rootsJSON(1, ent{"A", pa, f1}, ent{"B", pb, ""})
	l2 := rootsJSON(2, ent{"B", pb, ""})
	l3 := rootsJSON(3, ent{"A", pa, ""}, ent{"C", pc, f1})
	seed(l1, l2, l3, l3, 0)
	seed(l1, l2, []byte(`{`), l3, 1)
	seed(l3, l2, l1, l3, 2)
	seed([]byte(`{"roots":[{"label":"A`+string(rune(0x202e))+`","x509_spki_sha256":"`+pa+`"}],"sequence":-1}`), l2, l1, l1, 4)
	seed([]byte(`{"roots":[{"label":"A`+string(rune(0x202e))+`","x509_spki_sha256":"`+pa+`"}],"sequence":-1}`), l2, l1, l1, 4)
	seed([]byte{}, []byte{}, []byte{}, []byte{}, 5)
	f.Fuzz(func(t *testing.T, a, b, c, d []byte, pick uint8) {
		lists := [][]byte{a, b, c, d}
		files := map[string][]byte{}
		numbers := []int{9, 10, 11, 100}
		for i, l := range lists {
			// pick chooses a name with no number for one list, and gives two lists one number.
			n := numbers[(i+int(pick))%4]
			name := fmt.Sprintf("%d-aaaaaaa%d", n, i)
			if int(pick/4)%5 == i+1 {
				name = fmt.Sprintf("x-aaaaaaa%d", i)
			}
			if int(pick/32)%4 == i && i > 0 {
				name = fmt.Sprintf("%d-bbbbbbb%d", numbers[(i-1+int(pick))%4], i)
			}
			files[name] = l
		}
		rep, err := runMem(t, memBundle(files))
		if err != nil {
			t.Fatalf("Check: %v", err)
		}
		checkReport(t, rep)
		for _, f := range returnsOf(rep) {
			if !strings.HasPrefix(f.Detail, `root key "`) || !strings.Contains(f.Detail, `" returns`) || !strings.Contains(f.Detail, ": its ") {
				t.Fatalf("the detail of %q has not the form of the page", f.Line())
			}
			set := strings.TrimSuffix(strings.TrimPrefix(f.Path, "trust/"), "/root-list.json")
			if _, ok := files[set]; !ok || f.Path != listPathOf(set) {
				t.Fatalf("the path of %q is not the root list of a set", f.Line())
			}
			if len(f.Detail) > maxDetail+len("...") {
				t.Fatalf("a detail of %d bytes", len(f.Detail))
			}
		}
		if slices.Contains(rep.Reasons(), RootReturns) != (len(returnsOf(rep)) > 0) {
			t.Fatalf("Reasons() = %v and %d findings", rep.Reasons(), len(returnsOf(rep)))
		}
	})
}

// FuzzParseAnchor is the reader of the bytes of a root list: whatever the bytes are, it does not
// panic; a list it reads has at most 26 entries of roots, and no more keys than entries; every key
// has a pin or a fingerprint; a list it does not read has a problem that says so, no key and no
// entry counted against the limit of the run.
func FuzzParseAnchor(f *testing.F) {
	f.Add(rootsJSON(3, ent{"A", pa, f1}, ent{"B", pb, ""}))
	f.Add([]byte(`{"last_record_sha256":"` + digestA + `","roots":[],"version":1}`))
	f.Add([]byte(`{"roots":[{"label":"A","x509_spki_sha256":"` + strings.ToUpper(pa) + `","openpgp_fingerprint":"` + strings.ToUpper(f1) + `"}]}`))
	f.Add([]byte(`{"roots":[{"label":"` + strings.Repeat("A", 300) + `"}],"sequence":9007199254740991}`))
	f.Add([]byte(`{"roots":[{},{},{}],"unknown":{"a":[1,2,{"b":null}]}}`))
	f.Add([]byte(`{"roots":[[]]}`))
	f.Add([]byte(`{`))
	f.Add([]byte{})
	f.Add([]byte("\xef\xbb\xbf{}"))
	f.Add(rawList(rawEntry("A", pa, ""), rawEntry("B", "0x"+pb, ""), rawEntry("C", "", pairs(f1, ":"))))
	f.Add(rawList(rawEntry("A", pa, ""), rawEntry("B", "zz", "")))
	f.Add(rawList(rawEntry("A", " "+pa+"\n", f1+" ")))
	f.Add(rawList(`{"x509_spki_sha256":null}`, rawEntry("", "", f2)))
	f.Add(rawList(rawEntry("A", pa, ""), `{"label":"B"}`))
	f.Add(rawList(rawEntry("A", pa, ""), `{}`, rawEntry("C", pb, "")))
	f.Fuzz(func(t *testing.T, data []byte) {
		r := &reader{entriesLeft: 1 << 20, entryLimit: 1 << 20}
		a, err := r.parseAnchor(data)
		if err != nil || a == nil {
			t.Fatalf("parseAnchor = %v, %v", a, err)
		}
		if a.problem != "" {
			if !strings.HasPrefix(a.problem, "the root list cannot be read: ") || len(a.keys) != 0 || a.present || a.hasSequence {
				t.Fatalf("a problem with more in it: %+v", a)
			}
			if r.entriesLeft != 1<<20 {
				t.Fatalf("entries were counted for a list that cannot be read")
			}
			return
		}
		if len(a.keys) > MaxRootsPerList {
			t.Fatalf("%d keys", len(a.keys))
		}
		if used := 1<<20 - r.entriesLeft; used != len(a.keys) {
			t.Fatalf("%d entries counted for %d keys", used, len(a.keys))
		}
		for _, k := range a.keys {
			if len(k.label) > maxLabelShown+len("...") {
				t.Fatalf("a label of %d bytes", len(k.label))
			}
			if !k.hasPin && !k.hasFP {
				t.Fatalf("a key with no pin and no fingerprint: %+v", k)
			}
			if !k.hasPin && k.pin != [32]byte{} || !k.hasFP && k.fp != [20]byte{} {
				t.Fatalf("a member that is not there has bytes: %+v", k)
			}
		}
		// What the standard decoder says of the same bytes bounds the keys.
		var loose struct {
			Roots []json.RawMessage `json:"roots"`
		}
		if json.Unmarshal(data, &loose) == nil && len(a.keys) > len(loose.Roots) {
			t.Fatalf("%d keys from %d entries", len(a.keys), len(loose.Roots))
		}
		// The same bytes read again give the same result.
		b, err := (&reader{entriesLeft: 1 << 20, entryLimit: 1 << 20}).parseAnchor(data)
		if err != nil || fmt.Sprintf("%+v", a) != fmt.Sprintf("%+v", b) {
			t.Fatalf("a second read differs: %+v and %+v", a, b)
		}
	})
}

// FuzzHexForm is the reader of one pin or fingerprint. Whatever the text is, it does not panic. A
// text that has a character that no form allows is never read. A text that is read gives the
// bytes of the digits in it. A form written from bytes in the ways that the check allows is always
// read as those bytes.
func FuzzHexForm(f *testing.F) {
	f.Add(pa, 32, []byte{1, 2, 3})
	f.Add("0x"+pa, 32, []byte{0})
	f.Add(pairs(f1, ":"), 20, []byte{9, 9, 9, 9})
	f.Add(" "+f1+"\n", 20, []byte{255})
	f.Add("", 20, []byte{})
	f.Add("0x0X"+f1, 20, []byte{1})
	f.Add("g", 1, []byte{})
	f.Fuzz(func(t *testing.T, s string, n int, raw []byte) {
		if n < 1 || n > 64 {
			n = 32
		}
		b, ok := hexForm(s, n)
		if ok {
			if len(b) != n {
				t.Fatalf("%d bytes for %d", len(b), n)
			}
			var digits strings.Builder
			for _, r := range s {
				switch {
				case strings.ContainsRune("0123456789abcdefABCDEF", r):
					digits.WriteRune(r)
				case strings.ContainsRune(" \t\r\n:-xX", r):
				default:
					t.Fatalf("%q was read, and has the character %q", s, r)
				}
			}
			// The digits include the 0 of a prefix, so they are the bytes or the bytes with
			// one or two zeros in front.
			got := strings.ToLower(hex.EncodeToString(b))
			d := strings.ToLower(digits.String())
			if !strings.HasSuffix(d, got) || len(d)-len(got) > 2 {
				t.Fatalf("%q was read as %s, its digits are %s", s, got, d)
			}
		}
		// A text with a character no form allows is not read.
		for _, r := range s {
			if !strings.ContainsRune("0123456789abcdefABCDEFxX \t\r\n:-", r) && ok {
				t.Fatalf("%q was read", s)
			}
		}
		// A form made from bytes is read as the bytes.
		want := make([]byte, n)
		for i := range want {
			if len(raw) > 0 {
				want[i] = raw[i%len(raw)] ^ byte(i)
			}
		}
		h := hex.EncodeToString(want)
		var out strings.Builder
		pick := func(i int) byte {
			if len(raw) == 0 {
				return 0
			}
			return raw[i%len(raw)]
		}
		if pick(0)&1 != 0 {
			out.WriteString(" \t\r\n"[:int(pick(1))%5])
		}
		if pick(2)&1 != 0 {
			out.WriteString([]string{"0x", "0X"}[pick(3)&1])
		}
		for i := 0; i < len(h); i++ {
			if i > 0 && i%2 == 0 && pick(i)&3 == 0 {
				out.WriteString([]string{" ", ":", "-"}[int(pick(i+1))%3])
			}
			c := h[i]
			if pick(i+2)&1 != 0 && c >= 'a' && c <= 'f' {
				c -= 'a' - 'A'
			}
			out.WriteByte(c)
		}
		if pick(4)&1 != 0 {
			out.WriteString(" \t\r\n"[:int(pick(5))%5])
		}
		got, ok2 := hexForm(out.String(), n)
		if !ok2 || !bytes.Equal(got, want) {
			t.Fatalf("%q was read as %x, %v; want %x", out.String(), got, ok2, want)
		}
	})
}

// FuzzFindReturns takes bytes as the text of the pins and the fingerprints of up to five lists and
// holds what is true of every answer: no panic; a list that has an entry that cannot be read is
// refused with ErrRootKey, and a list that can be read gives returns in the order of its entries,
// each with a reason and each naming a holder that is another list; and when every list can be read
// the answers are those of the check on a bundle that has these lists in this order.
func FuzzFindReturns(f *testing.F) {
	f.Add([]byte{3, 1, 2, 0, 1, 2, 0, 1, 2, 0})
	f.Add([]byte{4, 1, 1, 1, 1, 2, 2, 1, 1, 1, 1, 1, 2, 1, 1, 1, 1, 1})
	f.Add([]byte("\x05\x01\xffpin text\x00\x02\x03\x04"))
	f.Add(append([]byte{2, 1, 5, 0}, []byte(pa+f1)...))
	f.Fuzz(func(t *testing.T, data []byte) {
		pos := 0
		next := func() int {
			if pos >= len(data) {
				return 0
			}
			pos++
			return int(data[pos-1])
		}
		pins := []string{"", pinOf(1), pinOf(2), strings.ToUpper(pinOf(1)), "0x" + pinOf(2), pairs(pinOf(3), ":")}
		fps := []string{"", fpOf(1), fpOf(2), strings.ToUpper(fpOf(1)), " " + fpOf(2) + "\n", pairs(fpOf(1), "-")}
		text := func(pool []string) string {
			b := next()
			if b < len(pool) {
				return pool[b]
			}
			end := min(len(data), pos+b%9)
			s := string(data[pos:end])
			pos = end
			return s
		}
		var lists []RootList
		for i, n := 0, 1+next()%5; i < n; i++ {
			l := RootList{Name: fmt.Sprintf("set-%d", i+1)}
			if next()%9 == 0 {
				l.Unreadable = true
			}
			for k, c := 0, next()%4; k < c; k++ {
				l.Keys = append(l.Keys, RootKey{Label: fmt.Sprintf("L%dE%d", i, k), Pin: text(pins), Fingerprint: text(fps)})
			}
			lists = append(lists, l)
		}
		allRead := true
		for i, l := range lists {
			got, err := FindReturns(lists[:i], l)
			_, kerr := keysOf(l.Keys)
			switch {
			case l.Unreadable:
				if err != nil || got != nil {
					t.Fatalf("an unreadable list: %v, %v", got, err)
				}
			case kerr != nil:
				allRead = false
				if !errors.Is(err, ErrRootKey) || got != nil {
					t.Fatalf("a list with an entry that cannot be read: %v, %v", got, err)
				}
			case err != nil:
				t.Fatalf("a list that can be read: %v", err)
			}
			last := -1
			for _, r := range got {
				if r.Entry <= last || r.Entry >= len(l.Keys) || (!r.ByPin && !r.ByFingerprint) {
					t.Fatalf("a return %+v of list %d", r, i)
				}
				last = r.Entry
				if r.ByPin && (r.PinHeldOn == "" || r.PinHeldOn == l.Name) || r.ByFingerprint && (r.FingerprintHeldOn == "" || r.FingerprintHeldOn == l.Name) {
					t.Fatalf("a return %+v names no other list", r)
				}
			}
		}
		if !allRead {
			return
		}
		// The check on a bundle with these lists, in this order.
		var cs []cset
		for i, l := range lists {
			cs = append(cs, cset{setN(i + 1), jsonOfList(l)})
		}
		rep := runChain(t, cs...)
		byPath := map[string][]string{}
		for _, fd := range returnsOf(rep) {
			label := labelOfDetail(fd.Detail)
			byPath[fd.Path] = append(byPath[fd.Path], fmt.Sprintf("%s pin=%v fp=%v", label,
				strings.Contains(fd.Detail, "its pin "), strings.Contains(fd.Detail, "OpenPGP fingerprint")))
			if strings.HasSuffix(fd.Detail, "...") {
				return // a reason may be cut away from a long detail
			}
		}
		for i, l := range lists {
			got, _ := FindReturns(lists[:i], l)
			var gotS []string
			for _, r := range got {
				gotS = append(gotS, fmt.Sprintf("%s pin=%v fp=%v", l.Keys[r.Entry].Label, r.ByPin, r.ByFingerprint))
			}
			wantS := byPath[listPathOf(setN(i+1))]
			slices.Sort(gotS)
			slices.Sort(wantS)
			if !slices.Equal(gotS, wantS) {
				t.Fatalf("list %d: FindReturns %v, the check %v", i+1, gotS, wantS)
			}
		}
	})
}

// jsonOfList writes a RootList as the text of a root list file. A text is written as a JSON string,
// whatever it holds.
func jsonOfList(l RootList) []byte {
	if l.Unreadable {
		return []byte(`{`)
	}
	type entry struct {
		Label       string `json:"label,omitempty"`
		Pin         string `json:"x509_spki_sha256,omitempty"`
		Fingerprint string `json:"openpgp_fingerprint,omitempty"`
	}
	list := struct {
		Roots   []entry `json:"roots"`
		Version int     `json:"version"`
	}{Roots: []entry{}, Version: 1}
	for _, k := range l.Keys {
		list.Roots = append(list.Roots, entry(k))
	}
	b, err := json.Marshal(list)
	if err != nil {
		panic(err)
	}
	return b
}
