//go:build linux || darwin

package history

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"
)

// FuzzSetPlaces makes a bundle in memory from bytes: a few trust sets, a few records, each record
// listing the sets that a byte picks, some records following the record before the one before
// them (a fork), and a limit of the places. The model counts the places by itself: a set stands
// at one place for each different record before a record that lists it. A run with a limit below
// the count ends with ErrTooMuch and no report; a run with a limit at or above it ends with a
// report, which is the report of the run with the default limit: nothing floats and nothing is
// dropped below the limit.
func FuzzSetPlaces(f *testing.F) {
	f.Add([]byte{3, 4, 5, 7, 7, 7, 7, 0, 0, 0, 0})
	f.Add([]byte{1, 1, 1, 1, 0})
	f.Add([]byte{5, 7, 19, 31, 31, 31, 31, 31, 31, 31, 255, 255, 255})
	f.Add([]byte{2, 6, 6, 3, 3, 3, 3, 3, 3, 1, 1, 1, 1, 1, 1})
	f.Add([]byte{4, 5, 3, 15, 8, 4, 2, 1, 0, 0, 0, 0, 0})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) < 3 {
			t.Skip()
		}
		sets := 1 + int(data[0])%5
		records := 1 + int(data[1])%7
		limit := 1 + int(data[2])%24
		rest := data[3:]
		next := func() byte {
			if len(rest) == 0 {
				return 0
			}
			b := rest[0]
			rest = rest[1:]
			return b
		}
		b := chainBundle(t, true)
		var digests []string
		places := map[string]bool{}
		for i := 0; i < records; i++ {
			mask, fork := next(), next()%4 == 0
			prevDigest := ""
			if i > 0 {
				prevDigest = digests[i-1]
			}
			var cs []cset
			for s := 0; s < sets; s++ {
				if mask&(1<<s) != 0 {
					cs = append(cs, cset{setN(s + 1), seqList(strconv.Itoa(s+1), kA)})
				}
			}
			var r *rec
			if fork && i >= 2 {
				prevDigest = digests[i-2]
				r = b.apply(prev(prevDigest), withBytes(cs))
			} else {
				r = b.apply(withBytes(cs))
			}
			digests = append(digests, r.digest)
			for _, c := range cs {
				places[c.name+"|"+prevDigest] = true
			}
		}
		want, err := runMem(t, b.mem)
		if err != nil {
			t.Fatalf("the default limit: %v", err)
		}
		rep, err := runPlaces(t, b, limit)
		if n := len(places); n > limit {
			if !errors.Is(err, ErrTooMuch) || rep != nil {
				t.Fatalf("%d places and a limit of %d: Check = %v, %v", n, limit, rep, err)
			}
			if got := err.Error(); !strings.Contains(got, "MaxSetPlaces") || !strings.Contains(got, fmt.Sprint(limit)) {
				t.Fatalf("the sentence %q does not name the limit %d", got, limit)
			}
			return
		}
		if err != nil || rep == nil {
			t.Fatalf("%d places and a limit of %d: Check = %v, %v", len(places), limit, rep, err)
		}
		if fmt.Sprint(rep.Findings) != fmt.Sprint(want.Findings) || rep.Records != want.Records || rep.Omitted != want.Omitted {
			t.Fatalf("at a limit of %d the report is not the one of the default limit:\n%v\n%v", limit, rep.Findings, want.Findings)
		}
	})
}
