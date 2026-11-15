package cards_test

import (
	"fmt"
	"runtime"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/wanted"
)

// The worst case of one Inspect is the most card files (64) of the most bytes each (256 KiB): the report keeps
// the bytes of each file, so it holds about 16 MiB. The test measures it and holds it under twice that.
func TestTheLargestSetHoldsAboutSixteenMebibytes(t *testing.T) {
	files := map[string]string{}
	for i := range wanted.MaxCards {
		head := cardText(fmt.Sprint(i+1), "server")
		line := "# " + strings.Repeat("x", 56) + "\n"
		rest := wanted.MaxBytes - len(head)
		text := head + strings.Repeat(line, (rest-2)/len(line)) + "#"
		text += strings.Repeat("y", wanted.MaxBytes-len(text)-1) + "\n"
		if len(text) != wanted.MaxBytes {
			t.Fatalf("the test file has %d bytes", len(text))
		}
		files[fmt.Sprintf("want/cards/c%04d.yaml", i)] = text
	}
	n := memBundle(files)
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	rep := mustInspect(t, n.open(nil))
	runtime.GC()
	runtime.ReadMemStats(&after)
	held := int64(after.HeapAlloc) - int64(before.HeapAlloc)
	allocated := int64(after.TotalAlloc) - int64(before.TotalAlloc)
	runtime.KeepAlive(rep)
	runtime.KeepAlive(files)
	runtime.KeepAlive(n)
	if len(rep.Cards) != wanted.MaxCards || len(rep.Findings) != 0 {
		t.Fatalf("cards %d, findings %d", len(rep.Cards), len(rep.Findings))
	}
	const sixteen = wanted.MaxCards * wanted.MaxBytes
	t.Logf("the report of %d files of %d bytes holds %d bytes (%.2f times the bytes of the files); the run allocated %d bytes in all", wanted.MaxCards, wanted.MaxBytes, held, float64(held)/sixteen, allocated)
	if held > 2*sixteen {
		t.Errorf("the report holds %d bytes, more than twice the %d bytes of the files", held, sixteen)
	}
}
