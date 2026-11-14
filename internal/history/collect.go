package history

import (
	"slices"
	"unicode/utf8"
)

// collector keeps the findings of a run, at most [MaxFindingsPerCode] of each code, and counts
// the rest.
type collector struct {
	perCode int
	list    []Finding
	count   map[Code]int
	omitted int
}

func newCollector(perCode int) *collector {
	return &collector{perCode: perCode, count: map[Code]int{}}
}

// add records one finding. A detail is cut to a bounded length.
func (c *collector) add(code Code, path, detail string) {
	if c.count[code] >= c.perCode {
		c.omitted++
		return
	}
	c.count[code]++
	c.list = append(c.list, Finding{Code: code, Path: path, Detail: cut(detail, maxDetail)})
}

// sorted returns the findings in the fixed order.
func (c *collector) sorted() []Finding {
	out := slices.Clone(c.list)
	slices.SortStableFunc(out, compare)
	return out
}

// cut returns s cut to at most n bytes, not inside a character, with "..." when it was cut.
func cut(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n] + "..."
}
