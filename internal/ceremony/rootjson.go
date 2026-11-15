package ceremony

import (
	"time"

	"ritueel.id/ritueel/internal/ceremony/files"
)

// rootJSONPath is the path in the bundle of the root.json of a label, roots/<label>/root.json
// (docs/reference/bundle.md, "The layout"; record 0006, rule 31).
func rootJSONPath(label string) string {
	return rootsDir + "/" + label + "/" + files.RootJSONFile
}

// parseTime reads a time that the plan wrote: YYYY-MM-DDThh:mm:ssZ, in UTC. files.CheckTime judges
// the form first, so a time with a fraction or an offset is refused.
func parseTime(s string) (time.Time, error) {
	if err := files.CheckTime(s); err != nil {
		return time.Time{}, err
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, err
	}
	return t.UTC(), nil
}
