package ceremony

import (
	"time"

	"ritueel.id/ritueel/internal/ceremony/files"
)

// ceremonyTimeLayout is the time in the name of a ceremony folder, YYYYMMDDThhmmssZ in UTC
// (docs/reference/ceremony-record.md, "The ceremony folder").
const ceremonyTimeLayout = "20060102T150405Z"

// ceremonyName is the name of the ceremony folder of a plan made at t: the time and the command
// only, for example 20261120T100000Z-apply. The page proposes a suffix of eight characters of the
// plan digest, which cannot be built, because the plan holds its own name and no name can hold the
// digest of a text that holds the name. A second plan in one second meets the first on one name, and
// the second folder is refused. It is the one place of the rule.
func ceremonyName(t time.Time) string {
	return t.UTC().Format(ceremonyTimeLayout) + "-" + files.CommandApply
}

// timeText is a time as the pages write it, YYYY-MM-DDThh:mm:ssZ in UTC.
func timeText(t time.Time) string { return t.UTC().Format(time.RFC3339) }
