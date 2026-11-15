package ceremony

import (
	"fmt"
	"strings"

	"ritueel.id/ritueel/internal/jsonset"
)

// AcceptedLimit is the accepted limit of a software test root, printed in the plan in words before
// the confirmation (record 0005, rule 20). The words are Proposed. A record says limit_shown only
// when this text was printed in the run.
const AcceptedLimit = "A software root key is a file. Anyone who copies the file can sign as this root, and nothing records it. This is a TEST ONLY root: it is for rehearsals and tests, never for anything that others rely on."

// Words returns the plan in words, one string a line, printable ASCII, in this order: the ceremony
// name and time; the trust set it writes; what it applies, a line for each key; what it leaves out
// with the reason, or that it leaves out nothing; the number of signatures and that none can be fixed
// before the keys are born; the number of touches; the wanted files it used, each with the first
// eight characters of its digest; the accepted limit; and last the plan digest in 64 digits. Every
// name from a file goes through jsonset.EscapeExact. A nil or zero PlanOut has no words.
func (p *PlanOut) Words() []string {
	if p == nil || p.Name == "" || p.SHA256 == "" {
		return nil
	}
	esc := jsonset.EscapeExact
	lines := []string{
		fmt.Sprintf("ceremony %s, made at %s, by ritueel %s (%s)", esc(p.Name), timeText(p.Time), esc(p.Program.Version), esc(p.Program.OSArch)),
		fmt.Sprintf("writes the first trust set, number %d", firstTrustSequence),
	}
	for _, b := range p.Births {
		lines = append(lines, fmt.Sprintf("make the X.509 root key %s: a software key in a file (%s), TEST ONLY", esc(b.Label), esc(b.Place)))
	}
	if len(p.LeavesOut) == 0 {
		lines = append(lines, "leaves out: nothing")
	}
	for _, l := range p.LeavesOut {
		lines = append(lines, fmt.Sprintf("leaves out %s: %s", esc(l.Object), jsonset.Escape(l.Reason)))
	}
	lines = append(lines,
		fmt.Sprintf("signatures: %d; none can be fixed before the keys are born, so each is derived from a key made in this ceremony", len(p.Signatures)),
		"touches: 0",
	)
	for _, w := range p.Wanted {
		lines = append(lines, fmt.Sprintf("wanted file %s, digest %s", esc(w.Path), prefixOf(w.SHA256)))
	}
	lines = append(lines, "limit: "+AcceptedLimit, "plan digest "+p.SHA256)
	return lines
}

// prefixOf is the first eight characters of a digest, or the whole text when it is shorter.
func prefixOf(digest string) string {
	if len(digest) < 8 {
		return strings.Clone(digest)
	}
	return digest[:8]
}
