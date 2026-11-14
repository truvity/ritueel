package history

import (
	"slices"
	"strconv"
)

// Report is what [Check] found.
type Report struct {
	// Records is the number of record.json files found, valid or not: one for each ceremony
	// folder of history/ that holds an entry of that name. It is the count that the end line
	// prints (record 0006, rule 11).
	Records int
	// Ends holds the full digests of the records no record that was read names, each once, in
	// the order of the digests. A record that could not be read has a digest and no name of a
	// predecessor, so it is an end, and so is the record before it. A clean history of at least
	// one record has exactly one end.
	Ends []string
	// Findings holds every finding and every notice, in the fixed order of [Code], then by path,
	// then by detail; at most [MaxFindingsPerCode] of each code. [Report.Omitted] counts the
	// rest.
	Findings []Finding
	// Omitted is the number of findings that were left out because their code had
	// [MaxFindingsPerCode] findings already. A code that has findings left out has findings
	// kept, so [Report.Reasons] and [Report.Warnings] are complete. A command that prints the
	// findings must print this number too ("N more findings not shown"), or a reader takes the
	// thousand lines for the whole list.
	Omitted int
}

// Failing returns the findings that end the command with exit code 3, in the order of Findings.
func (r *Report) Failing() []Finding { return r.filter(true) }

// Notices returns the notices, in the order of Findings.
func (r *Report) Notices() []Finding { return r.filter(false) }

func (r *Report) filter(failing bool) []Finding {
	var out []Finding
	for _, f := range r.Findings {
		if f.Code.Fails() == failing {
			out = append(out, f)
		}
	}
	return out
}

// Reasons returns the distinct codes of the failing findings, each once, in the order of
// [Codes]: the member "reasons" of the command. It is empty when the history is whole.
func (r *Report) Reasons() []Code { return r.distinct(true) }

// Warnings returns the distinct codes of the notices, each once, in the order of [Codes]: the
// member "warnings" of the command.
func (r *Report) Warnings() []Code { return r.distinct(false) }

func (r *Report) distinct(failing bool) []Code {
	var out []Code
	for _, f := range r.Findings { // sorted by code, so a repeat is next to its first
		if f.Code.Fails() == failing && !slices.Contains(out, f.Code) {
			out = append(out, f.Code)
		}
	}
	return out
}

// Clean reports whether no finding fails. A notice does not make a history unclean.
func (r *Report) Clean() bool { return len(r.Failing()) == 0 }

// End returns the first eight characters of the digest of the end of the history and the count
// of records, as the end line prints them. ok is false unless there is exactly one end: with no
// record there is none, and with two or more the history has a fork or a break and a finding
// says so. A caller prints the line only for a clean report.
func (r *Report) End() (eight string, count int, ok bool) {
	if len(r.Ends) != 1 {
		return "", r.Records, false
	}
	return r.Ends[0][:8], r.Records, true
}

// EndLine is the line of a run that found no failing finding, without its line break: "history: N
// ceremony records, end XXXXXXXX", with the count and the first eight characters of the digest of
// the end (docs/reference/cli.md, "check history"), or "history: 0 ceremony records" when there is
// no record, and the same without the end when the history does not have exactly one. The word
// "records" is the page's form for every N.
func (r *Report) EndLine() string {
	line := "history: " + strconv.Itoa(r.Records) + " ceremony records"
	if eight, _, ok := r.End(); ok {
		line += ", end " + eight
	}
	return line
}
