// Package buildinfo says which version and which commit a ritueel binary was built from.
package buildinfo

import "runtime/debug"

// The release build stamps these two with -ldflags "-X" (see the go-build recipe). A build
// that does not stamp them keeps the plain values below, and Read then asks the build
// information that the Go tool embeds.
var (
	version = "dev"
	commit  = "unknown"
)

const (
	unstampedVersion = "dev"
	unstampedCommit  = "unknown"
	develVersion     = "(devel)"
)

// Info is the version and the commit of the running binary.
type Info struct {
	Version string
	Commit  string
}

// Read returns the version and the commit of the running binary: the stamped values when
// the build stamped them, else what the Go tool embedded, else "dev" and "unknown".
func Read() Info {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		bi = nil
	}
	return resolve(version, commit, bi)
}

// resolve picks each value: the stamped one unless it is empty or still the plain default,
// then the embedded module version (a tagged `go install` build) and the embedded version
// control revision, then the plain default.
func resolve(stampedVersion, stampedCommit string, bi *debug.BuildInfo) Info {
	info := Info{Version: stampedVersion, Commit: stampedCommit}
	if info.Version == "" || info.Version == unstampedVersion {
		info.Version = unstampedVersion
		if bi != nil && bi.Main.Version != "" && bi.Main.Version != develVersion {
			info.Version = bi.Main.Version
		}
	}
	if info.Commit == "" || info.Commit == unstampedCommit {
		info.Commit = unstampedCommit
		if bi != nil {
			for _, s := range bi.Settings {
				if s.Key == "vcs.revision" && s.Value != "" {
					info.Commit = s.Value
					break
				}
			}
		}
	}
	return info
}
