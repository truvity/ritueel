package buildinfo

import (
	"runtime/debug"
	"testing"
)

// embedded makes the build information the Go tool would embed.
func embedded(mainVersion string, settings ...debug.BuildSetting) *debug.BuildInfo {
	return &debug.BuildInfo{
		Main:     debug.Module{Path: "ritueel.id/ritueel", Version: mainVersion},
		Settings: settings,
	}
}

func revision(v string) debug.BuildSetting {
	return debug.BuildSetting{Key: "vcs.revision", Value: v}
}

func TestResolve(t *testing.T) {
	tests := []struct {
		name          string
		version, comm string
		bi            *debug.BuildInfo
		want          Info
	}{
		{
			name:    "both stamped win over the embedded values",
			version: "v1.2.3", comm: "abcdef0",
			bi:   embedded("v9.9.9", revision("ffffff")),
			want: Info{Version: "v1.2.3", Commit: "abcdef0"},
		},
		{
			name:    "both stamped, no build information",
			version: "v1.2.3", comm: "abcdef0",
			bi:   nil,
			want: Info{Version: "v1.2.3", Commit: "abcdef0"},
		},
		{
			name:    "stamped defaults fall back to the embedded module version and revision",
			version: "dev", comm: "unknown",
			bi:   embedded("v0.4.0", revision("0123456789abcdef")),
			want: Info{Version: "v0.4.0", Commit: "0123456789abcdef"},
		},
		{
			name:    "empty stamped values fall back like the defaults",
			version: "", comm: "",
			bi:   embedded("v0.4.0", revision("0123456789abcdef")),
			want: Info{Version: "v0.4.0", Commit: "0123456789abcdef"},
		},
		{
			name:    "a (devel) module version is not a version",
			version: "dev", comm: "unknown",
			bi:   embedded("(devel)", revision("abc")),
			want: Info{Version: "dev", Commit: "abc"},
		},
		{
			name:    "an empty module version is not a version",
			version: "dev", comm: "unknown",
			bi:   embedded("", revision("abc")),
			want: Info{Version: "dev", Commit: "abc"},
		},
		{
			name:    "the commit comes from vcs.revision among other settings",
			version: "dev", comm: "unknown",
			bi: embedded("(devel)",
				debug.BuildSetting{Key: "-compiler", Value: "gc"},
				debug.BuildSetting{Key: "vcs", Value: "git"},
				revision("c0ffee"),
				debug.BuildSetting{Key: "vcs.modified", Value: "true"},
			),
			want: Info{Version: "dev", Commit: "c0ffee"},
		},
		{
			name:    "an empty revision is not a commit",
			version: "dev", comm: "unknown",
			bi:   embedded("v0.4.0", revision("")),
			want: Info{Version: "v0.4.0", Commit: "unknown"},
		},
		{
			name:    "no revision setting at all",
			version: "dev", comm: "unknown",
			bi:   embedded("v0.4.0", debug.BuildSetting{Key: "vcs", Value: "git"}),
			want: Info{Version: "v0.4.0", Commit: "unknown"},
		},
		{
			name:    "a revision under another key is not read",
			version: "dev", comm: "unknown",
			bi:   embedded("(devel)", debug.BuildSetting{Key: "vcs.time", Value: "2026-01-01T00:00:00Z"}),
			want: Info{Version: "dev", Commit: "unknown"},
		},
		{
			name:    "nil build information gives the defaults",
			version: "dev", comm: "unknown",
			bi:   nil,
			want: Info{Version: "dev", Commit: "unknown"},
		},
		{
			name:    "nil build information and empty stamped values give the defaults",
			version: "", comm: "",
			bi:   nil,
			want: Info{Version: "dev", Commit: "unknown"},
		},
		{
			name:    "only the version is stamped: the commit still falls back",
			version: "v1.2.3", comm: "unknown",
			bi:   embedded("v9.9.9", revision("feedbeef")),
			want: Info{Version: "v1.2.3", Commit: "feedbeef"},
		},
		{
			name:    "only the commit is stamped: the version still falls back",
			version: "dev", comm: "abcdef0",
			bi:   embedded("v9.9.9", revision("feedbeef")),
			want: Info{Version: "v9.9.9", Commit: "abcdef0"},
		},
		{
			name:    "only the version is stamped, no build information",
			version: "v1.2.3", comm: "unknown",
			bi:   nil,
			want: Info{Version: "v1.2.3", Commit: "unknown"},
		},
		{
			name:    "only the commit is stamped, no build information",
			version: "dev", comm: "abcdef0",
			bi:   nil,
			want: Info{Version: "dev", Commit: "abcdef0"},
		},
		{
			name:    "an empty stamped version with a stamped commit",
			version: "", comm: "abcdef0",
			bi:   embedded("v9.9.9", revision("feedbeef")),
			want: Info{Version: "v9.9.9", Commit: "abcdef0"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := resolve(tt.version, tt.comm, tt.bi); got != tt.want {
				t.Errorf("resolve(%q, %q, ...) = %+v, want %+v", tt.version, tt.comm, got, tt.want)
			}
		})
	}
}

// Read must always say something: a build that stamps nothing and has no version control
// information still reports "dev" and "unknown".
func TestReadNeverEmpty(t *testing.T) {
	got := Read()
	if got.Version == "" {
		t.Error("Read().Version is empty")
	}
	if got.Commit == "" {
		t.Error("Read().Commit is empty")
	}
}
