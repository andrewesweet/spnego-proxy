package main

import "testing"

func TestVersionString(t *testing.T) {
	tests := []struct {
		name    string
		version string
		commit  string
		want    string
	}{
		{"devel", "", "", "spnego-proxy version (devel)"},
		{"version only", "v0.1.0", "", "spnego-proxy version v0.1.0"},
		{"full", "v0.1.0", "abc1234def5678", "spnego-proxy version v0.1.0 (commit abc1234)"},
		{"short commit", "v0.1.0", "abc", "spnego-proxy version v0.1.0 (commit abc)"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			origVersion, origCommit := version, commit
			t.Cleanup(func() { version, commit = origVersion, origCommit })

			version = tt.version
			commit = tt.commit
			if got := versionString(); got != tt.want {
				t.Errorf("versionString() = %q, want %q", got, tt.want)
			}
		})
	}
}
