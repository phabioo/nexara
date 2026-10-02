package update

import "testing"

func TestParseVersion(t *testing.T) {
	tests := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"0.2.0", "0.2.0", false},
		{"v0.2.0", "0.2.0", false},
		{"0.2.0-rc1", "0.2.0-rc1", false},
		{"1.10.3-rc.2", "1.10.3-rc.2", false},
		{"dev", "", true},
		{"", "", true},
		{"0.2", "", true},
		{"0.2.0+build5", "", true},
		{"01.2.3", "", true},
		{"0.2.0-", "", true},
		{"0.2.0-rc/1", "", true},
		{"../0.2.0", "", true},
		{"0.2.0-..", "", true},
		{"0.2.0\n", "", true},
		{"1234567890.0.0", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			v, err := ParseVersion(tt.in)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil && v.String() != tt.want {
				t.Fatalf("String() = %q, want %q", v, tt.want)
			}
		})
	}
}

func TestVersionCompare(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"0.2.0", "0.2.0", 0},
		{"0.2.1", "0.2.0", 1},
		{"0.10.0", "0.9.9", 1},
		{"1.0.0", "0.99.99", 1},
		{"0.2.0-rc1", "0.2.0", -1},
		{"0.2.0", "0.2.0-rc1", 1},
		{"0.2.0-rc1", "0.2.0-rc2", -1},
		{"0.2.0-rc.2", "0.2.0-rc.10", -1},
		{"0.2.0-alpha", "0.2.0-beta", -1},
		{"0.2.0-1", "0.2.0-alpha", -1},
		{"0.2.0-rc", "0.2.0-rc.1", -1},
		{"0.1.0", "0.2.0-rc1", -1},
		{"v0.3.0", "0.2.9", 1},
	}
	for _, tt := range tests {
		t.Run(tt.a+"_vs_"+tt.b, func(t *testing.T) {
			a, _ := ParseVersion(tt.a)
			b, _ := ParseVersion(tt.b)
			if got := a.Compare(b); got != tt.want {
				t.Fatalf("Compare = %d, want %d", got, tt.want)
			}
			if got := b.Compare(a); got != -tt.want {
				t.Fatalf("reverse Compare = %d, want %d", got, -tt.want)
			}
		})
	}
}

func TestParseDebName(t *testing.T) {
	tests := []struct {
		name    string
		version string
		arch    string
		wantErr bool
	}{
		{"nexus_0.2.0_arm64.deb", "0.2.0", "arm64", false},
		{"nexus_0.2.0-rc1_amd64.deb", "0.2.0-rc1", "amd64", false},
		{"nexus_0.2.0_armhf.deb", "", "", true},
		{"nexus_0.2.0_arm64.deb.sig", "", "", true},
		{"../nexus_0.2.0_arm64.deb", "", "", true},
		{"nexus_../../x_arm64.deb", "", "", true},
		{"grid-agent_0.2.0_arm64.deb", "", "", true},
		{"nexus_0.2.0_arm64.deb\n", "", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, arch, err := ParseDebName(tt.name)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil && (v.String() != tt.version || arch != tt.arch) {
				t.Fatalf("got %s/%s, want %s/%s", v, arch, tt.version, tt.arch)
			}
		})
	}
}
