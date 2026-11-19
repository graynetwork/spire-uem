package campaign

import "testing"

func TestValidPackageName(t *testing.T) {
	valid := []string{"curl", "libcurl4", "git", "linux-image-6.1.0-28-amd64", "g++", "lib2.0", "a0", "python3.11"}
	for _, n := range valid {
		if !ValidPackageName(n) {
			t.Errorf("expected %q to be a valid package name", n)
		}
	}
	// Injection / malformed attempts must all be rejected.
	invalid := []string{
		"",                    // empty
		"a",                   // too short (policy requires >= 2)
		"-rf",                 // option injection
		"--allow-downgrades",  // option injection
		"curl; rm -rf /",      // shell metachars
		"curl rm",             // whitespace
		"curl\nrm",            // newline
		"curl=1.0",            // '=' is not a name char
		"CURL",                // uppercase not allowed in a name
		"../etc/passwd",       // path traversal
		"pkg/../../x",         // slash
		"pkg\x00",             // null byte
		".hidden",             // leading dot (not alphanumeric)
		"+plus",               // leading '+'
	}
	for _, n := range invalid {
		if ValidPackageName(n) {
			t.Errorf("expected %q to be REJECTED as a package name", n)
		}
	}
	// Oversized name.
	long := make([]byte, MaxPackageNameLen+1)
	for i := range long {
		long[i] = 'a'
	}
	if ValidPackageName(string(long)) {
		t.Errorf("expected oversized name to be rejected")
	}
}

func TestValidVersion(t *testing.T) {
	valid := []string{"7.88.1-10+deb12u7", "1:2.39.5-0+deb12u1", "1.0~rc1", "2.0", "1.2.3-1", "0.1"}
	for _, v := range valid {
		if !ValidVersion(v) {
			t.Errorf("expected %q to be a valid version", v)
		}
	}
	invalid := []string{
		"",                  // empty (use TargetLatest instead)
		"=1.0",              // leading '='
		"1.0; reboot",       // shell metachars
		"-1.0",              // leading '-' (option injection)
		"a1.0",              // must start with a digit
		"1.0 2.0",           // whitespace
		"1.0/../x",          // slash / traversal
		"1.0\x00",           // null byte
		"$(id)",             // command substitution
	}
	for _, v := range invalid {
		if ValidVersion(v) {
			t.Errorf("expected %q to be REJECTED as a version", v)
		}
	}
}

func TestNormalizeTarget(t *testing.T) {
	cases := []struct {
		in     string
		want   string
		wantOK bool
	}{
		{"", TargetLatest, true},
		{"  ", TargetLatest, true},
		{"latest", TargetLatest, true},
		{"latest available", TargetLatest, true},
		{"LATEST", TargetLatest, true},
		{"7.88.1-10+deb12u7", "7.88.1-10+deb12u7", true},
		{"-rf", "", false},
		{"bad; rm", "", false},
	}
	for _, c := range cases {
		got, ok := NormalizeTarget(c.in)
		if got != c.want || ok != c.wantOK {
			t.Errorf("NormalizeTarget(%q) = (%q,%v), want (%q,%v)", c.in, got, ok, c.want, c.wantOK)
		}
	}
}

func TestAptSpec(t *testing.T) {
	// latest -> bare name, never an "=" pin
	if spec, ok := AptSpec("curl", TargetLatest); !ok || spec != "curl" {
		t.Errorf("AptSpec latest = (%q,%v), want (curl,true)", spec, ok)
	}
	// pinned -> name=version
	if spec, ok := AptSpec("curl", "7.88.1-10+deb12u7"); !ok || spec != "curl=7.88.1-10+deb12u7" {
		t.Errorf("AptSpec pinned = (%q,%v)", spec, ok)
	}
	// A spec can never be produced from an unsafe name or version, even if a caller skipped
	// validation.
	if _, ok := AptSpec("-rf", TargetLatest); ok {
		t.Errorf("AptSpec must reject an option-injection package name")
	}
	if _, ok := AptSpec("curl", "1.0; rm -rf /"); ok {
		t.Errorf("AptSpec must reject an unsafe version")
	}
}
