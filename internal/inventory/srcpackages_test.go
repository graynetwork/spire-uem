package inventory

import "testing"

func TestParseSourcePackages(t *testing.T) {
	out := []byte(
		"libssl3\topenssl\t3.0.11-1~deb12u2\t3.0.11-1~deb12u2\n" +
			"openssl\topenssl\t3.0.11-1~deb12u2\t3.0.11-1~deb12u2\n" +
			"bash\t\t\t5.2.15-2+b7\n" + // empty source => falls back to binary name; src ver empty => binary ver
			"libc6:amd64\tglibc (2.36-9+deb12u7)\t\t2.36-9+deb12u7\n" + // arch qualifier + source version in parens
			"\t\t\t\n" + // blank line skipped
			"malformed-line-no-tabs\n", // too few fields, skipped
	)
	pkgs := parseSourcePackages(out)

	if len(pkgs) != 4 {
		t.Fatalf("expected 4 parsed packages, got %d: %+v", len(pkgs), pkgs)
	}

	byName := map[string]struct{ src, ver string }{}
	for _, p := range pkgs {
		byName[p.Name] = struct{ src, ver string }{p.Source, p.SourceVersion}
	}

	if got := byName["libssl3"]; got.src != "openssl" || got.ver != "3.0.11-1~deb12u2" {
		t.Errorf("libssl3 => %+v, want source=openssl ver=3.0.11-1~deb12u2", got)
	}
	if got := byName["bash"]; got.src != "bash" || got.ver != "5.2.15-2+b7" {
		t.Errorf("bash => %+v, want source=bash (fallback) ver=5.2.15-2+b7 (binary fallback)", got)
	}
	if got := byName["libc6"]; got.src != "glibc" || got.ver != "2.36-9+deb12u7" {
		t.Errorf("libc6 => %+v, want source=glibc ver=2.36-9+deb12u7 (arch stripped, parens version)", got)
	}
}

func TestParseSourcePackagesCap(t *testing.T) {
	var buf []byte
	for i := 0; i < maxReportedSourcePackages+500; i++ {
		buf = append(buf, []byte("pkg\tpkg\t1.0\t1.0\n")...)
	}
	pkgs := parseSourcePackages(buf)
	if len(pkgs) != maxReportedSourcePackages {
		t.Fatalf("expected cap at %d, got %d", maxReportedSourcePackages, len(pkgs))
	}
}
