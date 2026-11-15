package cvefeed

import "testing"

func TestCheckFeedURL(t *testing.T) {
	if err := checkFeedURL("https://security-tracker.debian.org/tracker/data/json"); err != nil {
		t.Errorf("https: %v", err)
	}
	for _, u := range []string{"http://mirror.local/feed.json", "file:///etc/passwd", "gopher://x", "not a url"} {
		if err := checkFeedURL(u); err == nil {
			t.Errorf("%s: expected refusal", u)
		}
	}
	t.Setenv("SPIRE_CVE_FEED_ALLOW_HTTP", "1")
	if err := checkFeedURL("http://mirror.local/feed.json"); err != nil {
		t.Errorf("http with opt-in: %v", err)
	}
}
