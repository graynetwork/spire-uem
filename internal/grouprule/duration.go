package grouprule

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// ParseDuration parses a bounded, human duration used by the older_than / newer_than
// operators. It accepts a positive integer with one suffix: s, m, h, d or w (seconds,
// minutes, hours, days, weeks). Examples: "7d", "12h", "30m", "2w". Go's time.ParseDuration
// does not understand days or weeks, so this is a small explicit parser. The result is
// capped at 10 years so a stored rule cannot overflow a timestamp calculation.
func ParseDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty duration")
	}
	unit := s[len(s)-1]
	numPart := s[:len(s)-1]
	n, err := strconv.Atoi(numPart)
	if err != nil {
		// Fall back to Go's parser for forms like "90m" handled above, or "1h30m".
		d, gerr := time.ParseDuration(s)
		if gerr != nil {
			return 0, fmt.Errorf("duration must be an integer with a unit s/m/h/d/w, e.g. 7d")
		}
		if d <= 0 {
			return 0, fmt.Errorf("duration must be positive")
		}
		return capDuration(d), nil
	}
	if n <= 0 {
		return 0, fmt.Errorf("duration must be positive")
	}
	var d time.Duration
	switch unit {
	case 's':
		d = time.Duration(n) * time.Second
	case 'm':
		d = time.Duration(n) * time.Minute
	case 'h':
		d = time.Duration(n) * time.Hour
	case 'd':
		d = time.Duration(n) * 24 * time.Hour
	case 'w':
		d = time.Duration(n) * 7 * 24 * time.Hour
	default:
		return 0, fmt.Errorf("unknown duration unit %q (use s/m/h/d/w)", string(unit))
	}
	return capDuration(d), nil
}

const maxDuration = 10 * 365 * 24 * time.Hour

func capDuration(d time.Duration) time.Duration {
	if d > maxDuration {
		return maxDuration
	}
	return d
}
