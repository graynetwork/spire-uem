package workflows

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// CronSchedule is a parsed standard 5-field cron expression: minute hour day-of-month month
// day-of-week. It is evaluated at minute granularity: Matches(t) reports whether a fire is
// due in the minute containing t. Only a bounded, well-formed subset is accepted (numbers,
// ranges a-b, steps */n and a-b/n, lists a,b,c, and the wildcard *), so a hostile expression
// cannot blow up. day-of-week 0 and 7 both mean Sunday.
//
// It deliberately avoids any external dependency and never shells out.
type CronSchedule struct {
	minute []bool // len 60
	hour   []bool // len 24
	dom    []bool // len 32 (1..31 used)
	month  []bool // len 13 (1..12 used)
	dow    []bool // len 7  (0..6, Sunday=0)
	// domRestricted / dowRestricted record whether the field was non-wildcard, so the
	// standard "OR between dom and dow when both restricted" rule can be applied.
	domRestricted bool
	dowRestricted bool
}

// ParseCron parses a 5-field cron expression. Extra whitespace between fields is tolerated.
func ParseCron(expr string) (*CronSchedule, error) {
	fields := strings.Fields(strings.TrimSpace(expr))
	if len(fields) != 5 {
		return nil, fmt.Errorf("cron expression must have exactly 5 fields (got %d)", len(fields))
	}
	c := &CronSchedule{
		minute: make([]bool, 60),
		hour:   make([]bool, 24),
		dom:    make([]bool, 32),
		month:  make([]bool, 13),
		dow:    make([]bool, 7),
	}
	if err := parseField(fields[0], 0, 59, c.minute); err != nil {
		return nil, fmt.Errorf("minute field: %w", err)
	}
	if err := parseField(fields[1], 0, 23, c.hour); err != nil {
		return nil, fmt.Errorf("hour field: %w", err)
	}
	if err := parseField(fields[2], 1, 31, c.dom); err != nil {
		return nil, fmt.Errorf("day-of-month field: %w", err)
	}
	if err := parseField(fields[3], 1, 12, c.month); err != nil {
		return nil, fmt.Errorf("month field: %w", err)
	}
	// day-of-week: normalise 7 to 0 first.
	dowField := fields[4]
	if err := parseDOW(dowField, c.dow); err != nil {
		return nil, fmt.Errorf("day-of-week field: %w", err)
	}
	c.domRestricted = fields[2] != "*"
	c.dowRestricted = dowField != "*"
	return c, nil
}

// ValidateCron reports whether expr is a well-formed 5-field cron expression.
func ValidateCron(expr string) error {
	_, err := ParseCron(expr)
	return err
}

// Matches reports whether a fire is due in the minute containing t (t is used in UTC).
func (c *CronSchedule) Matches(t time.Time) bool {
	t = t.UTC()
	if !c.minute[t.Minute()] || !c.hour[t.Hour()] || !c.month[int(t.Month())] {
		return false
	}
	domOK := c.dom[t.Day()]
	dowOK := c.dow[int(t.Weekday())]
	// Standard Vixie-cron rule: if BOTH dom and dow are restricted, a match on EITHER fires;
	// otherwise both must match (an unrestricted field is always true).
	if c.domRestricted && c.dowRestricted {
		return domOK || dowOK
	}
	return domOK && dowOK
}

func parseDOW(field string, out []bool) error {
	// Accept 0-7 where 7==0 (Sunday). Parse into a 0..7 temp then fold 7 into 0.
	tmp := make([]bool, 8)
	if err := parseField(field, 0, 7, tmp); err != nil {
		return err
	}
	for i := 0; i <= 7; i++ {
		if tmp[i] {
			out[i%7] = true
		}
	}
	return nil
}

// parseField fills out[min..max] from a cron field: `*`, `*/n`, `a`, `a-b`, `a-b/n`, lists.
func parseField(field string, min, max int, out []bool) error {
	if field == "" {
		return fmt.Errorf("empty field")
	}
	for _, part := range strings.Split(field, ",") {
		if err := parsePart(part, min, max, out); err != nil {
			return err
		}
	}
	return nil
}

func parsePart(part string, min, max int, out []bool) error {
	step := 1
	rangePart := part
	if slash := strings.IndexByte(part, '/'); slash >= 0 {
		rangePart = part[:slash]
		stepStr := part[slash+1:]
		s, err := strconv.Atoi(stepStr)
		if err != nil || s <= 0 {
			return fmt.Errorf("invalid step %q", stepStr)
		}
		step = s
	}

	var lo, hi int
	switch {
	case rangePart == "*":
		lo, hi = min, max
	case strings.IndexByte(rangePart, '-') >= 0:
		dash := strings.IndexByte(rangePart, '-')
		a, err1 := strconv.Atoi(rangePart[:dash])
		b, err2 := strconv.Atoi(rangePart[dash+1:])
		if err1 != nil || err2 != nil {
			return fmt.Errorf("invalid range %q", rangePart)
		}
		lo, hi = a, b
	default:
		v, err := strconv.Atoi(rangePart)
		if err != nil {
			return fmt.Errorf("invalid value %q", rangePart)
		}
		lo, hi = v, v
	}
	if lo < min || hi > max || lo > hi {
		return fmt.Errorf("value out of range [%d,%d]: %q", min, max, part)
	}
	for v := lo; v <= hi; v += step {
		out[v] = true
	}
	return nil
}
