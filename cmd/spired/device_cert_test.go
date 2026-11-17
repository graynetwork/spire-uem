package main

import (
	"testing"
	"time"
)

func TestRenewalDue(t *testing.T) {
	nb := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	na := nb.Add(30 * 24 * time.Hour) // 30-day lifetime; 2/3 => day 20

	// No certificate: never due.
	if renewalDue(nb, time.Time{}, nb.Add(time.Hour)) {
		t.Fatal("renewalDue should be false when there is no certificate")
	}
	// Fresh (day 1): not due.
	if renewalDue(nb, na, nb.Add(24*time.Hour)) {
		t.Fatal("renewalDue should be false on day 1")
	}
	// Just before 2/3 (day ~19): not due.
	if renewalDue(nb, na, nb.Add(19*24*time.Hour)) {
		t.Fatal("renewalDue should be false just before the 2/3 threshold")
	}
	// At/after 2/3 (day 21): due.
	if !renewalDue(nb, na, nb.Add(21*24*time.Hour)) {
		t.Fatal("renewalDue should be true past the 2/3 threshold")
	}
	// Expired: due.
	if !renewalDue(nb, na, na.Add(time.Hour)) {
		t.Fatal("renewalDue should be true once expired")
	}
	// Degenerate window (notAfter<=notBefore): due.
	if !renewalDue(nb, nb, nb) {
		t.Fatal("renewalDue should be true for a degenerate window")
	}
}
