package cmd

import (
	"fmt"
	"regexp"
	"testing"
	"time"
)

const dateFormat = "2006-01-02"

func init() {
	nowFunc = func() time.Time {
		t, _ := time.Parse(dateFormat, "2017-01-01")
		return t
	}
}

func TestParseExpiryWithDays(t *testing.T) {
	t1, _ := parseExpiry("1 day")
	t2, _ := parseExpiry("1 days")
	expected, _ := time.Parse(dateFormat, "2017-01-02")

	if t1 != expected {
		t.Fatalf("Parsing expiry 1 day from now (singular) did not return expected value (wanted: %s, got: %s)", expected, t1)
	}

	if t2 != expected {
		t.Fatalf("Parsing expiry 1 day from now (plural) did not return expected value (wanted: %s, got: %s)", expected, t2)
	}
}

func TestParseExpiryWithMonths(t *testing.T) {
	t1, _ := parseExpiry("1 month")
	t2, _ := parseExpiry("1 months")
	expected, _ := time.Parse(dateFormat, "2017-02-01")

	if t1 != expected {
		t.Fatalf("Parsing expiry 1 month from now (singular) did not return expected value (wanted: %s, got: %s)", expected, t1)
	}

	if t2 != expected {
		t.Fatalf("Parsing expiry 1 month from now (plural) did not return expected value (wanted: %s, got: %s)", expected, t2)
	}
}

func TestParseExpiryWithYears(t *testing.T) {
	t1, _ := parseExpiry("1 year")
	t2, _ := parseExpiry("1 years")
	expected, _ := time.Parse(dateFormat, "2018-01-01")

	if t1 != expected {
		t.Fatalf("Parsing expiry 1 year from now (singular) did not return expected value (wanted: %s, got: %s)", expected, t1)
	}

	if t2 != expected {
		t.Fatalf("Parsing expiry 1 year from now (plural) did not return expected value (wanted: %s, got: %s)", expected, t2)
	}
}

func TestParseExpiryWithMixed(t *testing.T) {
	t1, _ := parseExpiry("2 days 3 months 1 year")
	t2, _ := parseExpiry("5 years 5 days 6 months")
	expectedt1, _ := time.Parse(dateFormat, "2018-04-03")
	expectedt2, _ := time.Parse(dateFormat, "2022-07-06")

	if t1 != expectedt1 {
		t.Fatalf("Parsing expiry for mixed format t1 did not return expected value (wanted: %s, got: %s)", expectedt1, t1)
	}

	if t2 != expectedt2 {
		t.Fatalf("Parsing expiry for mixed format t2 did not return expected value (wanted: %s, got: %s)", expectedt2, t2)
	}
}

func TestParseInvalidExpiry(t *testing.T) {
	errorTime := onlyTime(time.Parse(dateFormat, "2017-01-01"))
	cases := []struct {
		Input       string
		Expected    time.Time
		ExpectedErr string
	}{
		{"53257284647843897", errorTime, "invalid or empty format"},
		{"5y", errorTime, "invalid or empty format"},
		{"53257284647843897 days", errorTime, ".*value out of range"},
		{"2147483647 hours", errorTime, ".*hour unit too large.*"},
		{"2147483647 days", errorTime, ".*proposed date too far in to the future.*"},
	}

	for _, c := range cases {
		result, err := parseExpiry(c.Input)
		if result != c.Expected {
			t.Fatalf("Invalid expiry '%s' did not have expected value (wanted: %s, got: %s)", c.Input, c.Expected, result)
		}

		if match, _ := regexp.MatchString(c.ExpectedErr, fmt.Sprintf("%s", err)); !match {
			t.Fatalf("Invalid expiry '%s' did not have expected error (wanted: %s, got: %s)", c.Input, c.ExpectedErr, err)
		}
	}
}

func onlyTime(a time.Time, b error) time.Time {
	return a
}
