package cmd

import (
	"fmt"
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
	t1, err1 := parseExpiry("53257284647843897")
	t2, err2 := parseExpiry("5 y")
	expectedt1, _ := time.Parse(dateFormat, "2017-01-01")
	expectedt2, _ := time.Parse(dateFormat, "2017-01-01")

	if t1 != expectedt1 && err1 != nil && fmt.Sprintf("%s", err1) == "Invalid expiry format" {
		t.Fatalf("Parsing invalid expiry t1 did not produce an error as expected")
	}

	if t2 != expectedt2 && err2 != nil && fmt.Sprintf("%s", err2) == "Invalid expiry format" {
		t.Fatalf("Parsing invalid expiry t2 did not produce an error as expected")
	}
}
