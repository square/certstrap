package cmd

import (
	"encoding/asn1"
	"testing"
)

func TestValidOid(t *testing.T) {
	parsed, _ := parseOid("1.3.6.1.5.5.7.3.1")
	expected := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}

	if !parsed.Equal(expected) {
		t.Fatalf("Parsed OID does not match expected (expected: %s, got %s)", expected, parsed)
	}
}

func TestInvalidOid(t *testing.T) {
	_, err := parseOid("not an OID")
	if err == nil {
		t.Fatalf("Expected error when parsing invalid OID")
	}
}
