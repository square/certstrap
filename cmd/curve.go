package cmd

import (
	"crypto/elliptic"
	"fmt"
	"strings"

	"github.com/square/certstrap/pkix"
)

// curves is a map of canonical curve name (as specified by the -curve flag)
// to function that creates a new key on that curve.
var curves = map[string]func() (*pkix.Key, error){
	"P-224": func() (*pkix.Key, error) {
		return pkix.CreateECDSAKey(elliptic.P224())
	},
	"P-256": func() (*pkix.Key, error) {
		return pkix.CreateECDSAKey(elliptic.P256())
	},
	"P-384": func() (*pkix.Key, error) {
		return pkix.CreateECDSAKey(elliptic.P384())
	},
	"P-521": func() (*pkix.Key, error) {
		return pkix.CreateECDSAKey(elliptic.P521())
	},
	"Ed25519": func() (*pkix.Key, error) {
		return pkix.CreateEd25519Key()
	},
}

// supportedCurves returns the list of supported curve names as a comma separated
// string for use in help text and error messages.
func supportedCurves() string {
	result := make([]string, 0, len(curves))
	for name := range curves {
		result = append(result, name)
	}
	return strings.Join(result, ", ")
}

func createKeyOnCurve(name string) (*pkix.Key, error) {
	create, ok := curves[name]
	if !ok {
		return nil, fmt.Errorf("unknown curve %q, curve must be one of %s", name, supportedCurves())
	}
	return create()
}
