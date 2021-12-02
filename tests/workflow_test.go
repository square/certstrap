//go:build integration

/*-
 * Copyright 2015 Square Inc.
 * Copyright 2014 CoreOS
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package tests

import (
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"os"
	"path"
	"strings"
	"testing"
)

// TestWorkflow runs certstrap in the normal workflow
// and traverses all commands and all key algorithms.
func TestWorkflow(t *testing.T) {
	tests := []struct {
		desc     string
		keySpec  []string
		expected x509.PublicKeyAlgorithm
	}{{
		desc:     "default RSA",
		expected: x509.RSA,
	}, {
		desc:     "P-256",
		keySpec:  []string{"--curve", "P-256"},
		expected: x509.ECDSA,
	}, {
		desc:     "P-521",
		keySpec:  []string{"--curve", "P-521"},
		expected: x509.ECDSA,
	}, {
		desc:     "Ed25519",
		keySpec:  []string{"--curve", "Ed25519"},
		expected: x509.Ed25519,
	}, {
		desc:     "RSA 2048",
		keySpec:  []string{"--key-bits", "2048"},
		expected: x509.RSA,
	}}

	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			os.RemoveAll(depotDir)
			defer os.RemoveAll(depotDir)

			use_uri := "test://test/test"

			args := []string{"init", "--passphrase", passphrase, "--common-name", "CA"}
			args = append(args, tc.keySpec...)
			stdout, stderr, err := run(binPath, args...)
			if stderr != "" || err != nil {
				t.Fatalf("Received unexpected error: %v, %v", stdout, err)
			}
			if strings.Count(stdout, "Created") != 3 {
				t.Fatalf("Received incorrect create: %v", stdout)
			}

			args = []string{"request-cert", "--passphrase", passphrase, "--common-name", hostname, "--uri", use_uri}
			args = append(args, tc.keySpec...)
			stdout, stderr, err = run(binPath, args...)
			if stderr != "" || err != nil {
				t.Fatalf("Received unexpected error: %v, %v", stderr, err)
			}
			if strings.Count(stdout, "Created") != 2 {
				t.Fatalf("Received incorrect create: %v", stdout)
			}

			stdout, stderr, err = run(binPath, "request-cert", "--passphrase", passphrase, "--ip", "127.0.0.1,8.8.8.8", "--common-name", "127.0.0.1")
			if stderr != "" || err != nil {
				t.Fatalf("Received unexpected error: %v, %v", stderr, err)
			}
			if strings.Count(stdout, "Created") != 2 {
				t.Fatalf("Received incorrect create: %v", stdout)
			}

			stdout, stderr, err = run(binPath, "sign", "--passphrase", passphrase, "--CA", "CA", hostname)
			if stderr != "" || err != nil {
				t.Fatalf("Received unexpected error: %v, %v", stderr, err)
			}
			if strings.Count(stdout, "Created") != 1 {
				t.Fatalf("Received incorrect create: %v", stdout)
			}

			fcontents, err := ioutil.ReadFile(path.Join(depotDir, strings.Join([]string{hostname, ".crt"}, "")))
			if err != nil {
				t.Fatalf("Reading cert failed: %v", err)
			}
			der, _ := pem.Decode(fcontents)
			cert, err := x509.ParseCertificate(der.Bytes)
			if !(len(cert.URIs) == 1 && cert.URIs[0].String() == use_uri) {
				t.Fatalf("URI not reflected in cert")
			}
			if cert.PublicKeyAlgorithm != tc.expected {
				t.Fatalf("Public key algorithm = %d, want %d", cert.PublicKeyAlgorithm, tc.expected)
			}
		})
	}
}
