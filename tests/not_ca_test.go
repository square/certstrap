// +build integration

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
	"os"
	"strings"
	"testing"
)

// Ensures certificates which aren't a CA can't sign other certificates.
func TestNotCA(t *testing.T) {
	os.RemoveAll(depotDir)
	defer os.RemoveAll(depotDir)

	stdout, stderr, err := run(binPath, "init", "--passphrase", passphrase, "--common-name", "cert1")
	if stderr != "" || err != nil {
		t.Fatalf("Received unexpected error: %v, %v", stderr, err)
	}
	if strings.Count(stdout, "Created") != 3 {
		t.Fatalf("Received incorrect create: %v", stdout)
	}

	stdout, stderr, err = run(binPath, "request-cert", "--passphrase", passphrase, "--common-name", "cert2")
	if stderr != "" || err != nil {
		t.Fatalf("Received unexpected error: %v, %v", stderr, err)
	}
	if strings.Count(stdout, "Created") != 2 {
		t.Fatalf("Received incorrect create: %v", stdout)
	}

	stdout, stderr, err = run(binPath, "request-cert", "--passphrase", passphrase, "--common-name", "cert3")
	if stderr != "" || err != nil {
		t.Fatalf("Received unexpected error: %v, %v", stderr, err)
	}
	if strings.Count(stdout, "Created") != 2 {
		t.Fatalf("Received incorrect create: %v", stdout)
	}

	stdout, stderr, err = run(binPath, "sign", "--passphrase", passphrase, "--CA", "cert1", "cert2")
	if stderr != "" || err != nil {
		t.Fatalf("Received unexpected error: %v, %v", stderr, err)
	}
	if strings.Count(stdout, "Created") != 1 {
		t.Fatalf("Received incorrect create: %v", stdout)
	}

	stdout, stderr, err = run(binPath, "sign", "--passphrase", passphrase, "--CA", "cert2", "cert3")
	if stderr != "Selected CA certificate is not allowed to sign certificates.\n" {
		t.Fatalf("Failed to receive expected error.")
	}
}
