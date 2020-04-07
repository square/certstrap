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

// TODO: needs improvement
func TestURI(t *testing.T) {
	os.RemoveAll(depotDir)
	defer os.RemoveAll(depotDir)

	stdout, stderr, err := run(binPath, "request-cert", "--passphrase", passphrase, "--common-name", "CA", "--uri", "http://test.test/test")
	if stderr != "" || err != nil {
		t.Fatalf("Received unexpected error: %v, %v", stderr, err)
	}
	if strings.Count(stdout, "Created") != 2 {
		t.Fatalf("Received incorrect create: %v", stdout)
	}

	os.RemoveAll(depotDir)
	defer os.RemoveAll(depotDir)

	stdout, stderr, err = run(binPath, "request-cert", "--passphrase", passphrase, "--common-name", "CA", "--uri", "test://192.168.0.1,test2://8.8.8.8")
	if stderr != "" || err != nil {
		t.Fatalf("Received unexpected error: %v, %v", stderr, err)
	}
	if strings.Count(stdout, "Created") != 2 {
		t.Fatalf("Received incorrect create: %v", stdout)
	}

	os.RemoveAll(depotDir)
	defer os.RemoveAll(depotDir)

	// Disallow URIs as "/"
	stdout, stderr, err = run(binPath, "request-cert", "--passphrase", passphrase, "--common-name", "CA", "--uri", "/")
	if !strings.Contains(stderr, "Invalid URI: /") {
		t.Fatalf("Received unexpected : %v, %v", stderr, err)
	}

	os.RemoveAll(depotDir)
	defer os.RemoveAll(depotDir)

	// Disallow URIs as "/test"
	stdout, stderr, err = run(binPath, "request-cert", "--passphrase", passphrase, "--common-name", "CA", "--uri", "/test")
	if !strings.Contains(stderr, "Invalid URI: /test") {
		t.Fatalf("Received unexpected : %v, %v", stderr, err)
	}
	os.RemoveAll(depotDir)
	defer os.RemoveAll(depotDir)
}
