/*-
 * Copyright (c) 2018 Marco Stolze (alias mcpride)
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

// TestWorkflow runs certstrap in the normal workflow
// and traverses all commands
func TestWorkflow(t *testing.T) {
	os.RemoveAll(depotDir)
	defer os.RemoveAll(depotDir)

	stdout, stderr, err := run(binPath, "init", "--passphrase", passphrase, "--common-name", "CA")
	if stderr != "" || err != nil {
		t.Fatalf("Received unexpected error: %v, %v", stderr, err)
	}
	if strings.Count(stdout, "Created") != 3 {
		t.Fatalf("Received incorrect create: %v", stdout)
	}

	stdout, stderr, err = run(binPath, "request-cert", "--passphrase", passphrase, "--common-name", hostname)
	if stderr != "" || err != nil {
		t.Fatalf("Received unexpected error: %v, %v", stderr, err)
	}
	if strings.Count(stdout, "Created") != 2 {
		t.Fatalf("Received incorrect create: %v", stdout)
	}

	stdout, stderr, err = run(binPath, "request-cert", "--passphrase", passphrase, "--ip", "127.0.0.1,8.8.8.8")
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

}
