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
	"path/filepath"
	"strings"
	"testing"
)

// Tests Name formtting
func TestFormat(t *testing.T) {
	os.RemoveAll(depotDir)
	defer os.RemoveAll(depotDir)

	stdout, stderr, err := run(binPath, "request-cert", "--passphrase", passphrase, "--uri", "nametest://nametest/nametest-nametest")
	if stderr != "" || err != nil {
		t.Fatalf("Received unexpected error: %v, %v", stderr, err)
	}
	if strings.Count(stdout, "Created") != 2 {
		t.Fatalf("Received incorrect create: %v", stdout)
	}
	if _, err := os.Stat(filepath.Join(depotDir, "nametest___nametest_nametest-nametest.csr")); os.IsNotExist(err) {
		t.Fatalf("CSR not created with correct name: %v", err)
	}

	os.RemoveAll(depotDir)
	defer os.RemoveAll(depotDir)
}
