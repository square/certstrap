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
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func copyToDepot(path string) error {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}
	_ = os.MkdirAll(depotDir, 0755)
	_, filename := filepath.Split(path)
	err = ioutil.WriteFile(filepath.Join(depotDir, filename), data, 0644)
	if err != nil {
		return err
	}
	return nil
}

// Ensures version 1 certificates can sign
func TestDeprecatedCA(t *testing.T) {
	os.RemoveAll(depotDir)
	defer os.RemoveAll(depotDir)

	err := copyToDepot("deprecated_ca/cert1.crt")
	if err != nil {
		t.Fatalf("copyToDepoy failed: %v", err)
	}
	err = copyToDepot("deprecated_ca/cert1.key")
	if err != nil {
		t.Fatalf("copyToDepoy failed: %v", err)
	}

	stdout, stderr, err := run(binPath, "request-cert", "--passphrase", passphrase, "--common-name", "cert2")
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
}
