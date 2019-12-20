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
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

const (
	depotDir   = ".certstrap-test"
	hostname   = "host1"
	passphrase = "123456"
)

var binPath = fmt.Sprintf("../bin/certstrap-%s-%s-amd64", os.Getenv("BUILD_TAG"), runtime.GOOS)

func run(command string, args ...string) (string, string, error) {
	var stdoutBytes, stderrBytes bytes.Buffer
	args = append([]string{"--depot-path", depotDir}, args...)
	cmd := exec.Command(command, args...)
	cmd.Stdout = &stdoutBytes
	cmd.Stderr = &stderrBytes
	err := cmd.Run()
	return stdoutBytes.String(), stderrBytes.String(), err
}

func runWithStdin(stdin io.Reader, command string, args ...string) (string, string, error) {
	var stdoutBytes, stderrBytes bytes.Buffer
	args = append([]string{"--depot-path", depotDir}, args...)
	cmd := exec.Command(command, args...)
	cmd.Stdin = stdin
	cmd.Stdout = &stdoutBytes
	cmd.Stderr = &stderrBytes
	err := cmd.Run()
	return stdoutBytes.String(), stderrBytes.String(), err
}

func TestVersion(t *testing.T) {
	stdout, stderr, err := run(binPath, "--version")
	if stderr != "" || err != nil {
		t.Fatalf("Received unexpected error: %v, %v", stderr, err)
	}
	if !strings.Contains(stdout, "version") {
		t.Fatalf("Received unexpected stdout: %v", stdout)
	}
}
