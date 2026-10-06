/*-
 * Copyright 2026 Square Inc.
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

package main

import "testing"

func TestResolveVersion(t *testing.T) {
	tests := []struct {
		name         string
		override     string
		buildVersion string
		want         string
	}{
		{name: "override wins over build info", override: "1.2.3", buildVersion: "v1.4.0", want: "1.2.3"},
		{name: "tagged build", buildVersion: "v1.4.0", want: "1.4.0"},
		{name: "prerelease tag", buildVersion: "v1.4.0-rc.1", want: "1.4.0-rc.1"},
		{name: "untagged commit", buildVersion: "v1.4.1-0.20261005184410-5abe9dab23cc", want: "1.4.1-0.20261005184410-5abe9dab23cc"},
		{name: "uncommitted changes", buildVersion: "v1.4.0+dirty", want: "1.4.0+dirty"},
		{name: "no git metadata", buildVersion: "(devel)", want: "(devel)"},
		{name: "no build info", want: "(devel)"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := resolveVersion(tc.override, tc.buildVersion); got != tc.want {
				t.Fatalf("resolveVersion(%q, %q) = %q, want %q", tc.override, tc.buildVersion, got, tc.want)
			}
		})
	}
}

func TestAppVersion(t *testing.T) {
	if appVersion() == "" {
		t.Fatal("appVersion() is empty")
	}

	defer func(v string) { release = v }(release)
	release = "1.2.3"
	if got := appVersion(); got != "1.2.3" {
		t.Fatalf("appVersion() = %q, want the -X override %q", got, "1.2.3")
	}
}
