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

import (
	"runtime/debug"
	"strings"
)

// release overrides what --version prints. Leave it empty to print the
// module version that Go stamps into the binary at build time. Builds
// without git metadata, such as from a source tarball, can set it with
// -ldflags "-X main.release=1.2.3".
var release string

// appVersion returns the version for --version, without the leading "v"
// of a Go module version.
func appVersion() string {
	var buildVersion string
	if info, ok := debug.ReadBuildInfo(); ok {
		buildVersion = info.Main.Version
	}
	return resolveVersion(release, buildVersion)
}

// resolveVersion returns override if it is set, then buildVersion without
// its leading "v", and "(devel)" if neither is set.
func resolveVersion(override, buildVersion string) string {
	if override != "" {
		return override
	}
	if buildVersion != "" {
		return strings.TrimPrefix(buildVersion, "v")
	}
	return "(devel)"
}
