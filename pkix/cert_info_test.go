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

package pkix

import (
	"encoding/base64"
	"testing"
)

const (
	serialNumber = 10
	infoBASE64   = "MTA="
)

func TestCertificateAuthorityInfo(t *testing.T) {
	i := NewCertificateAuthorityInfo(serialNumber)

	i.IncSerialNumber()
	if i.SerialNumber.Uint64() != serialNumber+1 {
		t.Fatal("Failed incrementing serial number")
	}
}

func TestCertificateAuthorityInfoFromJSON(t *testing.T) {
	data, err := base64.StdEncoding.DecodeString(infoBASE64)
	if err != nil {
		t.Fatal("Failed decoding base64 string:", err)
	}

	i, err := NewCertificateAuthorityInfoFromJSON(data)
	if err != nil {
		t.Fatal("Failed init CertificateAuthorityInfo:", err)
	}

	if i.SerialNumber.Uint64() != serialNumber {
		t.Fatal("Failed getting correct serial number")
	}

	b, err := i.Export()
	if err != nil {
		t.Fatal("Failed exporting info:", err)
	}
	if base64.StdEncoding.EncodeToString(b) != infoBASE64 {
		t.Fatal("Failed exporting correct info")
	}
}
