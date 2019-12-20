/*-
 * Copyright 2016 Square Inc.
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
	"bytes"
	"testing"
	"time"
)

const (
	crlPEM = `-----BEGIN X509 CRL-----
MIICfzBpMA0GCSqGSIb3DQEBCwUAMBMxETAPBgNVBAMTCENlcnRBdXRoFw0xNjAy
MDQyMjAwMTdaFw0yNjAyMDQyMjAwMTdaMACgIzAhMB8GA1UdIwQYMBaAFIM33UgM
CnTVX7cuOFiPIdvMsrzmMA0GCSqGSIb3DQEBCwUAA4ICAQBcrKZml+1XEb7iXiRX
3zkSlXqYmhW3WK5N2uF8+xpJWukkJNmQyM6FzeMWs0hZWTuN84lOBU4CmDjCglrt
Bn6VtmdAQHf42ZTAMUkFDI8+DsfXHxEYrDp1//1Ljz7ybNhuanmXkVcsyNVN6Rn3
LRV2g4tHSAtxMJBHg/CAQWI7vOzD6fDX+1JPMcmrAufglxPEc6r/I0N/CduIJMzO
Ivb6A6Nx/fZmYJEMuvb9Mt9uwnPhC7iiktq0QiAixOG3yPBduQNl73vsuRoROGDn
AYg+cIQ16jIqpaXYXj//QyfWWqqRl29TmXY1kRFZuH+hyAay30lcU+uUrAYqhG+N
ZbrwE1vLtaUGTko36ZY6omqz/Do2dU5bxDbKWskkSLqFleLXtoJqZsKfE1ZdFW0+
iAPDJcl3jCKrs2lN3RinJj76LtLxmIiaK2AsDg/iLaplaqbjtx4xWDzvfiNAeo8k
zEST4Zo0VXTJ/cxzx7Roe0kPFlCt/YNsOKLTOCfvjyFjMRcbcBlut7Fk7/VGWxsj
XkF1bcyI7WPSM8Taq6lWhjHtRUDT3q1gPpUY1CBWJKQrKUwjBzVk81wCS6LJfdTG
/5z7+UfcUAHh7Afm90hyk3nh+fPgSCQrRx9OC5kAJSLMKMvV9ikDZvr9rSkacowD
lrpOuuKFsK22BhjvCNY2fLWn0A==
-----END X509 CRL-----
`
)

func TestCreateCertificateRevocationList(t *testing.T) {
	key, err := CreateRSAKey(rsaBits)
	if err != nil {
		t.Fatal("Failed creating rsa key:", err)
	}

	crt, err := CreateCertificateAuthority(key, "OU", time.Now().AddDate(5, 0, 0), "test", "US", "California", "San Francisco", "CA Name", nil)
	if err != nil {
		t.Fatal("Failed creating certificate authority:", err)
	}
	_, err = CreateCertificateRevocationList(key, crt, time.Now().AddDate(5, 0, 0))
	if err != nil {
		t.Fatal("Failed creating crl:", err)
	}
}

func TestCertificateRevocationList(t *testing.T) {
	csr, err := NewCertificateRevocationListFromPEM([]byte(crlPEM))
	if err != nil {
		t.Fatal("Failed parsing CRL from PEM:", err)
	}

	pemBytes, err := csr.Export()
	if err != nil {
		t.Fatal("Failed exporting PEM-format bytes:", err)
	}
	if bytes.Compare(pemBytes, []byte(crlPEM)) != 0 {
		t.Fatal("Failed exporting the same PEM-format bytes")
	}
}
