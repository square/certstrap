/*-
 * Copyright 2015 Square Inc.
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
)

const (
	csrHostname = "host1"
	csrCN       = "CN"
	csrPEM      = `-----BEGIN CERTIFICATE REQUEST-----
MIIBgTCB7QIBADBGMQwwCgYDVQQGEwNVU0ExEDAOBgNVBAoTB2V0Y2QtY2ExEDAO
BgNVBAsTB3NlcnZlcjIxEjAQBgNVBAMTCTEyNy4wLjAuMTCBnTALBgkqhkiG9w0B
AQEDgY0AMIGJAoGBAMTO2QZgrM9RXjfZTn9LWQZ0Y5B+Uh0+z4mEiXIbKno/omW3
dsEdxM9Er0dAw4zBS5lr0QUymy2AZlJo078Bgz1KyEVKS48udvv404HnBc6fDhUC
3aax/V2aiX3SFPj8SLLy2h7hJBkIikwuSYo2ajuq69FgA0pd8UHtEsKhokyZAgMB
AAGgADALBgkqhkiG9w0BAQUDgYEAhsgW8OvSeJN3w+0IDGLx12WYbHUD44yV5VzV
Jp3vi0CaLKA4mNh6rlxhYFVX5AUlaSGKwVkn3M9br/apfP14esIRnuq+nZd7BtU1
13tL4D+UCnGHN5iYIb8stB7UVwuXNxnqUfJqiO4zoYNmrcBpssYuHVZ7to7Xvxu+
5iyRRSg=
-----END CERTIFICATE REQUEST-----
`
	wrongCSRPEM = `-----BEGIN WRONG CERTIFICATE REQUEST-----
MIIBgTCB7QIBADBGMQwwCgYDVQQGEwNVU0ExEDAOBgNVBAoTB2V0Y2QtY2ExEDAO
BgNVBAsTB3NlcnZlcjIxEjAQBgNVBAMTCTEyNy4wLjAuMTCBnTALBgkqhkiG9w0B
AQEDgY0AMIGJAoGBAMTO2QZgrM9RXjfZTn9LWQZ0Y5B+Uh0+z4mEiXIbKno/omW3
dsEdxM9Er0dAw4zBS5lr0QUymy2AZlJo078Bgz1KyEVKS48udvv404HnBc6fDhUC
3aax/V2aiX3SFPj8SLLy2h7hJBkIikwuSYo2ajuq69FgA0pd8UHtEsKhokyZAgMB
AAGgADALBgkqhkiG9w0BAQUDgYEAhsgW8OvSeJN3w+0IDGLx12WYbHUD44yV5VzV
Jp3vi0CaLKA4mNh6rlxhYFVX5AUlaSGKwVkn3M9br/apfP14esIRnuq+nZd7BtU1
13tL4D+UCnGHN5iYIb8stB7UVwuXNxnqUfJqiO4zoYNmrcBpssYuHVZ7to7Xvxu+
5iyRRSg=
-----END WRONG CERTIFICATE REQUEST-----
`
	badCSRPEM = `-----BEGIN CERTIFICATE REQUEST-----
MIIBgTCB7QIBADBGMQwwCgYDVQQGEwNVU0ExEDAOBgNVBAoTB2V0Y2QtY2ExEDAO
dsEdxM9Er0dAw4zBS5lr0QUymy2AZlJo078Bgz1KyEVKS48udvv404HnBc6fDhUC
3aax/V2aiX3SFPj8SLLy2h7hJBkIikwuSYo2ajuq69FgA0pd8UHtEsKhokyZAgMB
AAGgADALBgkqhkiG9w0BAQUDgYEAhsgW8OvSeJN3w+0IDGLx12WYbHUD44yV5VzV
Jp3vi0CaLKA4mNh6rlxhYFVX5AUlaSGKwVkn3M9br/apfP14esIRnuq+nZd7BtU1
13tL4D+UCnGHN5iYIb8stB7UVwuXNxnqUfJqiO4zoYNmrcBpssYuHVZ7to7Xvxu+
5iyRRSg=
-----END CERTIFICATE REQUEST-----
`
)

func TestCreateCertificateSigningRequest(t *testing.T) {
	key, err := CreateRSAKey(rsaBits)
	if err != nil {
		t.Fatal("Failed creating rsa key:", err)
	}

	csr, err := CreateCertificateSigningRequest(key, csrHostname, nil, nil, "example", "US", "California", "San Francisco", csrCN)
	if err != nil {
		t.Fatal("Failed creating certificate request:", err)
	}

	if err = csr.CheckSignature(); err != nil {
		t.Fatal("Failed cheching signature in certificate request:", err)
	}

	rawCsr, err := csr.GetRawCertificateSigningRequest()
	if err != nil {
		t.Fatal("Failed getting raw certificate request:", err)
	}

	if csrHostname != rawCsr.Subject.OrganizationalUnit[0] {
		t.Fatalf("Expect OrganizationalUnit to be %v instead of %v", csrHostname, rawCsr.Subject.OrganizationalUnit[0])
	}
	if csrCN != rawCsr.Subject.CommonName {
		t.Fatalf("Expect CommonName to be %v instead of %v", csrCN, rawCsr.Subject.CommonName)
	}
}

func TestCertificateSigningRequest(t *testing.T) {
	csr, err := NewCertificateSigningRequestFromPEM([]byte(csrPEM))
	if err != nil {
		t.Fatal("Failed parsing certificate request from PEM:", err)
	}

	if err = csr.CheckSignature(); err != nil {
		t.Fatal("Failed checking signature:", err)
	}

	pemBytes, err := csr.Export()
	if err != nil {
		t.Fatal("Failed exporting PEM-format bytes:", err)
	}
	if bytes.Compare(pemBytes, []byte(csrPEM)) != 0 {
		t.Fatal("Failed exporting the same PEM-format bytes")
	}
}

func TestWrongCertificateSigningRequest(t *testing.T) {
	if _, err := NewCertificateSigningRequestFromPEM([]byte("-")); err == nil {
		t.Fatal("Expect not to parse from PEM:", err)
	}

	if _, err := NewCertificateSigningRequestFromPEM([]byte(wrongCSRPEM)); err == nil {
		t.Fatal("Expect not to parse from PEM:", err)
	}
}

func TestBadCertificateSigningRequest(t *testing.T) {
	csr, err := NewCertificateSigningRequestFromPEM([]byte(badCSRPEM))
	if err != nil {
		t.Fatal("Failed to parse from PEM:", err)
	}

	if _, err = csr.GetRawCertificateSigningRequest(); err == nil {
		t.Fatal("Expect not to get x509.CertificateRequest")
	}

	if err = csr.CheckSignature(); err == nil {
		t.Fatal("Expect not to get x509.CertificateRequest")
	}
}
