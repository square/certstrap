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
	"crypto/x509"

	"bytes"
	"testing"
	"time"
)

func TestCreateCertificateHost(t *testing.T) {
	crtAuth, err := NewCertificateFromPEM([]byte(certAuthPEM))
	if err != nil {
		t.Fatal("Failed to parse certificate from PEM:", err)
	}

	key, err := NewKeyFromPrivateKeyPEM([]byte(rsaPrivKeyAuthPEM))
	if err != nil {
		t.Fatal("Failed parsing RSA private key:", err)
	}

	csr, err := NewCertificateSigningRequestFromPEM([]byte(csrPEM))
	if err != nil {
		t.Fatal("Failed parsing certificate request from PEM:", err)
	}

	crt, err := CreateCertificateHost(crtAuth, key, csr, time.Now().AddDate(5000, 0, 0))
	if err != nil {
		t.Fatal("Failed creating certificate for host:", err)
	}
	if crt.GetExpirationDuration() > crtAuth.GetExpirationDuration() {
		t.Fatal("Cert expires after issuer")
	}
	rawCrt, err := crt.GetRawCertificate()
	if err != nil {
		t.Fatal("Failed to get x509.Certificate:", err)
	}

	rawCsr, err := csr.GetRawCertificateSigningRequest()
	if err != nil {
		t.Fatal("Failed to get x509.Certificate:", err)
	}
	if !bytes.Equal(rawCrt.RawSubject, rawCsr.RawSubject) {
		t.Fatalf("Failed to preserve subject: %s %s", rawCrt.RawSubject, rawCsr.RawSubject)
	}

	rawCrtAuth, err := crtAuth.GetRawCertificate()
	if err != nil {
		t.Fatal("Failed to get x509.Certificate:", err)
	}
	if err = rawCrt.CheckSignatureFrom(rawCrtAuth); err != nil {
		t.Fatal("Failed to check signature:", err)
	}

	extKeyUsage := []x509.ExtKeyUsage{
		x509.ExtKeyUsageCodeSigning,
	}
	cscrt, err := CreateCertificateHostWithExtUsage(crtAuth, key, csr, time.Now().AddDate(5000, 0, 0), extKeyUsage)
	if err != nil {
		t.Fatal("Failed creating certificate with codesigning for host:", err)
	}

	csrawCrt, err := cscrt.GetRawCertificate()
	if err != nil {
		t.Fatal("Failed to get x509.Certificate with codesigning:", err)
	}

	hasCodeSigning := false
	for _, eku := range csrawCrt.ExtKeyUsage {
		if eku == x509.ExtKeyUsageCodeSigning {
			hasCodeSigning = true
		}
	}

	if !hasCodeSigning {
		t.Fatal("x509.Certificate does not include codesigning extra key usage")
	}

}
