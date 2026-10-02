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
	"crypto/elliptic"
	"crypto/x509"
	"math/big"
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
	tests := []struct {
		name      string
		createKey func() (*Key, error)
		algorithm x509.SignatureAlgorithm
	}{{
		name:      "RSA",
		createKey: func() (*Key, error) { return CreateRSAKey(rsaBits) },
		algorithm: x509.SHA256WithRSA,
	}, {
		name:      "ECDSA P-224",
		createKey: func() (*Key, error) { return CreateECDSAKey(elliptic.P224()) },
		algorithm: x509.ECDSAWithSHA256,
	}, {
		name:      "ECDSA P-256",
		createKey: func() (*Key, error) { return CreateECDSAKey(elliptic.P256()) },
		algorithm: x509.ECDSAWithSHA256,
	}, {
		name:      "ECDSA P-384",
		createKey: func() (*Key, error) { return CreateECDSAKey(elliptic.P384()) },
		algorithm: x509.ECDSAWithSHA384,
	}, {
		name:      "ECDSA P-521",
		createKey: func() (*Key, error) { return CreateECDSAKey(elliptic.P521()) },
		algorithm: x509.ECDSAWithSHA512,
	}, {
		name:      "Ed25519",
		createKey: CreateEd25519Key,
		algorithm: x509.PureEd25519,
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			key, err := tc.createKey()
			if err != nil {
				t.Fatal("Failed creating key:", err)
			}

			expiry := time.Now().AddDate(5, 0, 0)
			crt, err := CreateCertificateAuthority(key, "OU", expiry, "test", "US", "California", "San Francisco", "CA Name", nil)
			if err != nil {
				t.Fatal("Failed creating certificate authority:", err)
			}
			rawCrt, err := crt.GetRawCertificate()
			if err != nil {
				t.Fatal("Failed to get x509.Certificate:", err)
			}

			before := time.Now().Truncate(time.Second)
			crl, err := CreateCertificateRevocationList(key, crt, expiry)
			if err != nil {
				t.Fatal("Failed creating crl:", err)
			}

			list, err := x509.ParseRevocationList(crl.DERBytes())
			if err != nil {
				t.Fatal("Failed parsing crl:", err)
			}
			if err := list.CheckSignatureFrom(rawCrt); err != nil {
				t.Fatal("Failed to check crl signature:", err)
			}
			if list.SignatureAlgorithm != tc.algorithm {
				t.Fatalf("SignatureAlgorithm = %v, want %v", list.SignatureAlgorithm, tc.algorithm)
			}
			if !bytes.Equal(list.RawIssuer, rawCrt.RawSubject) {
				t.Fatal("CRL issuer does not match the CA subject")
			}
			if !bytes.Equal(list.AuthorityKeyId, rawCrt.SubjectKeyId) {
				t.Fatal("CRL authority key ID does not match the CA subject key ID")
			}
			if list.Number == nil || list.Number.Cmp(big.NewInt(1)) != 0 {
				t.Fatalf("Number = %v, want 1", list.Number)
			}
			if len(list.RevokedCertificateEntries) != 0 {
				t.Fatalf("got %d revoked certificates, want none", len(list.RevokedCertificateEntries))
			}
			if list.ThisUpdate.Before(before) || list.ThisUpdate.After(time.Now()) {
				t.Fatalf("ThisUpdate = %v, want the time of creation", list.ThisUpdate)
			}
			if !list.NextUpdate.Equal(expiry.Truncate(time.Second)) {
				t.Fatalf("NextUpdate = %v, want %v", list.NextUpdate, expiry)
			}
		})
	}
}

// TestCreateCertificateRevocationListElapsedExpiry covers init computing the
// expiry before generating the key, which can take longer than a short
// --expires, so the expiry has already passed when the CRL is created.
func TestCreateCertificateRevocationListElapsedExpiry(t *testing.T) {
	key, err := CreateRSAKey(rsaBits)
	if err != nil {
		t.Fatal("Failed creating rsa key:", err)
	}
	crt, err := CreateCertificateAuthority(key, "OU", time.Now().AddDate(5, 0, 0), "test", "US", "California", "San Francisco", "CA Name", nil)
	if err != nil {
		t.Fatal("Failed creating certificate authority:", err)
	}
	rawCrt, err := crt.GetRawCertificate()
	if err != nil {
		t.Fatal("Failed to get x509.Certificate:", err)
	}

	expiry := time.Now().Add(-time.Minute)
	crl, err := CreateCertificateRevocationList(key, crt, expiry)
	if err != nil {
		t.Fatal("Failed creating crl:", err)
	}

	list, err := x509.ParseRevocationList(crl.DERBytes())
	if err != nil {
		t.Fatal("Failed parsing crl:", err)
	}
	if err := list.CheckSignatureFrom(rawCrt); err != nil {
		t.Fatal("Failed to check crl signature:", err)
	}
	if !list.NextUpdate.Equal(expiry.Truncate(time.Second)) {
		t.Fatalf("NextUpdate = %v, want %v", list.NextUpdate, expiry)
	}
	if list.ThisUpdate.After(list.NextUpdate) {
		t.Fatalf("ThisUpdate = %v is after NextUpdate = %v", list.ThisUpdate, list.NextUpdate)
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
	if !bytes.Equal(pemBytes, []byte(crlPEM)) {
		t.Fatal("Failed exporting the same PEM-format bytes")
	}
}
