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
	"bytes"
	"testing"
	"time"
)

const (
	// hostname used by CA certificate
	authHostname = "CA"

	certAuthPEM = `-----BEGIN CERTIFICATE-----
MIICLzCCAZqgAwIBAgIBATALBgkqhkiG9w0BAQUwLTEMMAoGA1UEBhMDVVNBMRAw
DgYDVQQKEwdldGNkLWNhMQswCQYDVQQLEwJDQTAeFw0xNDAzMTMwMTE4NTBaFw0y
NDAzMTMwMTE4NTBaMC0xDDAKBgNVBAYTA1VTQTEQMA4GA1UEChMHZXRjZC1jYTEL
MAkGA1UECxMCQ0EwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAJ+IiwNRCU8n
pYJ2OUBI3YLpI2eFkOt2rYuehP0gDBRjA310hI6NKDIZ6hlM9WuXqpA3jySn7FvT
OCStboFf4GJTb9UlR/3toREoQielDw58pqM6Henwz+rBm3Os0pMWV91EhNBgaIvQ
lN9CgNDXRi7cm6wnC3mxSvPqi8XAEfevAgMBAAGjYzBhMA4GA1UdDwEB/wQEAwIA
BDAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTmshC5nXrRi1p+DlPttajDoTQU
YDAfBgNVHSMEGDAWgBTmshC5nXrRi1p+DlPttajDoTQUYDALBgkqhkiG9w0BAQUD
gYEARkl9T2RhTqb1JQzxl0y4uUdWsHzF934uQUpZtAxjUgSbeOlv8vXnsNVjq50O
hQLirtJOHrOz3fljhBYsLlkTV8zxen296NrNdajJL7O2eTka2zb5v4Us8LIbcw1z
2nubiYeMKUHnBlLwXZfG37cnedSk7fjGoFgpCvtWrTxHUng=
-----END CERTIFICATE-----
`
	badCertAuthPEM = `-----BEGIN CERTIFICATE-----
MIIB9zCCAWKgAwIBAgIBATALBgkqhkiG9w0BAQUwMTEMMAoGA1UEBhMDVVNBMRQw
EgYAVQQKEwtDb3JlT1MgSW5jLjELMAkGA1UEAxMCQ0EwHhcNMTQwMzA5MjE1NDI5
WhcNMjQwMzA5MjI1NDI5WjAxMQwwCgYDVQQGEwNVU0ExFDASBgNVBAoTC0NvcmVP
UyBJbmMuMQswCQYDVQQDEwJDQTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA
xLZYiSaYRWC90r/W+3cVFI6NnWfEo9Wrbn/PsJRz+Nn1NURuLpYWrMSZa1ihipVr
bPY9Xi8Xo5YCll2z9RcWoVp0ASU1VxctXKWbsk/lqnAKDX+/lTW4iKERUF67NOlR
GFtBzq7iVPQT7qNYCMu3CRG/4cTuOcCglH/xE9HdgdcCAwEAAaMjMCEwDgYDVR0P
AQH/BAQDAgAEMA8GA1UdEwEB/wQFMAMBAf8wCwYJKoZIhvcNAQEFA4GBAL129Vc3
lcfYfSfI2fMgkG3hc2Yhtu/SJ7wRFqlrNBM9lnNJnYMF+fAWv6u8xix8OWfYs38U
BB6sTriDpe5oo2H0o7Pf5ACE3IIy2Cf2+HAmNClYrdlwNYfP7aUazbEhuzPcvJYA
zPNy61oRnsETV77BH+JQ7j4E+pAJ5MHpKUcq
-----END CERTIFICATE-----
`
	wrongCertAuthPEM = `-----BEGIN WRONG CERTIFICATE-----
MIIB9zCCAWKgAwIBAgIBATALBgkqhkiG9w0BAQUwMTEMMAoGA1UEBhMDVVNBMRQw
EgYDVQQKEwtDb3JlT1MgSW5jLjELMAkGA1UEAxMCQ0EwHhcNMTQwMzA5MTgzMzQx
WhcNMjQwMzA5MTkzMzQxWjAxMQwwCgYDVQQGEwNVU0ExFDASBgNVBAoTC0NvcmVP
UyBJbmMuMQswCQYDVQQDEwJDQTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA
ptSfk77PDDWYiNholqgPyQwtnf7hmoFGEqiA4Cu0u+LW7vLqkysaXHUVjQH/ditJ
FPlvwsllgPbgCF9bUzrCbXbrV2xjIhairyOGFSrLGBZMIB91xHXPlFhy2U+4Piio
bisrv2InHvPTyyZqVbqLDhF8DmVMIZI/UCOKtCMSrN8CAwEAAaMjMCEwDgYDVR0P
AQH/BAQDAgAEMA8GA1UdEwEB/wQFMAMBAf8wCwYJKoZIhvcNAQEFA4GBAHKzf9iH
fKUdWUz5Ue8a1yRRTu5EuGK3pz22x6udcIYH6KFBPVfj5lSbbE3NirE7TKWvF2on
SCP/620bWJMxqNAYdwpiyGibsiUlueWB/3aavoq10MIHA6MBxw/wrsoLPns9f7dP
+ddM40NjuI1tvX6SnUwuahONdvUJDxqVR+AM
-----END WRONG CERTIFICATE-----
`
	certHostPEM = `-----BEGIN CERTIFICATE-----
MIICVTCCAcCgAwIBAgIBAjALBgkqhkiG9w0BAQUwLTEMMAoGA1UEBhMDVVNBMRAw
DgYDVQQKEwdldGNkLWNhMQswCQYDVQQLEwJDQTAeFw0xNDAzMTMwMTMyMjRaFw0y
NDAzMTMwMTMyMjRaMEQxDDAKBgNVBAYTA1VTQTEQMA4GA1UEChMHZXRjZC1jYTEO
MAwGA1UECxMFaG9zdDExEjAQBgNVBAMTCTEyNy4wLjAuMTCBnzANBgkqhkiG9w0B
AQEFAAOBjQAwgYkCgYEA13e693MWlI4/69SsselpaYW79NZsirZ1UX6oE9pffU16
rsRyEzcrpFDUvN2ehkXHm6R+iW7/ALvt2Q52uMspzXIfE+zSHXCT2Sz75TVYlqHj
49F9PcS0MVWAGq0Yh+RyGxTK74Xb9fQmYpq3WHTjDxLe9MP/4AntvTBMTYNn7csC
AwEAAaNyMHAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMB0GA1UdDgQW
BBSbN7QVtzzdDs/pnWBxwE10Woki8TAfBgNVHSMEGDAWgBTmshC5nXrRi1p+DlPt
tajDoTQUYDAPBgNVHREECDAGhwR/AAABMAsGCSqGSIb3DQEBBQOBgQA3Yj6FYMok
4bM3e01mcO+j+wRgcuux9hnfvcL8jjhCylGcRaHdWyq6GiKJYx4yQPcYpW2u1IEr
yVmg5buKT9uJrtJEwLNH1gAkFoKwG2YCmraa5mnBPNv2JuTQtO2m4fmpu+eyJA1r
uqLlOR3tvfiiJpjaegHCfPw+3p2dsufN7g==
-----END CERTIFICATE-----
`
)

func TestCertificateAuthority(t *testing.T) {
	crt, err := NewCertificateFromPEM([]byte(certAuthPEM))
	if err != nil {
		t.Fatal("Failed to parse certificate from PEM:", err)
	}

	if err = crt.CheckAuthority(); err != nil {
		t.Fatal("Failed to check self-sign:", err)
	}

	if err = crt.VerifyHost(crt, authHostname); err != nil {
		t.Fatal("Failed to verify CA:", err)
	}

	duration := crt.GetExpirationDuration()
	expireDate, _ := time.Parse("2006-Jan-02", "2024-Feb-03")
	if !time.Now().Add(duration).After(expireDate) {
		t.Fatal("Failed to get correct expiration")
	}

	pemBytes, err := crt.Export()
	if err != nil {
		t.Fatal("Failed exporting PEM-format bytes:", err)
	}
	if !bytes.Equal(pemBytes, []byte(certAuthPEM)) {
		t.Fatal("Failed exporting the same PEM-format bytes")
	}
}

func TestWrongCertificate(t *testing.T) {
	if _, err := NewCertificateFromPEM([]byte("-")); err == nil {
		t.Fatal("Expect not to parse certificate from PEM:", err)
	}

	if _, err := NewCertificateFromPEM([]byte(wrongCertAuthPEM)); err == nil {
		t.Fatal("Expect not to parse certificate from PEM:", err)
	}
}

func TestBadCertificate(t *testing.T) {
	crt, err := NewCertificateFromPEM([]byte(badCertAuthPEM))
	if err != nil {
		t.Fatal("Failed to parse certificate from PEM:", err)
	}

	if _, err = crt.GetRawCertificate(); err == nil {
		t.Fatal("Expect not to get x509.Certificate")
	}

	if err = crt.CheckAuthority(); err == nil {
		t.Fatal("Expect not to get x509.Certificate")
	}

	if err = crt.VerifyHost(crt, authHostname); err == nil {
		t.Fatal("Expect not to get x509.Certificate")
	}

	if duration := crt.GetExpirationDuration(); duration.Hours() >= 0 {
		t.Fatal("Expect not to get positive duration")
	}

	pemBytes, err := crt.Export()
	if err != nil {
		t.Fatal("Failed exporting PEM-format bytes:", err)
	}
	if !bytes.Equal(pemBytes, []byte(badCertAuthPEM)) {
		t.Fatal("Failed exporting the same PEM-format bytes")
	}
}

func TestCertificateVerify(t *testing.T) {
	crtAuth, err := NewCertificateFromPEM([]byte(certAuthPEM))
	if err != nil {
		t.Fatal("Failed to parse certificate from PEM:", err)
	}

	crtHost, err := NewCertificateFromPEM([]byte(certHostPEM))
	if err != nil {
		t.Fatal("Failed to parse certificate from PEM:", err)
	}

	if err = crtAuth.VerifyHost(crtHost, csrHostname); err != nil {
		t.Fatal("Verify certificate host from CA:", err)
	}
}
