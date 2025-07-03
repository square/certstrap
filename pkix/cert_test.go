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

	// ./certstrap init --c "USA" -o "etcd-ca" --ou "CA" --cn "CA"
	certAuthPEM = `-----BEGIN CERTIFICATE-----
MIIFNDCCAxygAwIBAgIBATANBgkqhkiG9w0BAQsFADA6MQwwCgYDVQQGEwNVU0Ex
EDAOBgNVBAoTB2V0Y2QtY2ExCzAJBgNVBAsTAkNBMQswCQYDVQQDEwJDQTAeFw0y
NTA3MDIyMzA5MzVaFw0yNzAxMDIyMzE5MzNaMDoxDDAKBgNVBAYTA1VTQTEQMA4G
A1UEChMHZXRjZC1jYTELMAkGA1UECxMCQ0ExCzAJBgNVBAMTAkNBMIICIjANBgkq
hkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA0yNmBdiP1mI6qpUhIs7iN4kGVIOG36cF
ez53lsjDNUn1L/nqcOlRNRacpgJkhBvMb/SEVv0muLC0b+bHJLGThIKJQyi1/CcG
LiXFLKjuyx8VSsKCuROhp4LZLMLpUhcftXB+NMUUkJOCQPeytvFvpYeOD7rKVK3L
Xf2PtZpIYQrBkmAcdwkqoVhTuvPqw5apOdURC+9rb9utJauaEkEhVrH1rrW9OBUN
be0Xu5isMzEHohSfeeAqIdR1PPrMRmc8eEfEbWKXf8Jzwri0F7Phrfxtxz9eT3yA
TpNr8b5G1XZIc9sKUG7q+8BV4rgLpAjd/n3+7vaF7JGyd7ohip3tIzdf/N7jwW+8
G7JQWRDJwf52EGmM3miEyBMef/B9lprjSO+bHRyjEAjWU7G+Muy29mKi7l3h+3XR
dBler2mLfsaqYjFmSVkX3Uf4ENUau26v3jiVJBzLBHarg4FTcABX3S96UiQivc50
zp1wSkTEcnZjYsGcqgZKnLDK6X4ThwAGfPlkJbK7uEh4fLtk9mVfjDPu4fgp5b52
MsCdXp/FGbnOpDGAEGTgsTq6KKPCRIxU5bTH38v/j2MI3MSNyfsb73PnMnqqApNQ
3Mrkwb7UmdVK9dadlDn6X47GKKmg7MqKeJ4Xxo8j32LWCdpGT09myWrh06hsrqAH
E8Zm1vmrsOsCAwEAAaNFMEMwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYB
Af8CAQAwHQYDVR0OBBYEFIMTOTmZTYIKOYoj2Y17xmyVKi0FMA0GCSqGSIb3DQEB
CwUAA4ICAQAq1FtkMNR+4SMf1ojaNxvEIYbp759XDOUS0IuWPTrWYxgdjoJoc9Wp
0JRSDqADI5SdwSuNUbJ+H+YydZ4Dq9PTfgKxN0kHrK40e13F1G/qZ1V00+mNI5Zr
vGKK5rzIfWyv1elnwcoh04k8l/EO9azhF+bUY4VKQEIjc26zHZwdQfcPRGSlfh2m
DsjTUcGCa6J4vty98Z29rRrmO1KConAc1aI/GWCDDogCzHTeBJG4MAvzwtPe4oCs
h8awwy7HqQRyKWxVtfh+3yRrx4fE4IDHXlaGj1Y2eiR31r3DjA2VdOepebHY/rzu
FmrlNWAlu5EpucfquI5bPgxANVGKVXTxsVztclsoKeqm7w1mLJXbEiuJihKwmfyA
0KjSnKzoFP4l72o15bGUMWr7jvSRJYGVCTuUEMcpAWWvohS4d4m0tBjfEimDkDwZ
TyrpFueAWCw7XI19IAa79ileVJvxN2Pnp3dEdaYpKEPsxfjXQyofG6m9eG7GVdgh
KbtjRZJ1xKUeBH0u0yHIhSAvjYeOHcWF/mhQSO9gwanciI5FnsG5zYjFcSj5qcY+
PWK1J5ZtavbbdYJCAVoKsMQKSzNemzqATIQmoCeRt5ztyt8Za/mN1KFnCgbwSFTn
GYUrZo1+6jMH+1oBLLex8YV6uJxoM9SoFqRMq4poMlSlLmk5sX4JiA==
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
	// ./certstrap request-cert --c "USA" -o "etcd-ca" --ou "host1" --cn "host1"
	// ./certstrap sign host1 --CA CA
	certHostPEM = `-----BEGIN CERTIFICATE-----
MIIEdTCCAl2gAwIBAgIQD9oO6SirviOMj1tTCD2FEDANBgkqhkiG9w0BAQsFADA6
MQwwCgYDVQQGEwNVU0ExEDAOBgNVBAoTB2V0Y2QtY2ExCzAJBgNVBAsTAkNBMQsw
CQYDVQQDEwJDQTAeFw0yNTA3MDIyMzE0MjZaFw0yNzAxMDIyMzE5MzNaMEAxDDAK
BgNVBAYTA1VTQTEQMA4GA1UEChMHZXRjZC1jYTEOMAwGA1UECxMFaG9zdDExDjAM
BgNVBAMTBWhvc3QxMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAucbb
gMKFM0HiYdYwqLHgAsA/0dytfFYObnPNPLFSMpKKEYxRSHVRKBFfm8ce6ivVDBEN
AN75VqQdi0qPh2tYDs1XFcJM6AU9TPiWPFoMq00e+SyFqwR7s0SRJOfIt4VA0ggG
rVdtjrWTlCv5EjpS1lTapMelZfoiNomebrKmfCMo9+VTjK32Hx8ncM1NNzVgq6rM
uts0Yc27AeiTm7lZbUjm6TDAElzUREnT90i/IPEm4VHX8eWxtpaBU+Aals7lSftf
aRESyTlu+b/lvH8WHfRqrCFpSNgBKimIP0+eSsaSs+K8tQ1QgEQtt7CLjlLCVYU6
H5k5oF+jA3VRM96aQQIDAQABo3EwbzAOBgNVHQ8BAf8EBAMCA7gwHQYDVR0lBBYw
FAYIKwYBBQUHAwEGCCsGAQUFBwMCMB0GA1UdDgQWBBQ3KvRJ3MhCjTittRUR5erx
/DldSzAfBgNVHSMEGDAWgBSDEzk5mU2CCjmKI9mNe8ZslSotBTANBgkqhkiG9w0B
AQsFAAOCAgEAO6VLumsg5D3INYK/B0ITHPf5StdeQRGEIfZZmdKmZfkcdfIedRjB
S9GxJ44twdKTLVQhje4IAEMxcy7o5vWCScVtV8c+jq+KKBY8wpUgtBFKULdB86sO
Iiaf1rDgFEKmu+ksfX8DY8BQJJpZ4bqUQPqkyD7bfTN7FHBIMHQVsQAvnr0SDnd1
ei0+CO4J1BZq+jFQA8LLdvpXrdMW+AzbalE/HaW2A2HZD0fBHmWYuHWqO8RFPEmX
If12xgHw6c9uskVu+SqXkaFoYf4Wg5MgYM9C/QKZgV7uooy2dHIJH+n9U3Js3dCs
2RIFinyw2MpQ0ULAduqN9R5Oppzzcw3P21bYFBf2kEwy5OLYoV2JkPVUoIZDBphk
Olm5oHoz99qG4ufzo7nPUV5WbebInfY2Ql4Fua8nR4FEkc8MXyPEmEphqXwyJsS+
OH93trtyP7TMTDH43euAzVzz4E0pcwNXL4g/U6pElLIvtR8FCt/TOliWxIOtJlhU
JZgrj2oQd85Ppp5AxcFBaDvXU5qFd5DlwDEQOIcV716OCvnP8X5Y9JO7C6gjvyGQ
bIk5R1WNw9pUy5QOETnWIEJOj06Q70dFEO1LGSt1bg4PDZ8lwJ/BWDd05NvioXPR
fRlokuzJaHNz3Y12aeaiypLowGhjfDISujswNl5be3vDDjKcwCwa/yE=
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
