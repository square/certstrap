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
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
	"testing"
)

const (
	// ./certstrap init --c "USA" -o "etcd-ca" --ou "CA" --cn "CA"
	rsaPrivKeyAuthPEM = `-----BEGIN RSA PRIVATE KEY-----
MIIJKQIBAAKCAgEA0yNmBdiP1mI6qpUhIs7iN4kGVIOG36cFez53lsjDNUn1L/nq
cOlRNRacpgJkhBvMb/SEVv0muLC0b+bHJLGThIKJQyi1/CcGLiXFLKjuyx8VSsKC
uROhp4LZLMLpUhcftXB+NMUUkJOCQPeytvFvpYeOD7rKVK3LXf2PtZpIYQrBkmAc
dwkqoVhTuvPqw5apOdURC+9rb9utJauaEkEhVrH1rrW9OBUNbe0Xu5isMzEHohSf
eeAqIdR1PPrMRmc8eEfEbWKXf8Jzwri0F7Phrfxtxz9eT3yATpNr8b5G1XZIc9sK
UG7q+8BV4rgLpAjd/n3+7vaF7JGyd7ohip3tIzdf/N7jwW+8G7JQWRDJwf52EGmM
3miEyBMef/B9lprjSO+bHRyjEAjWU7G+Muy29mKi7l3h+3XRdBler2mLfsaqYjFm
SVkX3Uf4ENUau26v3jiVJBzLBHarg4FTcABX3S96UiQivc50zp1wSkTEcnZjYsGc
qgZKnLDK6X4ThwAGfPlkJbK7uEh4fLtk9mVfjDPu4fgp5b52MsCdXp/FGbnOpDGA
EGTgsTq6KKPCRIxU5bTH38v/j2MI3MSNyfsb73PnMnqqApNQ3Mrkwb7UmdVK9dad
lDn6X47GKKmg7MqKeJ4Xxo8j32LWCdpGT09myWrh06hsrqAHE8Zm1vmrsOsCAwEA
AQKCAgBBZlmXvfjv4wVhCUh2S7bulNcNHqCMbmPYRQUuA4nT29DCx5rC1sJ8u0BS
e7M+6I1usEK93zQ7SSDa+JT+3LJg/T4fO2EDdeMIMFLe/oTZDgu+WHm9ckNEa9dx
cf5rmxYLUYkGN3WjQs256f/FgwueLlrmrGk3yY2Q05XMHroEtRw4huTKSmCWEZH9
+sfhRa2taD4bgFG7GESNwpW6ycnV3NHJCCpQUNUUE7iiNyw/vxQqNFEhoznpuLGH
7feQZzHn3/MMHtnmjQjma+f8348sIWCvswU3gc0MicWJ3/J49GaE3HhZacIHsQ/p
ZjDU4ppA1i49PsdE++xYAaOaGEj3a2Mo3QSb3lc2fBnxiOHyWOA8ICaF5iCRWFYM
MIS+moBIXaLONY9LXw3FBmwYw5+fRRX5SAsznbQ+mA18PBP4mziteeqAlVFQzuel
JCiCRlcP+j/xT/uExI0YLLAQfqNGv+LDxTslEv3B3IjErOYgcCy8/d9HKoFcMmj2
SYFWUdkckPzasMtuFofHsqE84TL74p3vUy75SDWni9PlKdqxl+O9FkhMF0SjUsE9
t2RQjjE8dpaZZko1z41E7fQ2jPZmH8UEbwCg15csm21kFSbLhCwp966ccUd3LWIY
XjxSNq/88Vn4Z1JfU0c94HB8cOL7zDrvvwx0stlXir733NVFIQKCAQEA3cUNegIw
fEPyBAkwM321qvp3yqRCek1FbU+kzruNBrycqQhFHwA6Ck8fNA1eiHH9GHqULxEO
G5MfEosRMqCX+354mDgMCk2JHO2uUICZs9gHT5pj0GEojXpC7HFz7BbWUhj4TXwr
8IN3Qh4+K72LzxTu/11bTNtArGp+bSxjXrlEbBIlqoBZ9vmZjqGALlsvW/CdnzqC
ERIXXajb81ss3SO/MJhrx6B68sU80Gqm5g5rfXivtN9X8+beKrVrWjEx1kNNS0V5
035+rQVos8EoHX6iz9VmMjiMf0S06tAUvSzOPkgR4gXp2jckS9dZk0RwUwBCC02D
r3RyfSxxR1XKdQKCAQEA87pB3eBLQGg2WcerLKandEnygYRnG6+Fj99x+b6eS5O+
6l+lSmRTKj+GKAYW1D+w8eqhVT9z7Ifs236q9PxLva/dDkKJYO0OtHFJ53NCe2tB
lMphqu8SCSZl1jQxQ0UlSuyUM5S79dEytLkwS4kt5qYB0yR1ZFSXI7zfQaLKZ/Rp
AGoD5T936zkycQBnTar2oBQ8XP32LNMI9L5SYIx8ZCQ/ucMkfl7MaHxOIbSiTyMV
R/erNhpdJL2ORf5ysLGZkmb1BirHS9ovEhgNZYj4AtykF0UGiNfC9VwnBFFrG2ls
abZCm4cZoVsjABpa9ReLZS0iG+IibG+XmY1+uBJh3wKCAQBa7M3ntjoW2OzDRtki
Y2o2nda7mLlA16mddcgGktLxbid1DlT4rukdDO+oMcsOel3gyXE0EvQLzjgxLB9y
+HEXxfS/xEr7dmq/F5wemXtrRylIM+60owEzcGs78hArPfnFU0OK0Vxakiw1SZ0H
5gEKeHS88pPaYRKVHlyTel2Lmr446P/UdidsoU2aMxEQ8IXsVizp+d0WDqrR1cfI
cRtl16At1nBqOpvuKXwTn4aqUEM2AGNZ7zBqab+xFwzav8zFInbwY53dXsGlQtB4
0rsVzLQILmBmOtUv4QWkOIgoP9SXqIjceLw2oeEZz0OEo8zB2xs48yEIsN+3/p67
Nqt5AoIBAQDlB8U3i7sLRiK00VXAesbnF0okfVgrAxCed1nyVzcHTEpekgyQUKB6
FgGqgLZZM5TCcDq1EhCMV9qzFF/wIVnHYYh4CvxvsbRcygypy3zQ36Rb/qYy679m
C8gstxUH4uU9d/14Ty8luzVL8K46fSk+Egeq8xrBcmAovCaL1j8f2uQE+Jq6hZ7Z
0wDcgYWRzbM+EGX8+MWpr5I98s8UXU/TBuE/XepgOhMZqJ3/PHA9r3kjDNC94Z5f
lSUqDwaVlf77PXbJGc/4LoqHFUUZgdGVVuN33mxakW5qBPPBMgVVWAcBe70xy43B
PBQy15FbuYlLRVNFIoY4odCzAezvao6/AoIBAQDD5U+ghaGdp44N/zOd0AthVjAx
oi4VMx6gLI78pNUT7IZHVUMn00878qv4VITscT3zY7EgdK+rNbg2R4+ZBRPO0tsC
kGHl6bXiB+XwINVtoFs/PZdx+xTNcoZ/SULkcRC/XQmwTgJe23Nr5IpQBcKHX9co
MWB0OY48H3Ur5vFnHSxjC3QwNMgOd7aLOyNu4Q7rbfM7GRBCQcbcKm58t0PkZKDO
ZNyf3gSt6If1fqnN5dUukPYSpP1e1975BYmBxOZuY+jVwqPoGfwWSmo4ZcGrPWK9
J4GydnVtTsMmp/zTN1cDG+1a6TourRQXclSVS9zR3NALJJnCgzCrKvm9L70/
-----END RSA PRIVATE KEY-----
`
	wrongRSAPrivKeyAuthPEM = `-----BEGIN WRONG RSA PRIVATE KEY-----
MIICWwIBAAKBgQCm1J+Tvs8MNZiI2GiWqA/JDC2d/uGagUYSqIDgK7S74tbu8uqT
KxpcdRWNAf92K0kU+W/CyWWA9uAIX1tTOsJtdutXbGMiFqKvI4YVKssYFkwgH3XE
dc+UWHLZT7g+KKhuKyu/Yice89PLJmpVuosOEXwOZUwhkj9QI4q0IxKs3wIDAQAB
AoGAHCjLfq64WAE76+1LShK4B2Fs2bxJ7EBhyYhzqGL4MLaLPO33tjuSSYThzFlH
+3Q287leqexAm9IP4pnl2liStI2X0eQqZAfX6gd/QQ4Rr7zI9URcd8UPKykKO8Lm
ghpDW+tuEV2A89/NUlcFKteLDYp1wCxCHNTAbY1R4QXVdYECQQDNlw4I/6RcSodX
veAYIQy9eSeAzgAwchtpzz+/7xWG95OUaadyZsPDQp2dmbJPKSGJ0v1cetieQ3ji
fb/qr7q/AkEAz7yfwW6v/M9vCqcxkik9I2VGiE5Xg11f7wX7eT0rwtfSPUpWPtgp
L1YF3FLi58xCxPUkzDlyQ+NZaYQ4roo14QJAQHC+h3eJzxvVPF1ZpnaFhcY56Zeo
W4cIrKu3cbPA7aMgcP6E68jmR4fT25hXWZSs3IRzwc8HouPHOkbsJuWaBQJAf2Yu
k3JOe7y7XM0smXaxCAQUPYPOJ8IcE3qXvsLFE7lINk5glin7GAypi3VJst6SFDhD
WPviF8BWFWABYwlgAQJAViX52BxO/KzLm+/QuTzVqKoqEZW+dqJx984TJug9Vy7h
IEzY0Lcuq3pwJlQyyaNQxXF4orPp5Rzi5pNabuGJ8Q==
-----END WRONG RSA PRIVATE KEY-----
`
	badRSAPrivKeyAuthPEM = `-----BEGIN RSA PRIVATE KEY-----
MIICWwIBAAKBgQCm1J+Tvs8MNZiI2GiWqA/JDC2d/uGagUYSqIDgK7S74tbu8uqT
dc+UWHLZT7g+KKhuKyu/Yice89PLJmpVuosOEXwOZUwhkj9QI4q0IxKs3wIDAQAB
ghpDW+tuEV2A89/NUlcFKteLDYp1wCxCHNTAbY1R4QXVdYECQQDNlw4I/6RcSodX
veAYIQy9eSeAzgAwchtpzz+/7xWG95OUaadyZsPDQp2dmbJPKSGJ0v1cetieQ3ji
fb/qr7q/AkEAz7yfwW6v/M9vCqcxkik9I2VGiE5Xg11f7wX7eT0rwtfSPUpWPtgp
L1YF3FLi58xCxPUkzDlyQ+NZaYQ4roo14QJAQHC+h3eJzxvVPF1ZpnaFhcY56Zeo
W4cIrKu3cbPA7aMgcP6E68jmR4fT25hXWZSs3IRzwc8HouPHOkbsJuWaBQJAf2Yu
k3JOe7y7XM0smXaxCAQUPYPOJ8IcE3qXvsLFE7lINk5glin7GAypi3VJst6SFDhD
IEzY0Lcuq3pwJlQyyaNQxXF4orPp5Rzi5pNabuGJ8Q==
-----END RSA PRIVATE KEY-----
`
	// openssl pkey -in out/CA.key -out out/CA.key.encrypted -des3 -traditional
	rsaEncryptedPrivKeyAuthPEM = `-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-EDE3-CBC,F1EF634443F5EE07

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
-----END RSA PRIVATE KEY-----
`
	p256PrivKeyPEM = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgxMg/54VIbzxz212o
g9ud2XLplNaPqi1jqadVuFXPxMOhRANCAARiNZ2xp1llazZyUjvjnsvRknFbUI9r
f8I43034ustdwkvgh+7TfZGeEHNmOwQi9RInxIAReFx2gUARYn2f1qnj
-----END PRIVATE KEY-----
`
	// Encrypted PKCS8 generated with openssl to ensure comaptibility.
	p256EncryptedPrivKeyPEM = `-----BEGIN ENCRYPTED PRIVATE KEY-----
MIHeMEkGCSqGSIb3DQEFDTA8MBsGCSqGSIb3DQEFDDAOBAgQo5EVNe/KkgICCAAw
HQYJYIZIAWUDBAEqBBBYCWWlK2TXfGNAf/dNVsUdBIGQP5aHz3sKokKkrLLKrxNv
t/HFn59QJPaagQm1IlK0LfwV6RMrKuJjAJ+bSFZit9/2iCLQw9yekyNbzcAuhihz
4CCMvvHCigtATIby3Bv/OhnHnpcsF4HVkXd1h0rKaV0xDK6xWYZ6d7KS2NJtaJAF
DBi43A9dlURMcw3/CYJ3jgzJGAP8nCm4omyNckloBaAa
-----END ENCRYPTED PRIVATE KEY-----
`
	ed25519PrivKeyPEM = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEINhpLppsFdDXk0P4mMq5kBHntPJGaaG27C1ZZYJCoWL3
-----END PRIVATE KEY-----
`
	// Encrypted PKCS8 generated with openssl to ensure comaptibility.
	ed25519EncryptedPrivKeyPEM = `-----BEGIN ENCRYPTED PRIVATE KEY-----
MIGbMFcGCSqGSIb3DQEFDTBKMCkGCSqGSIb3DQEFDDAcBAgaJGiyG0Hd8wICCAAw
DAYIKoZIhvcNAgkFADAdBglghkgBZQMEASoEEAKxHGl8qfK3DM9FKMWQAHUEQKu6
TL8589WqvDu8nE8ZrFwibbR9eMloekr89lqs1vJd7KJngUtXbW3XL2dtdSXzCGYF
T4rZH6EqxXGdvvmo1pw=
-----END ENCRYPTED PRIVATE KEY-----
`
	password      = "123456"
	wrongPassword = "654321"
	rsaBits       = 1024

	// openssl rsa -in out/CA.key -pubout | openssl asn1parse -strparse 19 -noout -out - | openssl dgst -binary -sha1 | openssl base64
	subjectKeyIDOfRSAPubKeyAuthBASE64 = "gxM5OZlNggo5iiPZjXvGbJUqLQU="
)

func TestCreateRSAKey(t *testing.T) {
	key, err := CreateRSAKey(rsaBits)
	if err != nil {
		t.Fatal("Failed creating rsa key:", err)
	}

	if err = key.Private.(*rsa.PrivateKey).Validate(); err != nil {
		t.Fatal("Failed to validate private key")
	}
}

func TestRSAKey(t *testing.T) {
	key, err := NewKeyFromPrivateKeyPEM([]byte(rsaPrivKeyAuthPEM))
	if err != nil {
		t.Fatal("Failed parsing RSA private key:", err)
	}

	if err = key.Private.(*rsa.PrivateKey).Validate(); err != nil {
		t.Fatal("Failed validating RSA private key:", err)
	}
}

func TestWrongRSAKey(t *testing.T) {
	key, err := NewKeyFromPrivateKeyPEM([]byte(".."))
	if key != nil || err == nil {
		t.Fatal("Expect not to parse RSA private key:", err)
	}

	key, err = NewKeyFromPrivateKeyPEM([]byte(wrongRSAPrivKeyAuthPEM))
	if key != nil || err == nil {
		t.Fatal("Expect not to parse RSA private key:", err)
	}
}

func TestBadRSAKey(t *testing.T) {
	key, err := NewKeyFromPrivateKeyPEM([]byte(badRSAPrivKeyAuthPEM))
	if key != nil || err == nil {
		t.Fatal("Expect not to parse bad RSA private key:", err)
	}
}

// TestRSAKeyExport tests the ability to convert rsa key into PEM bytes
func TestRSAKeyExport(t *testing.T) {
	key, err := NewKeyFromPrivateKeyPEM([]byte(rsaPrivKeyAuthPEM))
	if err != nil {
		t.Fatal("Failed to parse certificate from PEM:", err)
	}

	pemBytes, err := key.ExportPrivate()
	if err != nil {
		t.Fatal("Failed exporting PEM-format bytes:", err)
	}
	if !bytes.Equal(pemBytes, []byte(rsaPrivKeyAuthPEM)) {
		t.Fatal("Failed exporting the same PEM-format bytes")
	}
}

// TestRSAKeyExportEncrypted tests the ability to convert rsa key into encrypted PEM bytes
func TestRSAKeyExportEncrypted(t *testing.T) {
	key, err := NewKeyFromEncryptedPrivateKeyPEM([]byte(rsaEncryptedPrivKeyAuthPEM), []byte(password))
	if err != nil {
		t.Fatal("Failed to parse certificate from PEM:", err)
	}

	pemBytes, err := key.ExportPrivate()
	if err != nil {
		t.Fatal("Failed exporting PEM-format bytes:", err)
	}
	if !bytes.Equal(pemBytes, []byte(rsaPrivKeyAuthPEM)) {
		t.Fatal("Failed exporting the same PEM-format bytes")
	}

	pemBytes, err = key.ExportEncryptedPrivate([]byte(password))
	if err != nil {
		t.Fatal("Failed exporting PEM-format bytes:", err)
	}

	if _, err := NewKeyFromEncryptedPrivateKeyPEM(pemBytes, []byte(wrongPassword)); err == nil {
		t.Fatal("Expect not parsing certificate from PEM:", err)
	}
}

func TestRSAKeyGenerateSubjectKeyID(t *testing.T) {
	key, err := NewKeyFromPrivateKeyPEM([]byte(rsaPrivKeyAuthPEM))
	if err != nil {
		t.Fatal("Failed parsing RSA private key:", err)
	}

	id, err := GenerateSubjectKeyID(key.Public)
	if err != nil {
		t.Fatal("Failed generating SubjectKeyId:", err)
	}
	correctID, _ := base64.StdEncoding.DecodeString(subjectKeyIDOfRSAPubKeyAuthBASE64)
	if !bytes.Equal(id, correctID) {
		t.Fatal("Failed generating correct SubjectKeyId")
	}
}

func TestCreateECDSAKey(t *testing.T) {
	key, err := CreateECDSAKey(elliptic.P256())
	if err != nil {
		t.Fatalf("CreateECDSAKey(P256) failed: %v", err)
	}
	if _, ok := key.Private.(*ecdsa.PrivateKey); !ok {
		t.Fatal("CreateECDSAKey did not contain an ecdsa.PrivateKey")
	}
}

func TestCreateEd25519Key(t *testing.T) {
	key, err := CreateEd25519Key()
	if err != nil {
		t.Fatalf("CreateEd25519Key failed: %v", err)
	}
	if _, ok := key.Private.(ed25519.PrivateKey); !ok {
		t.Fatal("CreateEd25519Key did not contain an ed25519.PrivateKey")
	}
}

func TestECCExportImport(t *testing.T) {
	tests := []struct {
		desc string
		key  *Key
	}{{
		desc: "ECDSA P256",
		key: func() *Key {
			key, err := CreateECDSAKey(elliptic.P256())
			if err != nil {
				t.Fatalf("CreateECDSAKey(P256) failed: %v", err)
			}
			return key
		}(),
	}, {
		desc: "Ed25519",
		key: func() *Key {
			key, err := CreateEd25519Key()
			if err != nil {
				t.Fatalf("CreateEd25519Key() failed: %v", err)
			}
			return key
		}(),
	}}
	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			// Use the SKID to be sure that the key is the same post-import.
			before, err := GenerateSubjectKeyID(tc.key.Public)
			if err != nil {
				t.Fatalf("GenerateSubjectKeyID failed: %v", err)
			}
			pem, err := tc.key.ExportPrivate()
			if err != nil {
				t.Fatalf("ExportPrivate failed: %v", err)
			}
			key, err := NewKeyFromPrivateKeyPEM(pem)
			if err != nil {
				t.Fatalf("NewKeyFromPrivateKeyPEM failed: %v", err)
			}
			after, err := GenerateSubjectKeyID(key.Public)
			if err != nil {
				t.Fatalf("GenerateSubjectKeyID failed: %v", err)
			}
			if !bytes.Equal(before, after) {
				t.Fatalf("SKID before export (%s) does not match SKID after export/import (%s)", hex.EncodeToString(before), hex.EncodeToString(after))
			}
		})
	}
}

func TestEncryptedECCImportExport(t *testing.T) {
	tests := []struct {
		name         string
		pem          string
		encryptedPEM string
	}{{
		name:         "ECDSA P256",
		pem:          p256PrivKeyPEM,
		encryptedPEM: p256EncryptedPrivKeyPEM,
	}, {
		name:         "Ed25519",
		pem:          ed25519PrivKeyPEM,
		encryptedPEM: ed25519EncryptedPrivKeyPEM,
	}}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// 1. Decrypt the openssl-encrypted PKCS8.
			priv, err := NewKeyFromEncryptedPrivateKeyPEM([]byte(tc.encryptedPEM), []byte(password))
			if err != nil {
				t.Fatalf("NewKeyFromEncryptedPrivateKeyPEM failed: %v", err)
			}
			// 2. Export the decrypted PEM to compare with the expected PEM.
			pem, err := priv.ExportPrivate()
			if err != nil {
				t.Fatalf("ExportPrivate failed: %v", err)
			}
			if tc.pem != string(pem) {
				t.Fatalf("Want pem:\n%sgot:\n%s", tc.pem, pem)
			}
			// 3. Ensure that Decrypt(Encrypt(pem)) == pem.
			encryptedPEM, err := priv.ExportEncryptedPrivate([]byte(password))
			if err != nil {
				t.Fatalf("ExportEncryptedPrivate failed: %v", err)
			}
			priv, err = NewKeyFromEncryptedPrivateKeyPEM([]byte(encryptedPEM), []byte(password))
			if err != nil {
				t.Fatalf("NewKeyFromEncryptedPrivateKeyPEM failed: %v", err)
			}
			decryptedPEM, err := priv.ExportPrivate()
			if err != nil {
				t.Fatalf("ExportPrivate failed: %v", err)
			}
			if !bytes.Equal(pem, decryptedPEM) {
				t.Fatalf("Want pem:\n%sgot:\n%s", pem, decryptedPEM)
			}
			// 4. Sanity check to ensure that the wrong password fails to decrypt...
			if _, err := NewKeyFromEncryptedPrivateKeyPEM([]byte(encryptedPEM), []byte(wrongPassword)); err == nil {
				t.Fatalf("NewKeyFromEncryptedPrivateKeyPEM(wrongPassword) succeeeded, expected failure")
			}
		})
	}
}
