/*-
 * Copyright (c) 2018 Marco Stolze (alias mcpride)
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
	"crypto/rsa"
	"encoding/base64"
	"testing"
)

const (
	rsaPrivKeyAuthPEM = `-----BEGIN RSA PRIVATE KEY-----
MIICWwIBAAKBgQCfiIsDUQlPJ6WCdjlASN2C6SNnhZDrdq2LnoT9IAwUYwN9dISO
jSgyGeoZTPVrl6qQN48kp+xb0zgkrW6BX+BiU2/VJUf97aERKEInpQ8OfKajOh3p
8M/qwZtzrNKTFlfdRITQYGiL0JTfQoDQ10Yu3JusJwt5sUrz6ovFwBH3rwIDAQAB
AoGARTkFQNIn3O3SFlLgMrGrVEN/Nksxf8pGMX/+Kqt+MlZoTEaDwisj1uGBv6qy
DxaHTv6coQYwPAPhp6CNg5uri69Rab+B5evU6RdKrrhsTFWu1eQ34/ApTydiyM16
vwSzLk//nv3GtfXUrFXkrlCi8t20rKn2UnqaCMtyL6BldRkCQQDJ/wDAbRh1JpN7
6oclNap46m1ur/sYYizoEQS7yBFdB7c0xAckZPTnj8SSNv5en8M1+nt6gEVg1jpG
uMUs69LLAkEAyi9PVwDtbl7PMlzGtFd9JjsOokgYPN/vA65sT30jZKczi6KVUHO5
p4pD/s6Ic3iqf9xSwpvRmFpoXxB82Np+LQJAfRyEyqrHy0fpcYcBzfo/bEVHIpe9
XozwY4ym8egpWQW+Y+BGzDP7vLE/f5CwXMt3jadnc6ifUCtgTQ2Ekx49oQJAQdmw
zJR3wEfO0gdXjGsmTqpTdNVoV4NT1G4dxrHqMiEm76avXPmkEQY+aSIZXQqC9Yvr
xIh9dlKTxcqX7wUSrQJAXXpygOzREafol7PuVve1YxteDjFo7xUpd2wf3Ce17+x6
GAfucNv1WCPaGCmHd3PlxSI6KDToOCcu36Uc9/VOhg==
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

	rsaEncryptedPrivKeyAuthPEM = `-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-EDE3-CBC,83426dfe1b543fad

rK3T3b13v0jh1hu/t8z6/ySQtDC7cr+gO3GpbudfgIONJMoocDI5dGACgMvIPTog
xEVnq1/XdPqCSxfS728LkPBkZ5B4g9aFixRTfyDdYp25lHyCTCTpM5PGOzQCcg2E
SD0LZFSqw/gy29IQTK6HwRLFHa0ZlncIUj6RnSxgTYiuSzYtFAXsVjLdrwW8MOIh
cKZlQc5rAKnFMgYSK356Yj2HEtcaisNL5hp/AjPRlW1HMrCDNx7m0x3qNIdaQEHz
Hckw+hLLmPbM1F5d0heUITOh3GCTNBj2R4ukJ+rqv4gCp9/afkFgMdwglL1bRyUn
711tqiFKENDzDetgfb/OXdn7qLjbdP2uIj9HZXsXoXptD1hc1RRssP5cZ/VzxpOQ
KaAwJp8pcUpmJIP5rMu+x+VYggBUaKTs9TqgYfvH2P0ElcW2VlQy/3ayXfpMrCI5
+3uTYdE2KLp++2w2Gr3utwWekfAhI1oh8MOkZIFNbQu+ECZ2ZLRxC+4x/suthxzT
BMQPl/7m5Q+L0GqcqEOZVJ9ekLvdd4dH/UXz2di8YA6C6+DCLYtod+jacCOnLWCQ
720coUEkdeivWpePWCGhJr07Yw54I/NC+91xkSSBQLNPOR3CO+0BRZ96Gc0B6KU8
VtqebOpqR2DBWyIv2JRuUk1ABjN4H2ByHOPKs8jiraCAKvWK7S+7OX7gDypwkCI9
wipI15zxSvuOidoO1DptZEj/RXYU45exY1LM2hXqQ2+AQ6MB+EvEMDk/qmmEeICS
chlXS8rRhHtP+dYo4waeWbUCthn0NcB5pyI8Nkv4WFI=
-----END RSA PRIVATE KEY-----
`
	password      = "123456"
	wrongPassword = "654321"
	rsaBits       = 1024

	subjectKeyIDOfRSAPubKeyAuthBASE64 = "5rIQuZ160Ytafg5T7bWow6E0FGA="
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
	if bytes.Compare(pemBytes, []byte(rsaPrivKeyAuthPEM)) != 0 {
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
	if bytes.Compare(pemBytes, []byte(rsaPrivKeyAuthPEM)) != 0 {
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
	if bytes.Compare(id, correctID) != 0 {
		t.Fatal("Failed generating correct SubjectKeyId")
	}
}
