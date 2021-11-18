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
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"

	"go.step.sm/crypto/pemutil"
)

const (
	rsaPrivateKeyPEMBlockType            = "RSA PRIVATE KEY"
	pkcs8PrivateKeyPEMBlockType          = "PRIVATE KEY"
	encryptedPKCS8PrivateKeyPEMBLockType = "ENCRYPTED PRIVATE KEY"
)

// CreateRSAKey creates a new Key using RSA algorithm
func CreateRSAKey(rsaBits int) (*Key, error) {
	priv, err := rsa.GenerateKey(rand.Reader, rsaBits)
	if err != nil {
		return nil, err
	}

	return NewKey(&priv.PublicKey, priv), nil
}

// CreateECDSAKey creates a new ECDSA key on the given curve
func CreateECDSAKey(c elliptic.Curve) (*Key, error) {
	priv, err := ecdsa.GenerateKey(c, rand.Reader)
	if err != nil {
		return nil, err
	}

	return NewKey(&priv.PublicKey, priv), nil
}

// CreateEd25519Key creates a new Ed25519 key
func CreateEd25519Key() (*Key, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	return NewKey(priv.Public(), priv), nil
}

// Key contains a public-private keypair
type Key struct {
	Public  crypto.PublicKey
	Private crypto.PrivateKey
}

func NewKeyFromSigner(signer crypto.Signer) *Key {
	return &Key{Public: signer.Public(), Private: signer}
}

// NewKey returns a new public-private keypair Key type
func NewKey(pub crypto.PublicKey, priv crypto.PrivateKey) *Key {
	return &Key{Public: pub, Private: priv}
}

// NewKeyFromPrivateKeyPEM inits Key from PEM-format rsa private key bytes
func NewKeyFromPrivateKeyPEM(data []byte) (*Key, error) {
	pemBlock, _ := pem.Decode(data)
	if pemBlock == nil {
		return nil, errors.New("cannot find the next PEM formatted block")
	}
	var signer crypto.Signer
	switch pemBlock.Type {
	case rsaPrivateKeyPEMBlockType:
		priv, err := x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
		if err != nil {
			return nil, err
		}
		signer = priv
	case pkcs8PrivateKeyPEMBlockType:
		priv, err := x509.ParsePKCS8PrivateKey(pemBlock.Bytes)
		if err != nil {
			return nil, err
		}
		signer = priv.(crypto.Signer)
	default:
		return nil, fmt.Errorf("unknown PEM block type %q", pemBlock.Type)
	}
	return NewKeyFromSigner(signer), nil
}

// NewKeyFromEncryptedPrivateKeyPEM inits Key from encrypted PEM-format private key bytes
func NewKeyFromEncryptedPrivateKeyPEM(data []byte, password []byte) (*Key, error) {
	pemBlock, _ := pem.Decode(data)
	if pemBlock == nil {
		return nil, errors.New("cannot find the next PEM formatted block")
	}
	var signer crypto.Signer
	switch pemBlock.Type {
	case rsaPrivateKeyPEMBlockType:
		b, err := x509.DecryptPEMBlock(pemBlock, password)
		if err != nil {
			return nil, err
		}
		priv, err := x509.ParsePKCS1PrivateKey(b)
		if err != nil {
			return nil, err
		}
		signer = priv
	case encryptedPKCS8PrivateKeyPEMBLockType:
		b, err := pemutil.DecryptPKCS8PrivateKey(pemBlock.Bytes, password)
		if err != nil {
			return nil, err
		}
		priv, err := x509.ParsePKCS8PrivateKey(b)
		if err != nil {
			return nil, err
		}
		signer = priv.(crypto.Signer)
	default:
		return nil, fmt.Errorf("unsupported PEM block type %q", pemBlock.Type)
	}

	return NewKeyFromSigner(signer), nil
}

// ExportPrivate exports PEM-format private key. RSA keys are exported
// as PKCS#1, ECDSA and Ed25519 keys are exported as PKCS#8.
func (k *Key) ExportPrivate() ([]byte, error) {
	var privPEMBlock *pem.Block
	switch priv := k.Private.(type) {
	case *rsa.PrivateKey:
		privBytes := x509.MarshalPKCS1PrivateKey(priv)
		privPEMBlock = &pem.Block{
			Type:  rsaPrivateKeyPEMBlockType,
			Bytes: privBytes,
		}
	case *ecdsa.PrivateKey, ed25519.PrivateKey:
		privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			return nil, err
		}
		privPEMBlock = &pem.Block{
			Type:  pkcs8PrivateKeyPEMBlockType,
			Bytes: privBytes,
		}
	default:
		return nil, fmt.Errorf("unsupported key type %T", k.Private)
	}

	return pem.EncodeToMemory(privPEMBlock), nil
}

// ExportEncryptedPrivate exports encrypted PEM-format private key
func (k *Key) ExportEncryptedPrivate(password []byte) ([]byte, error) {
	var privPEMBlock *pem.Block
	switch priv := k.Private.(type) {
	case *rsa.PrivateKey:
		privBytes := x509.MarshalPKCS1PrivateKey(priv)
		block, err := x509.EncryptPEMBlock(rand.Reader, rsaPrivateKeyPEMBlockType, privBytes, password, x509.PEMCipher3DES)
		if err != nil {
			return nil, err
		}
		privPEMBlock = block
	case *ecdsa.PrivateKey, ed25519.PrivateKey:
		privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			return nil, err
		}
		block, err := pemutil.EncryptPKCS8PrivateKey(rand.Reader, privBytes, password, x509.PEMCipherAES256)
		if err != nil {
			return nil, err
		}
		privPEMBlock = block
	default:
		return nil, fmt.Errorf("unsupported key type %T", k.Private)
	}

	return pem.EncodeToMemory(privPEMBlock), nil
}

// rsaPublicKey reflects the ASN.1 structure of a PKCS#1 public key.
type rsaPublicKey struct {
	N *big.Int
	E int
}

// GenerateSubjectKeyID generates SubjectKeyId used in Certificate
// Id is 160-bit SHA-1 hash of the value of the BIT STRING subjectPublicKey
func GenerateSubjectKeyID(pub crypto.PublicKey) ([]byte, error) {
	var pubBytes []byte
	var err error
	switch pub := pub.(type) {
	case *rsa.PublicKey:
		pubBytes, err = asn1.Marshal(rsaPublicKey{
			N: pub.N,
			E: pub.E,
		})
		if err != nil {
			return nil, err
		}
	case *ecdsa.PublicKey:
		pubBytes = elliptic.Marshal(pub.Curve, pub.X, pub.Y)
	case ed25519.PublicKey:
		pubBytes = pub
	default:
		return nil, fmt.Errorf("unsupported key type %T", pub)
	}

	hash := sha1.Sum(pubBytes)

	return hash[:], nil
}
