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
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"
	"time"
)

const (
	crlPEMBlockType = "X509 CRL"
)

// CreateCertificateRevocationList creates an empty CRL for ca, signed by its
// key and valid until expiry. It is the CA's first CRL, so its CRL number is 1.
// The CA certificate must have a subject key ID and the CRL signing key usage.
func CreateCertificateRevocationList(key *Key, ca *Certificate, expiry time.Time) (*CertificateRevocationList, error) {
	rawCrt, err := ca.GetRawCertificate()
	if err != nil {
		return nil, err
	}

	signer, ok := key.Private.(crypto.Signer)
	if !ok {
		return nil, errors.New("CA private key does not implement crypto.Signer")
	}

	// init computes expiry before generating the key, which can outlast a
	// short --expires. x509.CreateRevocationList rejects a NextUpdate before
	// ThisUpdate, so keep the requested expiry and move ThisUpdate back to it.
	thisUpdate := time.Now()
	if expiry.Before(thisUpdate) {
		thisUpdate = expiry
	}

	crlBytes, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: thisUpdate,
		NextUpdate: expiry,
	}, rawCrt, signer)
	if err != nil {
		return nil, err
	}
	return NewCertificateRevocationListFromDER(crlBytes), nil
}

// CertificateSigningRequest is a wrapper around a x509 CertificateRequest and its DER-formatted bytes
type CertificateRevocationList struct {
	derBytes []byte
}

// DERBytes returns DER-formatted bytes of the CRL.
func (c *CertificateRevocationList) DERBytes() []byte {
	return c.derBytes
}

// NewCertificateRevocationListFromDER inits CertificateRevocationList from DER-format bytes
func NewCertificateRevocationListFromDER(derBytes []byte) *CertificateRevocationList {
	return &CertificateRevocationList{derBytes: derBytes}
}

// NewCertificateRevocationListFromPEM inits CertificateRevocationList from PEM-format bytes
func NewCertificateRevocationListFromPEM(data []byte) (*CertificateRevocationList, error) {
	pemBlock, _ := pem.Decode(data)
	if pemBlock == nil {
		return nil, errors.New("cannot find the next PEM formatted block")
	}
	if pemBlock.Type != crlPEMBlockType || len(pemBlock.Headers) != 0 {
		return nil, errors.New("unmatched type or headers")
	}
	return &CertificateRevocationList{derBytes: pemBlock.Bytes}, nil
}

// Export returns PEM-format bytes
func (c *CertificateRevocationList) Export() ([]byte, error) {
	pemBlock := &pem.Block{
		Type:    crlPEMBlockType,
		Headers: nil,
		Bytes:   c.derBytes,
	}

	buf := new(bytes.Buffer)
	if err := pem.Encode(buf, pemBlock); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
