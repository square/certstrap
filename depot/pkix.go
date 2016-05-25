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

package depot

import (
	"strings"

	"github.com/square/certstrap/pkix"
)

const (
	crtSuffix     = ".crt"
	csrSuffix     = ".csr"
	privKeySuffix = ".key"
	crlSuffix     = ".crl"
)

const (
	branchPerm = 0440
	leafPerm   = 0444
)

// CrtTag returns a tag corresponding to a certificate
func CrtTag(prefix string) *Tag {
	return &Tag{prefix + crtSuffix, leafPerm}
}

// PrivKeyTag returns a tag corresponding to a private key
func PrivKeyTag(prefix string) *Tag {
	return &Tag{prefix + privKeySuffix, branchPerm}
}

// CsrTag returns a tag corresponding to a certificate signature request file
func CsrTag(prefix string) *Tag {
	return &Tag{prefix + csrSuffix, leafPerm}
}

// CrlTag returns a tag corresponding to a certificate revocation list
func CrlTag(prefix string) *Tag {
	return &Tag{prefix + crlSuffix, leafPerm}
}

// GetNameFromCrtTag returns the host name from a certificate file tag
func GetNameFromCrtTag(tag *Tag) string {
	name := strings.TrimSuffix(tag.name, crtSuffix)
	if name == tag.name {
		return ""
	}
	return name
}

// PutCertificate creates a certificate file for a given CA name in the depot
func PutCertificate(d Depot, name string, crt *pkix.Certificate) error {
	b, err := crt.Export()
	if err != nil {
		return err
	}
	return d.Put(CrtTag(name), b)
}

// CheckCertificate checks the depot for existence of a certificate file for a given CA name
func CheckCertificate(d Depot, name string) bool {
	return d.Check(CrtTag(name))
}

// GetCertificate retrieves a certificate file for a given name from the depot
func GetCertificate(d Depot, name string) (crt *pkix.Certificate, err error) {
	b, err := d.Get(CrtTag(name))
	if err != nil {
		return nil, err
	}
	return pkix.NewCertificateFromPEM(b)
}

// DeleteCertificate removes a certificate file for a given name from the depot
func DeleteCertificate(d Depot, name string) error {
	return d.Delete(CrtTag(name))
}

// PutCertificateSigningRequest creates a certificate signing request file for a given name and csr in the depot
func PutCertificateSigningRequest(d Depot, name string, csr *pkix.CertificateSigningRequest) error {
	b, err := csr.Export()
	if err != nil {
		return err
	}
	return d.Put(CsrTag(name), b)
}

// CheckCertificateSigningRequest checks the depot for existence of a certificate signing request file for a given host name
func CheckCertificateSigningRequest(d Depot, name string) bool {
	return d.Check(CsrTag(name))
}

// GetCertificateSigningRequest retrieves a certificate signing request file for a given host name from the depot
func GetCertificateSigningRequest(d Depot, name string) (crt *pkix.CertificateSigningRequest, err error) {
	b, err := d.Get(CsrTag(name))
	if err != nil {
		return nil, err
	}
	return pkix.NewCertificateSigningRequestFromPEM(b)
}

// DeleteCertificateSigningRequest removes a certificate signing request file for a given host name from the depot
func DeleteCertificateSigningRequest(d Depot, name string) error {
	return d.Delete(CsrTag(name))
}

// PutPrivateKey creates a private key file for a given name in the depot
func PutPrivateKey(d Depot, name string, key *pkix.Key) error {
	b, err := key.ExportPrivate()
	if err != nil {
		return err
	}
	return d.Put(PrivKeyTag(name), b)
}

// CheckPrivateKey checks the depot for existence of a private key file for a given name
func CheckPrivateKey(d Depot, name string) bool {
	return d.Check(PrivKeyTag(name))
}

// GetPrivateKey retrieves a private key file for a given name from the depot
func GetPrivateKey(d Depot, name string) (key *pkix.Key, err error) {
	b, err := d.Get(PrivKeyTag(name))
	if err != nil {
		return nil, err
	}
	return pkix.NewKeyFromPrivateKeyPEM(b)
}

// PutEncryptedPrivateKey creates an encrypted private key file for a given name in the depot
func PutEncryptedPrivateKey(d Depot, name string, key *pkix.Key, passphrase []byte) error {
	b, err := key.ExportEncryptedPrivate(passphrase)
	if err != nil {
		return err
	}
	return d.Put(PrivKeyTag(name), b)
}

// GetEncryptedPrivateKey retrieves an encrypted private key file for a given name from the depot
func GetEncryptedPrivateKey(d Depot, name string, passphrase []byte) (key *pkix.Key, err error) {
	b, err := d.Get(PrivKeyTag(name))
	if err != nil {
		return nil, err
	}
	return pkix.NewKeyFromEncryptedPrivateKeyPEM(b, passphrase)
}

// PutCertificateRevocationList creates a CRL file for a given name and ca in the depot
func PutCertificateRevocationList(d Depot, name string, crl *pkix.CertificateRevocationList) error {
	b, err := crl.Export()
	if err != nil {
		return err
	}
	return d.Put(CrlTag(name), b)
}
