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
	"crypto/rand"
	"crypto/x509"
	"strings"

	"github.com/square/certstrap/pkix"
	"software.sslmate.com/src/go-pkcs12"
)

const (
	crtSuffix     = ".crt"
	csrSuffix     = ".csr"
	privKeySuffix = ".key"
	crlSuffix     = ".crl"
	pfxSuffix     = ".pfx"
)

// CrtTag returns a tag corresponding to a certificate
func CrtTag(prefix string) *Tag {
	return &Tag{prefix + crtSuffix, LeafPerm}
}

// PrivKeyTag returns a tag corresponding to a private key
func PrivKeyTag(prefix string) *Tag {
	return &Tag{prefix + privKeySuffix, BranchPerm}
}

// CsrTag returns a tag corresponding to a certificate signature request file
func CsrTag(prefix string) *Tag {
	return &Tag{prefix + csrSuffix, LeafPerm}
}

// CrlTag returns a tag corresponding to a certificate revocation list
func CrlTag(prefix string) *Tag {
	return &Tag{prefix + crlSuffix, LeafPerm}
}

// PfxTag returns a tag corresponding to a personal information exchange
func PfxTag(prefix string) *Tag {
	return &Tag{prefix + pfxSuffix, LeafPerm}
}

// GetNameFromCrtTag returns the host name from a certificate file tag
func GetNameFromCrtTag(tag *Tag) string {
	return getName(tag, crtSuffix)
}

// GetNameFromPrivKeyTag returns the host name from a private key file tag
func GetNameFromPrivKeyTag(tag *Tag) string {
	return getName(tag, privKeySuffix)
}

// GetNameFromCsrTag returns the host name from a certificate request file tag
func GetNameFromCsrTag(tag *Tag) string {
	return getName(tag, csrSuffix)
}

// GetNameFromCrlTag returns the host name from a certificate revocation list file tag
func GetNameFromCrlTag(tag *Tag) string {
	return getName(tag, crlSuffix)
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

// CheckPersonalInformationExchange checks the depot for existence of a pfx file for a given name
func CheckPersonalInformationExchange(d Depot, name string) bool {
	return d.Check(PfxTag(name))
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

// PutPersonalInformationExchange creates a Personal Information Exchange certificate file for a given name in the depot
func PutPersonalInformationExchange(d Depot, name string, crt *pkix.Certificate, key *pkix.Key, caCrts []*pkix.Certificate, passphrase []byte) ([]byte, error) {
	c, err := crt.GetRawCertificate()
	if err != nil {
		return nil, err
	}
	chain := []*x509.Certificate{}
	for i := range caCrts {
		cc, err := caCrts[i].GetRawCertificate()
		if err != nil {
			return nil, err
		}
		chain = append(chain, cc)
	}
	b, err := pkcs12.Encode(rand.Reader, key.Private, c, chain, string(passphrase))
	if err != nil {
		return nil, err
	}
	return b, d.Put(PfxTag(name), b)
}

// GetCertificateRevocationList gets a CRL file for a given name and ca in the depot.
func GetCertificateRevocationList(d Depot, name string) (*pkix.CertificateRevocationList, error) {
	b, err := d.Get(CrlTag(name))
	if err != nil {
		return nil, err
	}
	return pkix.NewCertificateRevocationListFromPEM(b)
}

func getName(tag *Tag, suffix string) string {
	name := strings.TrimSuffix(tag.name, suffix)
	if name == tag.name {
		return ""
	}
	return name
}
