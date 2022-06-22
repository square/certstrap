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
	"crypto/rand"
	"crypto/x509"
	"math/big"
	"time"
)

type Option func(*x509.Certificate)

// CreateCertificateAuthority creates Certificate Authority using existing key.
// CertificateAuthorityInfo returned is the extra infomation required by Certificate Authority.
func CreateCertificateAuthority(key *Key, organizationalUnit string, expiry time.Time, organization string, country string, province string, locality string, commonName string, permitDomains []string) (*Certificate, error) {
	// Passing all arguments to CreateCertificateAuthorityWithOptions
	return CreateCertificateAuthorityWithOptions(key, organizationalUnit, expiry, organization, country, province, locality, commonName, permitDomains)
}

// CreateCertificateAuthorityWithOptions creates Certificate Authority using existing key with options.
// CertificateAuthorityInfo returned is the extra infomation required by Certificate Authority.
func CreateCertificateAuthorityWithOptions(key *Key, organizationalUnit string, expiry time.Time, organization string, country string, province string, locality string, commonName string, permitDomains []string, opts ...Option) (*Certificate, error) {
	authTemplate := newAuthTemplate()

	subjectKeyID, err := GenerateSubjectKeyID(key.Public)
	if err != nil {
		return nil, err
	}
	authTemplate.SubjectKeyId = subjectKeyID
	authTemplate.NotAfter = expiry
	if len(country) > 0 {
		authTemplate.Subject.Country = []string{country}
	}
	if len(province) > 0 {
		authTemplate.Subject.Province = []string{province}
	}
	if len(locality) > 0 {
		authTemplate.Subject.Locality = []string{locality}
	}
	if len(organization) > 0 {
		authTemplate.Subject.Organization = []string{organization}
	}
	if len(organizationalUnit) > 0 {
		authTemplate.Subject.OrganizationalUnit = []string{organizationalUnit}
	}
	if len(commonName) > 0 {
		authTemplate.Subject.CommonName = commonName
	}

	if len(permitDomains) > 0 {
		authTemplate.PermittedDNSDomainsCritical = true
		authTemplate.PermittedDNSDomains = permitDomains
	}

	applyOptions(&authTemplate, opts)

	crtBytes, err := x509.CreateCertificate(rand.Reader, &authTemplate, &authTemplate, key.Public, key.Private)
	if err != nil {
		return nil, err
	}

	return NewCertificateFromDER(crtBytes), nil
}

// CreateIntermediateCertificateAuthority creates an intermediate
// CA certificate signed by the given authority.
func CreateIntermediateCertificateAuthority(crtAuth *Certificate, keyAuth *Key, csr *CertificateSigningRequest, proposedExpiry time.Time) (*Certificate, error) {
	// Passing all arguments to CreateIntermediateCertificateAuthorityWithOptions
	return CreateIntermediateCertificateAuthorityWithOptions(crtAuth, keyAuth, csr, proposedExpiry)
}

// CreateIntermediateCertificateAuthorityWithOptions creates an intermediate with options.
// CA certificate signed by the given authority.
func CreateIntermediateCertificateAuthorityWithOptions(crtAuth *Certificate, keyAuth *Key, csr *CertificateSigningRequest, proposedExpiry time.Time, opts ...Option) (*Certificate, error) {
	authTemplate := newAuthTemplate()

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}
	authTemplate.SerialNumber.Set(serialNumber)

	rawCsr, err := csr.GetRawCertificateSigningRequest()
	if err != nil {
		return nil, err
	}

	authTemplate.RawSubject = rawCsr.RawSubject

	caExpiry := time.Now().Add(crtAuth.GetExpirationDuration())
	// ensure cert doesn't expire after issuer
	if caExpiry.Before(proposedExpiry) {
		authTemplate.NotAfter = caExpiry
	} else {
		authTemplate.NotAfter = proposedExpiry
	}

	authTemplate.SubjectKeyId, err = GenerateSubjectKeyID(rawCsr.PublicKey)
	if err != nil {
		return nil, err
	}

	authTemplate.IPAddresses = rawCsr.IPAddresses
	authTemplate.DNSNames = rawCsr.DNSNames
	authTemplate.URIs = rawCsr.URIs

	rawCrtAuth, err := crtAuth.GetRawCertificate()
	if err != nil {
		return nil, err
	}

	applyOptions(&authTemplate, opts)

	crtOutBytes, err := x509.CreateCertificate(rand.Reader, &authTemplate, rawCrtAuth, rawCsr.PublicKey, keyAuth.Private)
	if err != nil {
		return nil, err
	}

	return NewCertificateFromDER(crtOutBytes), nil
}

// WithPathlenOption will check if the certificate should have `pathlen` or not.
func WithPathlenOption(pathlen int, excludePathlen bool) func(template *x509.Certificate) {
	return func(template *x509.Certificate) {
		template.MaxPathLen = pathlen

		if excludePathlen {
			template.MaxPathLen = -1
		}
	}
}

func applyOptions(template *x509.Certificate, opts []Option) {
	for _, opt := range opts {
		opt(template)
	}
}

func newAuthTemplate() x509.Certificate {
	// Build CA based on RFC5280
	return x509.Certificate{
		SerialNumber: big.NewInt(1),
		// NotBefore is set to be 10min earlier to fix gap on time difference in cluster
		NotBefore: time.Now().Add(-10 * time.Minute).UTC(),
		NotAfter:  time.Time{},
		// Used for certificate signing only
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,

		ExtKeyUsage:        nil,
		UnknownExtKeyUsage: nil,

		// activate CA
		BasicConstraintsValid: true,
		IsCA:                  true,
		// Not allow any non-self-issued intermediate CA, sets MaxPathLen=0
		MaxPathLenZero: true,

		// 160-bit SHA-1 hash of the value of the BIT STRING subjectPublicKey
		// (excluding the tag, length, and number of unused bits)
		// **SHOULD** be filled in later
		SubjectKeyId: nil,

		// Subject Alternative Name
		DNSNames: nil,

		PermittedDNSDomainsCritical: false,
		PermittedDNSDomains:         nil,
	}
}
