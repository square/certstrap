package cmd

import (
	"crypto/x509"
	x509pkix "crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// crlValidity is how long a CRL written by revoke is valid for.
const crlValidity = 2 * 8760 * time.Hour

var (
	oidExtensionCRLNumber  = asn1.ObjectIdentifier{2, 5, 29, 20}
	oidExtensionReasonCode = asn1.ObjectIdentifier{2, 5, 29, 21}
)

// v1CertificateList mirrors the CertificateList structure that the deprecated
// x509.ParseDERCRL decoded. Unlike x509.ParseRevocationList, it accepts CRLs
// without a version field, which certstrap releases built with old Go versions
// wrote.
type v1CertificateList struct {
	TBSCertList struct {
		Version             int `asn1:"optional,default:0"`
		Signature           x509pkix.AlgorithmIdentifier
		Issuer              x509pkix.RDNSequence
		ThisUpdate          time.Time
		NextUpdate          time.Time                     `asn1:"optional"`
		RevokedCertificates []x509pkix.RevokedCertificate `asn1:"optional"`
		Extensions          []x509pkix.Extension          `asn1:"tag:0,optional,explicit"`
	}
	SignatureAlgorithm x509pkix.AlgorithmIdentifier
	SignatureValue     asn1.BitString
}

// parseRevocationList parses a DER-encoded CRL. v1 CRLs written by old
// certstrap releases are also accepted, so that revoke keeps working with
// existing depots; any other CRL that x509.ParseRevocationList rejects is
// reported with its error.
func parseRevocationList(der []byte) (*x509.RevocationList, error) {
	list, err := x509.ParseRevocationList(der)
	if err == nil {
		return list, nil
	}

	var v1 v1CertificateList
	if rest, v1Err := asn1.Unmarshal(der, &v1); v1Err != nil || len(rest) != 0 || v1.TBSCertList.Version != 0 {
		return nil, err
	}
	return v1.toRevocationList()
}

// toRevocationList returns the parts of l that revoke carries over, in the
// form x509.ParseRevocationList returns them.
func (l *v1CertificateList) toRevocationList() (*x509.RevocationList, error) {
	list := &x509.RevocationList{}
	for _, ext := range l.TBSCertList.Extensions {
		if ext.Id.Equal(oidExtensionCRLNumber) {
			if err := unmarshalExtension(ext, &list.Number); err != nil {
				return nil, fmt.Errorf("malformed CRL number in v1 CRL: %v", err)
			}
		}
	}

	for _, revoked := range l.TBSCertList.RevokedCertificates {
		entry := x509.RevocationListEntry{
			SerialNumber:   revoked.SerialNumber,
			RevocationTime: revoked.RevocationTime,
			Extensions:     revoked.Extensions,
		}
		for _, ext := range revoked.Extensions {
			if ext.Id.Equal(oidExtensionReasonCode) {
				var reason asn1.Enumerated
				if err := unmarshalExtension(ext, &reason); err != nil {
					return nil, fmt.Errorf("malformed reason code in v1 CRL: %v", err)
				}
				entry.ReasonCode = int(reason)
			}
		}
		list.RevokedCertificateEntries = append(list.RevokedCertificateEntries, entry)
	}
	return list, nil
}

func unmarshalExtension(ext x509pkix.Extension, value any) error {
	rest, err := asn1.Unmarshal(ext.Value, value)
	if err != nil {
		return err
	}
	if len(rest) != 0 {
		return errors.New("trailing data")
	}
	return nil
}

// nextRevocationList returns the template for the CRL that replaces current
// once serial is revoked at now. The existing entries are kept in order, with
// their revocation times, reason codes and other extensions, and the new entry
// is appended. The CRL number is one more than current's, or 1 if current has
// none (as with CRLs written before certstrap numbered them) or a negative one.
func nextRevocationList(current *x509.RevocationList, serial *big.Int, now time.Time) *x509.RevocationList {
	entries := make([]x509.RevocationListEntry, 0, len(current.RevokedCertificateEntries)+1)
	for _, entry := range current.RevokedCertificateEntries {
		entries = append(entries, x509.RevocationListEntry{
			SerialNumber:   entry.SerialNumber,
			RevocationTime: entry.RevocationTime,
			// x509.CreateRevocationList encodes the reason code extension
			// itself, and rejects it in ExtraExtensions.
			ReasonCode:      entry.ReasonCode,
			ExtraExtensions: withoutExtension(entry.Extensions, oidExtensionReasonCode),
		})
	}
	entries = append(entries, x509.RevocationListEntry{
		SerialNumber:   serial,
		RevocationTime: now,
	})

	number := big.NewInt(1)
	if current.Number != nil && current.Number.Sign() > 0 {
		number.Add(current.Number, number)
	}

	return &x509.RevocationList{
		RevokedCertificateEntries: entries,
		Number:                    number,
		ThisUpdate:                now,
		NextUpdate:                now.Add(crlValidity),
	}
}

func withoutExtension(extensions []x509pkix.Extension, id asn1.ObjectIdentifier) []x509pkix.Extension {
	var kept []x509pkix.Extension
	for _, ext := range extensions {
		if !ext.Id.Equal(id) {
			kept = append(kept, ext)
		}
	}
	return kept
}
