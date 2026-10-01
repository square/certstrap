package cmd

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	x509pkix "crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

// legacyCRLPEM is a CRL written by certstrap init in 2016, also used as crlPEM
// in pkix/crl_test.go. It has no version field, an AuthorityKeyId extension
// and an empty revokedCertificates sequence.
const legacyCRLPEM = `-----BEGIN X509 CRL-----
MIICfzBpMA0GCSqGSIb3DQEBCwUAMBMxETAPBgNVBAMTCENlcnRBdXRoFw0xNjAy
MDQyMjAwMTdaFw0yNjAyMDQyMjAwMTdaMACgIzAhMB8GA1UdIwQYMBaAFIM33UgM
CnTVX7cuOFiPIdvMsrzmMA0GCSqGSIb3DQEBCwUAA4ICAQBcrKZml+1XEb7iXiRX
3zkSlXqYmhW3WK5N2uF8+xpJWukkJNmQyM6FzeMWs0hZWTuN84lOBU4CmDjCglrt
Bn6VtmdAQHf42ZTAMUkFDI8+DsfXHxEYrDp1//1Ljz7ybNhuanmXkVcsyNVN6Rn3
LRV2g4tHSAtxMJBHg/CAQWI7vOzD6fDX+1JPMcmrAufglxPEc6r/I0N/CduIJMzO
Ivb6A6Nx/fZmYJEMuvb9Mt9uwnPhC7iiktq0QiAixOG3yPBduQNl73vsuRoROGDn
AYg+cIQ16jIqpaXYXj//QyfWWqqRl29TmXY1kRFZuH+hyAay30lcU+uUrAYqhG+N
ZbrwE1vLtaUGTko36ZY6omqz/Do2dU5bxDbKWskkSLqFleLXtoJqZsKfE1ZdFW0+
iAPDJcl3jCKrs2lN3RinJj76LtLxmIiaK2AsDg/iLaplaqbjtx4xWDzvfiNAeo8k
zEST4Zo0VXTJ/cxzx7Roe0kPFlCt/YNsOKLTOCfvjyFjMRcbcBlut7Fk7/VGWxsj
XkF1bcyI7WPSM8Taq6lWhjHtRUDT3q1gPpUY1CBWJKQrKUwjBzVk81wCS6LJfdTG
/5z7+UfcUAHh7Afm90hyk3nh+fPgSCQrRx9OC5kAJSLMKMvV9ikDZvr9rSkacowD
lrpOuuKFsK22BhjvCNY2fLWn0A==
-----END X509 CRL-----
`

var (
	oidSHA256WithRSA           = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidExtensionInvalidityDate = asn1.ObjectIdentifier{2, 5, 29, 24}
	testRevocationTime         = time.Date(2020, time.January, 2, 3, 4, 5, 0, time.UTC)
	secondTestRevocationTime   = time.Date(2021, time.February, 3, 4, 5, 6, 0, time.UTC)
)

// testTBSCertList is the RFC 5280 TBSCertList, used to build CRLs that
// x509.CreateRevocationList does not write: v1, unnumbered or malformed ones.
type testTBSCertList struct {
	Version             int `asn1:"optional,default:0"`
	Signature           x509pkix.AlgorithmIdentifier
	Issuer              asn1.RawValue
	ThisUpdate          time.Time
	NextUpdate          time.Time                     `asn1:"optional"`
	RevokedCertificates []x509pkix.RevokedCertificate `asn1:"optional"`
	Extensions          []x509pkix.Extension          `asn1:"tag:0,optional,explicit"`
}

type testCertificateList struct {
	TBSCertList        asn1.RawValue
	SignatureAlgorithm x509pkix.AlgorithmIdentifier
	SignatureValue     asn1.BitString
}

// buildTestCRL encodes a CRL with the given version, entries and extensions,
// issued and signed (SHA256WithRSA, as certstrap did for RSA CAs) by ca and key.
func buildTestCRL(t *testing.T, ca *x509.Certificate, key crypto.Signer, version int, revoked []x509pkix.RevokedCertificate, extensions []x509pkix.Extension) []byte {
	t.Helper()
	algorithm := x509pkix.AlgorithmIdentifier{Algorithm: oidSHA256WithRSA, Parameters: asn1.NullRawValue}
	tbs, err := asn1.Marshal(testTBSCertList{
		Version:             version,
		Signature:           algorithm,
		Issuer:              asn1.RawValue{FullBytes: ca.RawSubject},
		ThisUpdate:          testRevocationTime,
		NextUpdate:          testRevocationTime.Add(crlValidity),
		RevokedCertificates: revoked,
		Extensions:          extensions,
	})
	if err != nil {
		t.Fatalf("could not marshal TBSCertList: %v", err)
	}
	digest := sha256.Sum256(tbs)
	signature, err := key.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("could not sign CRL: %v", err)
	}
	der, err := asn1.Marshal(testCertificateList{
		TBSCertList:        asn1.RawValue{FullBytes: tbs},
		SignatureAlgorithm: algorithm,
		SignatureValue:     asn1.BitString{Bytes: signature, BitLength: 8 * len(signature)},
	})
	if err != nil {
		t.Fatalf("could not marshal CertificateList: %v", err)
	}
	return der
}

func mustMarshal(t *testing.T, value any) []byte {
	t.Helper()
	b, err := asn1.Marshal(value)
	if err != nil {
		t.Fatalf("could not marshal %v: %v", value, err)
	}
	return b
}

func reasonCodeExtension(t *testing.T, reason int) x509pkix.Extension {
	return x509pkix.Extension{Id: oidExtensionReasonCode, Value: mustMarshal(t, asn1.Enumerated(reason))}
}

func invalidityDateExtension(t *testing.T) x509pkix.Extension {
	return x509pkix.Extension{Id: oidExtensionInvalidityDate, Value: mustMarshal(t, testRevocationTime)}
}

func crlNumberExtension(t *testing.T, number int64) x509pkix.Extension {
	return x509pkix.Extension{Id: oidExtensionCRLNumber, Value: mustMarshal(t, big.NewInt(number))}
}

// testRevokedCertificates returns two entries: one with a reason code and an
// invalidity date, and one without extensions.
func testRevokedCertificates(t *testing.T) []x509pkix.RevokedCertificate {
	return []x509pkix.RevokedCertificate{{
		SerialNumber:   big.NewInt(10),
		RevocationTime: testRevocationTime,
		Extensions:     []x509pkix.Extension{reasonCodeExtension(t, 1), invalidityDateExtension(t)},
	}, {
		SerialNumber:   big.NewInt(11),
		RevocationTime: secondTestRevocationTime,
	}}
}

type testSigner struct {
	name      string
	key       crypto.Signer
	algorithm x509.SignatureAlgorithm
}

// testSigners returns a key of every type and curve certstrap can create, with
// the signature algorithm x509 defaults to for it.
func testSigners(t *testing.T) []testSigner {
	t.Helper()
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("could not create RSA key: %v", err)
	}
	signers := []testSigner{{name: "RSA", key: rsaKey, algorithm: x509.SHA256WithRSA}}
	for _, curve := range []struct {
		curve     elliptic.Curve
		algorithm x509.SignatureAlgorithm
	}{
		{elliptic.P224(), x509.ECDSAWithSHA256},
		{elliptic.P256(), x509.ECDSAWithSHA256},
		{elliptic.P384(), x509.ECDSAWithSHA384},
		{elliptic.P521(), x509.ECDSAWithSHA512},
	} {
		key, err := ecdsa.GenerateKey(curve.curve, rand.Reader)
		if err != nil {
			t.Fatalf("could not create %s key: %v", curve.curve.Params().Name, err)
		}
		signers = append(signers, testSigner{name: curve.curve.Params().Name, key: key, algorithm: curve.algorithm})
	}
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("could not create Ed25519 key: %v", err)
	}
	return append(signers, testSigner{name: "Ed25519", key: edKey, algorithm: x509.PureEd25519})
}

// newTestCA returns a self-signed CA certificate for key with the key usage
// and subject key ID that certstrap CAs have.
func newTestCA(t *testing.T, key crypto.Signer) *x509.Certificate {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               x509pkix.Name{CommonName: "CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          []byte{1, 2, 3, 4},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatalf("could not create CA certificate: %v", err)
	}
	ca, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("could not parse CA certificate: %v", err)
	}
	return ca
}

func newTestRSACA(t *testing.T) (*x509.Certificate, crypto.Signer) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("could not create RSA key: %v", err)
	}
	return newTestCA(t, key), key
}

func TestParseRevocationList(t *testing.T) {
	ca, key := newTestRSACA(t)
	legacy, _ := pem.Decode([]byte(legacyCRLPEM))
	if legacy == nil {
		t.Fatal("could not decode legacy CRL PEM")
	}

	tests := []struct {
		name        string
		der         []byte
		wantNumber  *big.Int
		wantEntries []x509pkix.RevokedCertificate
	}{{
		name: "certstrap 2016 v1 CRL",
		der:  legacy.Bytes,
	}, {
		name:        "v1 CRL with revoked certificates",
		der:         buildTestCRL(t, ca, key, 0, testRevokedCertificates(t), nil),
		wantEntries: testRevokedCertificates(t),
	}, {
		name:        "v1 CRL with CRL number",
		der:         buildTestCRL(t, ca, key, 0, testRevokedCertificates(t), []x509pkix.Extension{crlNumberExtension(t, 41)}),
		wantNumber:  big.NewInt(41),
		wantEntries: testRevokedCertificates(t),
	}, {
		name:        "unnumbered v2 CRL",
		der:         buildTestCRL(t, ca, key, 1, testRevokedCertificates(t), nil),
		wantEntries: testRevokedCertificates(t),
	}, {
		name:        "numbered v2 CRL",
		der:         buildTestCRL(t, ca, key, 1, testRevokedCertificates(t), []x509pkix.Extension{crlNumberExtension(t, 41)}),
		wantNumber:  big.NewInt(41),
		wantEntries: testRevokedCertificates(t),
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			list, err := parseRevocationList(tc.der)
			if err != nil {
				t.Fatalf("could not parse CRL: %v", err)
			}
			if (list.Number == nil) != (tc.wantNumber == nil) || (tc.wantNumber != nil && list.Number.Cmp(tc.wantNumber) != 0) {
				t.Fatalf("Number = %v, want %v", list.Number, tc.wantNumber)
			}
			if len(list.RevokedCertificateEntries) != len(tc.wantEntries) {
				t.Fatalf("got %d revoked certificates, want %d", len(list.RevokedCertificateEntries), len(tc.wantEntries))
			}
			for i, want := range tc.wantEntries {
				got := list.RevokedCertificateEntries[i]
				if got.SerialNumber.Cmp(want.SerialNumber) != 0 || !got.RevocationTime.Equal(want.RevocationTime) {
					t.Fatalf("entry %d = (%v, %v), want (%v, %v)", i, got.SerialNumber, got.RevocationTime, want.SerialNumber, want.RevocationTime)
				}
				if len(got.Extensions) != len(want.Extensions) {
					t.Fatalf("entry %d has %d extensions, want %d", i, len(got.Extensions), len(want.Extensions))
				}
				wantReason := 0
				for j, ext := range want.Extensions {
					if !got.Extensions[j].Id.Equal(ext.Id) || !bytes.Equal(got.Extensions[j].Value, ext.Value) {
						t.Fatalf("entry %d extension %d = %v, want %v", i, j, got.Extensions[j], ext)
					}
					if ext.Id.Equal(oidExtensionReasonCode) {
						wantReason = 1
					}
				}
				if got.ReasonCode != wantReason {
					t.Fatalf("entry %d ReasonCode = %d, want %d", i, got.ReasonCode, wantReason)
				}
			}
		})
	}
}

func TestParseRevocationListErrors(t *testing.T) {
	ca, key := newTestRSACA(t)
	legacy, _ := pem.Decode([]byte(legacyCRLPEM))
	if legacy == nil {
		t.Fatal("could not decode legacy CRL PEM")
	}
	badReason := []x509pkix.RevokedCertificate{{
		SerialNumber:   big.NewInt(10),
		RevocationTime: testRevocationTime,
		// An INTEGER instead of an ENUMERATED.
		Extensions: []x509pkix.Extension{{Id: oidExtensionReasonCode, Value: mustMarshal(t, 1)}},
	}}

	tests := []struct {
		name string
		der  []byte
		// wantParserErr is set when the error must be the one from
		// x509.ParseRevocationList, i.e. not hidden by the v1 fallback.
		wantParserErr bool
		wantErr       string
	}{
		{name: "not a CRL", der: []byte("not a CRL"), wantParserErr: true},
		{name: "v1 CRL with trailing data", der: append(bytes.Clone(legacy.Bytes), 0), wantParserErr: true},
		{name: "v2 CRL with malformed reason code", der: buildTestCRL(t, ca, key, 1, badReason, nil), wantParserErr: true},
		{name: "v3 CRL", der: buildTestCRL(t, ca, key, 2, testRevokedCertificates(t), nil), wantParserErr: true},
		{name: "v1 CRL with malformed reason code", der: buildTestCRL(t, ca, key, 0, badReason, nil), wantErr: "malformed reason code in v1 CRL"},
		{
			name:    "v1 CRL with malformed CRL number",
			der:     buildTestCRL(t, ca, key, 0, nil, []x509pkix.Extension{{Id: oidExtensionCRLNumber, Value: mustMarshal(t, "41")}}),
			wantErr: "malformed CRL number in v1 CRL",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseRevocationList(tc.der)
			if err == nil {
				t.Fatal("parsed CRL, want error")
			}
			if tc.wantParserErr {
				_, parserErr := x509.ParseRevocationList(tc.der)
				if parserErr == nil || err.Error() != parserErr.Error() {
					t.Fatalf("error = %q, want x509.ParseRevocationList error %v", err, parserErr)
				}
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %q, want it to contain %q", err, tc.wantErr)
			}
		})
	}
}

func TestNextRevocationListNumber(t *testing.T) {
	tests := []struct {
		name    string
		current *big.Int
		want    int64
	}{
		{name: "unnumbered", current: nil, want: 1},
		{name: "zero", current: big.NewInt(0), want: 1},
		{name: "negative", current: big.NewInt(-3), want: 1},
		{name: "numbered", current: big.NewInt(7), want: 8},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var before *big.Int
			if tc.current != nil {
				before = new(big.Int).Set(tc.current)
			}
			next := nextRevocationList(&x509.RevocationList{Number: tc.current}, big.NewInt(1), time.Now())
			if next.Number.Cmp(big.NewInt(tc.want)) != 0 {
				t.Fatalf("Number = %v, want %d", next.Number, tc.want)
			}
			if before != nil && tc.current.Cmp(before) != 0 {
				t.Fatalf("current Number changed from %v to %v", before, tc.current)
			}
		})
	}
}

// TestNextRevocationListSigned revokes two certificates in turn, starting from
// an unnumbered v1 CRL, and checks the CRLs that x509.CreateRevocationList
// signs from the templates, for every key type.
func TestNextRevocationListSigned(t *testing.T) {
	legacyCA, legacyKey := newTestRSACA(t)
	legacy, err := parseRevocationList(buildTestCRL(t, legacyCA, legacyKey, 0, testRevokedCertificates(t), nil))
	if err != nil {
		t.Fatalf("could not parse v1 CRL: %v", err)
	}

	for _, signer := range testSigners(t) {
		t.Run(signer.name, func(t *testing.T) {
			ca := newTestCA(t, signer.key)
			revoke := func(current *x509.RevocationList, serial int64, now time.Time) *x509.RevocationList {
				t.Helper()
				der, err := x509.CreateRevocationList(rand.Reader, nextRevocationList(current, big.NewInt(serial), now), ca, signer.key)
				if err != nil {
					t.Fatalf("could not create CRL: %v", err)
				}
				list, err := x509.ParseRevocationList(der)
				if err != nil {
					t.Fatalf("could not parse CRL: %v", err)
				}
				if err := list.CheckSignatureFrom(ca); err != nil {
					t.Fatalf("CRL signature does not verify: %v", err)
				}
				if list.SignatureAlgorithm != signer.algorithm {
					t.Fatalf("SignatureAlgorithm = %v, want %v", list.SignatureAlgorithm, signer.algorithm)
				}
				if !bytes.Equal(list.RawIssuer, ca.RawSubject) || !bytes.Equal(list.AuthorityKeyId, ca.SubjectKeyId) {
					t.Fatal("CRL issuer or authority key ID does not match the CA")
				}
				if !list.ThisUpdate.Equal(now.Truncate(time.Second)) || !list.NextUpdate.Equal(now.Add(crlValidity).Truncate(time.Second)) {
					t.Fatalf("validity = [%v, %v], want [%v, %v]", list.ThisUpdate, list.NextUpdate, now, now.Add(crlValidity))
				}
				return list
			}

			first := time.Now().UTC()
			list := revoke(legacy, 12, first)
			list = revoke(list, 13, first.Add(time.Hour))

			if list.Number.Cmp(big.NewInt(2)) != 0 {
				t.Fatalf("Number = %v, want 2", list.Number)
			}
			want := []struct {
				serial int64
				time   time.Time
				reason int
			}{
				{10, testRevocationTime, 1},
				{11, secondTestRevocationTime, 0},
				{12, first.Truncate(time.Second), 0},
				{13, first.Add(time.Hour).Truncate(time.Second), 0},
			}
			if len(list.RevokedCertificateEntries) != len(want) {
				t.Fatalf("got %d revoked certificates, want %d", len(list.RevokedCertificateEntries), len(want))
			}
			for i, w := range want {
				got := list.RevokedCertificateEntries[i]
				if got.SerialNumber.Int64() != w.serial || !got.RevocationTime.Equal(w.time) || got.ReasonCode != w.reason {
					t.Fatalf("entry %d = (%v, %v, %d), want (%d, %v, %d)", i, got.SerialNumber, got.RevocationTime, got.ReasonCode, w.serial, w.time, w.reason)
				}
			}
			invalidityDate := invalidityDateExtension(t)
			var found bool
			for _, ext := range list.RevokedCertificateEntries[0].Extensions {
				found = found || (ext.Id.Equal(invalidityDate.Id) && bytes.Equal(ext.Value, invalidityDate.Value))
			}
			if !found {
				t.Fatalf("invalidity date extension was not preserved: %v", list.RevokedCertificateEntries[0].Extensions)
			}
		})
	}
}
