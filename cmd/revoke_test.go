package cmd

import (
	"crypto"
	"crypto/elliptic"
	"crypto/x509"
	x509pkix "crypto/x509/pkix"
	"flag"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/square/certstrap/depot"
	"github.com/square/certstrap/pkix"
	"github.com/urfave/cli"
)

const (
	caName = "ca"
	cnName = "cn"
)

func TestRevokeCmd(t *testing.T) {
	tests := []struct {
		name      string
		createKey func() (*pkix.Key, error)
	}{
		{name: "RSA", createKey: func() (*pkix.Key, error) { return pkix.CreateRSAKey(2048) }},
		{name: "P-224", createKey: func() (*pkix.Key, error) { return pkix.CreateECDSAKey(elliptic.P224()) }},
		{name: "P-256", createKey: func() (*pkix.Key, error) { return pkix.CreateECDSAKey(elliptic.P256()) }},
		{name: "P-384", createKey: func() (*pkix.Key, error) { return pkix.CreateECDSAKey(elliptic.P384()) }},
		{name: "P-521", createKey: func() (*pkix.Key, error) { return pkix.CreateECDSAKey(elliptic.P521()) }},
		{name: "Ed25519", createKey: pkix.CreateEd25519Key},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			setupDepot(t)
			setupCA(t, d, tc.createKey)
			setupCN(t, d, cnName)
			setupCN(t, d, "cn2")

			runRevoke(t, cnName)
			first := revocationListFromDepot(t)
			assertRevoked(t, first, big.NewInt(2), cnName)

			runRevoke(t, "cn2")
			second := revocationListFromDepot(t)
			assertRevoked(t, second, big.NewInt(3), cnName, "cn2")
			if !second.RevokedCertificateEntries[0].RevocationTime.Equal(first.RevokedCertificateEntries[0].RevocationTime) {
				t.Fatal("revocation time of the first certificate changed")
			}
		})
	}
}

// TestRevokeCmdExistingCRL revokes a certificate in depots whose CRL predates
// numbered CRLs: unnumbered v2 CRLs, as written by x509.Certificate.CreateCRL,
// and v1 CRLs, as written by certstrap releases built with old Go versions.
func TestRevokeCmdExistingCRL(t *testing.T) {
	tests := []struct {
		name    string
		version int
	}{
		{name: "v1", version: 0},
		{name: "unnumbered v2", version: 1},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			setupDepot(t)
			setupCA(t, d, func() (*pkix.Key, error) { return pkix.CreateRSAKey(2048) })
			setupCN(t, d, cnName)

			caCert, err := depot.GetCertificate(d, caName)
			if err != nil {
				t.Fatalf("could not get CA certificate: %v", err)
			}
			caX509, err := caCert.GetRawCertificate()
			if err != nil {
				t.Fatalf("could not parse CA certificate: %v", err)
			}
			caKey, err := depot.GetPrivateKey(d, caName)
			if err != nil {
				t.Fatalf("could not get CA key: %v", err)
			}
			existing := []x509pkix.RevokedCertificate{{
				SerialNumber:   big.NewInt(10),
				RevocationTime: testRevocationTime,
				Extensions:     []x509pkix.Extension{reasonCodeExtension(t, 1)},
			}}
			der := buildTestCRL(t, caX509, caKey.Private.(crypto.Signer), tc.version, existing, nil)
			if err := d.Delete(depot.CrlTag(caName)); err != nil {
				t.Fatalf("could not delete CRL: %v", err)
			}
			if err := depot.PutCertificateRevocationList(d, caName, pkix.NewCertificateRevocationListFromDER(der)); err != nil {
				t.Fatalf("could not put CRL: %v", err)
			}

			runRevoke(t, cnName)

			list := revocationListFromDepot(t)
			if list.Number == nil || list.Number.Cmp(big.NewInt(1)) != 0 {
				t.Fatalf("Number = %v, want 1", list.Number)
			}
			if len(list.RevokedCertificateEntries) != 2 {
				t.Fatalf("unexpected number of revoked certs: want = 2, got = %d", len(list.RevokedCertificateEntries))
			}
			old := list.RevokedCertificateEntries[0]
			if old.SerialNumber.Cmp(big.NewInt(10)) != 0 || !old.RevocationTime.Equal(testRevocationTime) || old.ReasonCode != 1 {
				t.Fatalf("existing entry = (%v, %v, %d), want (10, %v, 1)", old.SerialNumber, old.RevocationTime, old.ReasonCode, testRevocationTime)
			}
			if list.RevokedCertificateEntries[1].SerialNumber.Cmp(certificateSerial(t, cnName)) != 0 {
				t.Fatal("certificates serial numbers are not equal")
			}
		})
	}
}

func setupDepot(t *testing.T) {
	t.Helper()
	tmp, err := os.MkdirTemp("", "certstrap-revoke")
	if err != nil {
		t.Fatalf("could not create tmp dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(tmp) })

	d, err = depot.NewFileDepot(tmp)
	if err != nil {
		t.Fatalf("could not create file depot: %v", err)
	}
}

func runRevoke(t *testing.T, cn string) {
	t.Helper()
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.String("CA", "", "")
	fs.String("CN", "", "")
	if err := fs.Parse([]string{"-CA", caName, "-CN", cn}); err != nil {
		t.Fatal("could not parse flags")
	}

	new(revokeCommand).run(cli.NewContext(nil, fs, nil))
}

func revocationListFromDepot(t *testing.T) *x509.RevocationList {
	t.Helper()
	list, err := depot.GetCertificateRevocationList(d, caName)
	if err != nil {
		t.Fatalf("could not get crl: %v", err)
	}

	certList, err := x509.ParseRevocationList(list.DERBytes())
	if err != nil {
		t.Fatalf("could not parse crl: %v", err)
	}

	caCert, err := depot.GetCertificate(d, caName)
	if err != nil {
		t.Fatalf("could not get CA certificate: %v", err)
	}
	caX509, err := caCert.GetRawCertificate()
	if err != nil {
		t.Fatalf("could not parse CA certificate: %v", err)
	}
	if err := certList.CheckSignatureFrom(caX509); err != nil {
		t.Fatalf("crl signature does not verify: %v", err)
	}
	return certList
}

func certificateSerial(t *testing.T, name string) *big.Int {
	t.Helper()
	cert, err := depot.GetCertificate(d, name)
	if err != nil {
		t.Fatalf("could not get certificate: %v", err)
	}
	x509Cert, err := cert.GetRawCertificate()
	if err != nil {
		t.Fatalf("could not parse certificate: %v", err)
	}
	return x509Cert.SerialNumber
}

// assertRevoked checks that list has the given CRL number and revokes the
// named certificates, in order.
func assertRevoked(t *testing.T, list *x509.RevocationList, number *big.Int, names ...string) {
	t.Helper()
	if list.Number == nil || list.Number.Cmp(number) != 0 {
		t.Fatalf("Number = %v, want %v", list.Number, number)
	}
	if len(list.RevokedCertificateEntries) != len(names) {
		t.Fatalf("unexpected number of revoked certs: want = %d, got = %d", len(names), len(list.RevokedCertificateEntries))
	}
	for i, name := range names {
		if certificateSerial(t, name).Cmp(list.RevokedCertificateEntries[i].SerialNumber) != 0 {
			t.Fatalf("certificates serial numbers are not equal for %s", name)
		}
	}
}

func setupCA(t *testing.T, dt depot.Depot, createKey func() (*pkix.Key, error)) {
	// create private key
	key, err := createKey()
	if err != nil {
		t.Fatalf("could not create key: %v", err)
	}
	if err = depot.PutPrivateKey(dt, caName, key); err != nil {
		t.Fatalf("could not put private key: %v", err)
	}

	// create certificate authority
	caCert, err := pkix.CreateCertificateAuthority(key, caName, time.Now().Add(1*time.Minute), "", "", "", "", caName, nil)
	if err != nil {
		t.Fatalf("could not create authority cert: %v", err)
	}
	if err = depot.PutCertificate(dt, caName, caCert); err != nil {
		t.Fatalf("could not put certificate: %v", err)
	}

	// create an empty certificate revocation list
	crl, err := pkix.CreateCertificateRevocationList(key, caCert, time.Now().Add(1*time.Minute))
	if err != nil {
		t.Fatalf("could not create crl: %v", err)
	}
	if err = depot.PutCertificateRevocationList(dt, caName, crl); err != nil {
		t.Fatalf("could not put crl: %v", err)
	}
}

func setupCN(t *testing.T, dt depot.Depot, name string) {
	// create private key
	key, err := pkix.CreateRSAKey(2048)
	if err != nil {
		t.Fatalf("could not create RSA key: %v", err)
	}
	if err = depot.PutPrivateKey(dt, name, key); err != nil {
		t.Fatalf("could not put private key: %v", err)
	}

	csr, err := pkix.CreateCertificateSigningRequest(key, name, nil, []string{"example.com"}, nil, "", "", "", "", name)
	if err != nil {
		t.Fatalf("could not create csr: %v", err)
	}

	caCert, err := depot.GetCertificate(dt, caName)
	if err != nil {
		t.Fatalf("could not get cert: %v", err)
	}

	caKey, err := depot.GetPrivateKey(dt, caName)
	if err != nil {
		t.Fatalf("could not get CA key: %v", err)
	}

	cnCert, err := pkix.CreateCertificateHost(caCert, caKey, csr, time.Now().Add(1*time.Hour))
	if err != nil {
		t.Fatalf("could not create cert host: %v", err)
	}
	if err = depot.PutCertificate(dt, name, cnCert); err != nil {
		t.Fatalf("could not put cert: %v", err)
	}
}
