package cmd

import (
	"crypto/x509"
	"flag"
	"io/ioutil"
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
	tmp, err := ioutil.TempDir("", "certstrap-revoke")
	if err != nil {
		t.Fatalf("could not create tmp dir: %v", err)
	}
	defer os.RemoveAll(tmp)

	d, err = depot.NewFileDepot(tmp)
	if err != nil {
		t.Fatalf("could not create file depot: %v", err)
	}

	setupCA(t, d)
	setupCN(t, d)

	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.String("CA", "", "")
	fs.String("CN", "", "")
	if err := fs.Parse([]string{"-CA", "ca", "-CN", "cn"}); err != nil {
		t.Fatal("could not parse flags")
	}

	new(revokeCommand).run(cli.NewContext(nil, fs, nil))

	list, err := depot.GetCertificateRevocationList(d, caName)
	if err != nil {
		t.Fatalf("could not get crl: %v", err)
	}

	certList, err := x509.ParseDERCRL(list.DERBytes())
	if err != nil {
		t.Fatalf("could not parse crl: %v", err)
	}

	if len(certList.TBSCertList.RevokedCertificates) != 1 {
		t.Fatalf("unexpected number of revoked certs: want = 1, got = %d", len(certList.TBSCertList.RevokedCertificates))
	}

	cnCert, _ := depot.GetCertificate(d, cnName)
	cnX509, _ := cnCert.GetRawCertificate()

	if cnX509.SerialNumber.Cmp(certList.TBSCertList.RevokedCertificates[0].SerialNumber) != 0 {
		t.Fatalf("certificates serial numbers are not equal")
	}
}

func setupCA(t *testing.T, dt depot.Depot) {
	// create private key
	key, err := pkix.CreateRSAKey(2048)
	if err != nil {
		t.Fatalf("could not create RSA key: %v", err)
	}
	if err = depot.PutPrivateKey(dt, caName, key); err != nil {
		t.Fatalf("could not put private key: %v", err)
	}

	// create certificate authority
	caCert, err := pkix.CreateCertificateAuthority(key, caName, time.Now().Add(1*time.Minute), "", "", "", "", caName, nil, 0, false)
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

func setupCN(t *testing.T, dt depot.Depot) {
	// create private key
	key, err := pkix.CreateRSAKey(2048)
	if err != nil {
		t.Fatalf("could not create RSA key: %v", err)
	}
	if err = depot.PutPrivateKey(dt, cnName, key); err != nil {
		t.Fatalf("could not put private key: %v", err)
	}

	csr, err := pkix.CreateCertificateSigningRequest(key, cnName, nil, []string{"example.com"}, nil, "", "", "", "", cnName)
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
	if err = depot.PutCertificate(dt, "cn", cnCert); err != nil {
		t.Fatalf("could not put cert: %v", err)
	}
}
