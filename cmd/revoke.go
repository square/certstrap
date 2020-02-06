package cmd

import (
	"crypto/rand"
	"crypto/x509"
	x509pkix "crypto/x509/pkix"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/square/certstrap/depot"
	"github.com/square/certstrap/pkix"
	"github.com/urfave/cli"
)

type revokeCommand struct {
	ca, cn string
}

// NewRevokeCommand revokes the given certificate by adding it to the CA's CRL.
func NewRevokeCommand() cli.Command {
	return cli.Command{
		Name:        "revoke",
		Usage:       "Revoke certificate",
		Description: "Add certificate to the CA's CRL.",
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:  "CN",
				Usage: "Common Name (CN) of certificate to revoke",
			},
			cli.StringFlag{
				Name:  "CA",
				Usage: "Name of CA under which certificate was issued",
			},
		},
		Action: new(revokeCommand).run,
	}
}

func (c *revokeCommand) checkErr(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}

func (c *revokeCommand) parseArgs(ctx *cli.Context) error {
	if ctx.String("CA") == "" {
		return errors.New("CA name must be provided")
	}
	c.ca = strings.Replace(ctx.String("CA"), " ", "_", -1)

	if ctx.String("CN") == "" {
		return errors.New("CN name must be provided")
	}
	c.cn = strings.Replace(ctx.String("CN"), " ", "_", -1)

	return nil
}

func (c *revokeCommand) run(ctx *cli.Context) {
	c.checkErr(c.parseArgs(ctx))

	caCert, err := c.CAx509Certificate()
	c.checkErr(err)

	cnCert, err := c.CNx509Certificate()
	c.checkErr(err)

	revoked, err := c.revokedCertificates()
	c.checkErr(err)

	revoked = append(revoked, x509pkix.RevokedCertificate{
		SerialNumber:   cnCert.SerialNumber,
		RevocationTime: time.Now(),
	})

	err = c.saveRevokedCertificates(caCert, revoked)
	c.checkErr(err)
}

func (c *revokeCommand) CAx509Certificate() (*x509.Certificate, error) {
	cert, err := depot.GetCertificate(d, c.ca)
	if err != nil {
		return nil, err
	}
	return cert.GetRawCertificate()
}

func (c *revokeCommand) CNx509Certificate() (*x509.Certificate, error) {
	cert, err := depot.GetCertificate(d, c.cn)
	if err != nil {
		return nil, err
	}
	return cert.GetRawCertificate()
}

func (c *revokeCommand) revokedCertificates() ([]x509pkix.RevokedCertificate, error) {
	list, err := depot.GetCertificateRevocationList(d, c.ca)
	if err != nil {
		return nil, err
	}

	certList, err := x509.ParseDERCRL(list.DERBytes())
	if err != nil {
		return nil, err
	}

	return certList.TBSCertList.RevokedCertificates, nil
}

func (c *revokeCommand) saveRevokedCertificates(cert *x509.Certificate, list []x509pkix.RevokedCertificate) error {
	priv, err := depot.GetPrivateKey(d, c.ca)
	if err != nil {
		return fmt.Errorf("could not get %q private key: %v", c.ca, err)
	}

	crlBytes, err := cert.CreateCRL(rand.Reader, priv.Private, list, time.Now(), time.Now().Add(2*8760*time.Hour))
	if err != nil {
		return fmt.Errorf("could not create CRL: %v", err)
	}
	if err := d.Delete(depot.CrlTag(c.ca)); err != nil {
		return fmt.Errorf("could not delete CRL: %v", err)
	}
	if err = depot.PutCertificateRevocationList(d, c.ca, pkix.NewCertificateRevocationListFromDER(crlBytes)); err != nil {
		return fmt.Errorf("could not put revokation list: %v", err)
	}
	return nil
}
