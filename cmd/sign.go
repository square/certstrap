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

package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/square/certstrap/depot"
	"github.com/square/certstrap/pkix"
	"github.com/urfave/cli"
)

// NewSignCommand sets up a "sign" command to sign a CSR with a given CA for a new certificate
func NewSignCommand() cli.Command {
	return cli.Command{
		Name:        "sign",
		Usage:       "Sign certificate request",
		Description: "Sign certificate request with CA, and generate certificate for the host.",
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:  "passphrase",
				Usage: "Passphrase to decrypt private-key PEM block of CA",
			},
			cli.IntFlag{
				Name:   "years",
				Hidden: true,
			},
			cli.StringFlag{
				Name:  "expires",
				Value: "2 years",
				Usage: "How long until the certificate expires (example: 1 year 2 days 3 months 4 hours)",
			},
			cli.StringFlag{
				Name:  "CA",
				Usage: "Name of CA to issue cert with",
			},
			cli.StringFlag{
				Name:  "csr",
				Usage: "Path to certificate request PEM file (if blank, will use --depot-path and default name)",
			},
			cli.StringFlag{
				Name:  "cert",
				Usage: "Path to certificate output PEM file (if blank, will use --depot-path and default name)",
			},
			cli.BoolFlag{
				Name:  "stdout",
				Usage: "Print certificate to stdout in addition to saving file",
			},
			cli.BoolFlag{
				Name:  "intermediate",
				Usage: "Whether generated certificate should be a intermediate",
			},
		},
		Action: newSignAction,
	}
}

func newSignAction(c *cli.Context) {
	if len(c.Args()) != 1 {
		fmt.Fprintln(os.Stderr, "One host name must be provided.")
		os.Exit(1)
	}

	formattedReqName := strings.Replace(c.Args()[0], " ", "_", -1)
	formattedCAName := strings.Replace(c.String("CA"), " ", "_", -1)

	if depot.CheckCertificate(d, formattedReqName) {
		fmt.Fprintf(os.Stderr, "Certificate \"%s\" already exists!\n", formattedReqName)
		os.Exit(1)
	}

	expires := c.String("expires")
	if years := c.Int("years"); years != 0 {
		expires = fmt.Sprintf("%s %d years", expires, years)
	}

	// Expiry parsing is a naive regex implementation
	// Token based parsing would provide better feedback but
	expiresTime, err := parseExpiry(expires)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid expiry: %s\n", err)
		os.Exit(1)
	}

	csr, err := getCertificateSigningRequest(c, d, formattedReqName)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Get certificate request error:", err)
		os.Exit(1)
	}
	crt, err := depot.GetCertificate(d, formattedCAName)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Get CA certificate error:", err)
		os.Exit(1)
	}
	// Validate that crt is allowed to sign certificates.
	raw_crt, err := crt.GetRawCertificate()
	if err != nil {
		fmt.Fprintln(os.Stderr, "GetRawCertificate failed on CA certificate:", err)
		os.Exit(1)
	}
	// We punt on checking BasicConstraintsValid and checking MaxPathLen. The goal
	// is to prevent accidentally creating invalid certificates, not protecting
	// against malicious input.
	// We have run into test certificates which are version 1 and don't have basic
	// constraints. We can treat these certificates as valid if they are self-signed.
	if !raw_crt.IsCA && raw_crt.CheckSignatureFrom(raw_crt) != nil {
		fmt.Fprintln(os.Stderr, "Selected CA certificate is not allowed to sign certificates.")
		os.Exit(1)
	}

	key, err := depot.GetPrivateKey(d, formattedCAName)
	if err != nil {
		pass, err := getPassPhrase(c, "CA key")
		if err != nil {
			fmt.Fprintln(os.Stderr, "Get CA key error: ", err)
			os.Exit(1)
		}
		key, err = depot.GetEncryptedPrivateKey(d, formattedCAName, pass)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Get CA key error: ", err)
			os.Exit(1)
		}
	}

	var crtOut *pkix.Certificate
	if c.Bool("intermediate") {
		fmt.Fprintln(os.Stderr, "Building intermediate")
		crtOut, err = pkix.CreateIntermediateCertificateAuthority(crt, key, csr, expiresTime)
	} else {
		crtOut, err = pkix.CreateCertificateHost(crt, key, csr, expiresTime)
	}

	if err != nil {
		fmt.Fprintln(os.Stderr, "Create certificate error:", err)
		os.Exit(1)
	} else {
		fmt.Printf("Created %s/%s.crt from %s/%s.csr signed by %s/%s.key\n", depotDir, formattedReqName, depotDir, formattedReqName, depotDir, formattedCAName)
	}

	if c.Bool("stdout") {
		crtBytes, err := crtOut.Export()
		if err != nil {
			fmt.Fprintln(os.Stderr, "Print certificate error:", err)
			os.Exit(1)
		} else {
			fmt.Printf(string(crtBytes))
		}
	}

	if err = putCertificate(c, d, formattedReqName, crtOut); err != nil {
		fmt.Fprintln(os.Stderr, "Save certificate error:", err)
	}
}
