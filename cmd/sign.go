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

	"github.com/square/certstrap/Godeps/_workspace/src/github.com/codegangsta/cli"
	"github.com/square/certstrap/depot"
	"github.com/square/certstrap/pkix"
)

// NewSignCommand sets up a "sign" command to sign a CSR with a given CA for a new certificate
func NewSignCommand() cli.Command {
	return cli.Command{
		Name:        "sign",
		Usage:       "Sign certificate request",
		Description: "Sign certificate request with CA, and generate certificate for the host.",
		Flags: []cli.Flag{
			cli.StringFlag{"passphrase", "", "Passphrase to decrypt private-key PEM block of CA", ""},
			cli.IntFlag{"years", 2, "How long until the certificate expires", ""},
			cli.StringFlag{"CA", "", "CA to sign cert", ""},
			cli.BoolFlag{"stdout", "Print certificate to stdout in addition to saving file", ""},
			cli.BoolFlag{"intermediate", "Generated certificate should be a intermediate", ""},
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
		fmt.Fprintln(os.Stderr, "Certificate has existed!")
		os.Exit(1)
	}

	csr, err := depot.GetCertificateSigningRequest(d, formattedReqName)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Get certificate request error:", err)
		os.Exit(1)
	}
	crt, err := depot.GetCertificate(d, formattedCAName)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Get CA certificate error:", err)
		os.Exit(1)
	}

	key, err := depot.GetPrivateKey(d, formattedCAName)
	if err != nil {
		key, err = depot.GetEncryptedPrivateKey(d, formattedCAName, getPassPhrase(c, "CA key"))
		if err != nil {
			fmt.Fprintln(os.Stderr, "Get CA key error:", err)
			os.Exit(1)
		}
	}

	var crtOut *pkix.Certificate
	if c.Bool("intermediate") {
		fmt.Fprintf(os.Stderr, "Building intermediate")
		crtOut, err = pkix.CreateIntermediateCertificateAuthority(crt, key, csr, c.Int("years"))
	} else {
		crtOut, err = pkix.CreateCertificateHost(crt, key, csr, c.Int("years"))
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
			fmt.Printf(string(crtBytes[:]))
		}
	}

	if err = depot.PutCertificate(d, formattedReqName, crtOut); err != nil {
		fmt.Fprintln(os.Stderr, "Save certificate error:", err)
	}
}
