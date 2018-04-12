/*-
 * Copyright (c) 2018 Marco Stolze (alias mcpride)
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
	"io/ioutil"
	"os"
	"strings"

	"github.com/mcpride/certstrap/Godeps/_workspace/src/github.com/codegangsta/cli"
	"github.com/mcpride/certstrap/depot"
	"github.com/mcpride/certstrap/pkix"
)

// NewInitCommand sets up an "init" command to initialize a new CA
func NewInitCommand() cli.Command {
	return cli.Command{
		Name:        "init",
		Usage:       "Create Certificate Authority",
		Description: "Create Certificate Authority, including certificate, key and extra information file.",
		Flags: []cli.Flag{
			cli.StringFlag{"passphrase", "", "Passphrase to encrypt private-key PEM block", ""},
			cli.IntFlag{"key-bits", 4096, "Bit size of RSA keypair to generate", ""},
			cli.IntFlag{"years", 0, "DEPRECATED; Use --expires instead", ""},
			cli.StringFlag{"expires", "18 months", "How long until the certificate expires. Example: 1 year 2 days 3 months 4 hours", ""},
			cli.StringFlag{"organization, o", "", "CA Certificate organization", ""},
			cli.StringFlag{"organizational-unit, ou", "", "CA Certificate organizational unit", ""},
			cli.StringFlag{"country, c", "", "CA Certificate country", ""},
			cli.StringFlag{"common-name, cn", "", "CA Common Name", ""},
			cli.StringFlag{"province, st", "", "CA state/province", ""},
			cli.StringFlag{"locality, l", "", "CA locality", ""},
			cli.StringFlag{"key", "", "Path to private key PEM file.  If blank, will generate new keypair.", ""},
			cli.StringFlag{"out-name, on", "", "Name for output files without path and extension. If blank, CA common name will be used.", ""},
			cli.BoolFlag{"stdout", "Print CA certificate to stdout in addition to saving file", ""},
		},
		Action: initAction,
	}
}

func initAction(c *cli.Context) {

	if !c.IsSet("common-name") {
		fmt.Println("Must supply Common Name for CA")
		os.Exit(1)
	}

	formattedName := strings.Replace(c.String("common-name"), " ", "_", -1)
	if c.IsSet("out-name") {
		formattedName = strings.Replace(c.String("out-name"), " ", "_", -1)
	}

	if depot.CheckCertificate(d, formattedName) || depot.CheckPrivateKey(d, formattedName) {
		fmt.Fprintln(os.Stderr, "CA with specified name already exists!")
		os.Exit(1)
	}

	var err error
	expires := c.String("expires")
	if years := c.Int("years"); years != 0 {
		expires = fmt.Sprintf("%s %s years", expires, years)
	}

	// Expiry parsing is a naive regex implementation
	// Token based parsing would provide better feedback but
	expiresTime, err := parseExpiry(expires)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid expiry: %s\n", err)
		os.Exit(1)
	}

	var passphrase []byte
	if c.IsSet("passphrase") {
		passphrase = []byte(c.String("passphrase"))
	} else {
		passphrase, err = createPassPhrase()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}

	var key *pkix.Key
	if c.IsSet("key") {
		keyBytes, err := ioutil.ReadFile(c.String("key"))
		key, err = pkix.NewKeyFromPrivateKeyPEM(keyBytes)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Read Key error:", err)
			os.Exit(1)
		}
		fmt.Printf("Read %s\n", c.String("key"))
	} else {
		key, err = pkix.CreateRSAKey(c.Int("key-bits"))
		if err != nil {
			fmt.Fprintln(os.Stderr, "Create RSA Key error:", err)
			os.Exit(1)
		}
		if len(passphrase) > 0 {
			fmt.Printf("Created %s/%s.key (encrypted by passphrase)\n", depotDir, formattedName)
		} else {
			fmt.Printf("Created %s/%s.key\n", depotDir, formattedName)
		}
	}

	crt, err := pkix.CreateCertificateAuthority(key, c.String("organizational-unit"), expiresTime, c.String("organization"), c.String("country"), c.String("province"), c.String("locality"), c.String("common-name"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "Create certificate error:", err)
		os.Exit(1)
	}
	fmt.Printf("Created %s/%s.crt\n", depotDir, formattedName)

	if c.Bool("stdout") {
		crtBytes, err := crt.Export()
		if err != nil {
			fmt.Fprintln(os.Stderr, "Print CA certificate error:", err)
			os.Exit(1)
		} else {
			fmt.Printf(string(crtBytes[:]))
		}
	}

	if err = depot.PutCertificate(d, formattedName, crt); err != nil {
		fmt.Fprintln(os.Stderr, "Save certificate error:", err)
	}
	if len(passphrase) > 0 {
		if err = depot.PutEncryptedPrivateKey(d, formattedName, key, passphrase); err != nil {
			fmt.Fprintln(os.Stderr, "Save encrypted private key error:", err)
		}
	} else {
		if err = depot.PutPrivateKey(d, formattedName, key); err != nil {
			fmt.Fprintln(os.Stderr, "Save private key error:", err)
		}
	}

	// Create an empty CRL, this is useful for Java apps which mandate a CRL.
	crl, err := pkix.CreateCertificateRevocationList(key, crt, expiresTime)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Create CRL error:", err)
		os.Exit(1)
	}
	if err = depot.PutCertificateRevocationList(d, formattedName, crl); err != nil {
		fmt.Fprintln(os.Stderr, "Save CRL error:", err)
		os.Exit(1)
	}
	fmt.Printf("Created %s/%s.crl\n", depotDir, formattedName)
}
