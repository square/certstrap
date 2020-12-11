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
	"io/ioutil"
	"os"
	"strings"

	"github.com/square/certstrap/depot"
	"github.com/square/certstrap/pkix"
	"github.com/urfave/cli"
)

// NewInitCommand sets up an "init" command to initialize a new CA
func NewInitCommand() cli.Command {
	return cli.Command{
		Name:        "init",
		Usage:       "Create Certificate Authority",
		Description: "Create Certificate Authority, including certificate, key and extra information file.",
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:  "passphrase",
				Usage: "Passphrase to encrypt private key PEM block",
			},
			cli.IntFlag{
				Name:  "key-bits",
				Value: 4096,
				Usage: "Size (in bits) of RSA keypair to generate (example: 4096)",
			},
			cli.IntFlag{
				Name:   "years",
				Hidden: true,
			},
			cli.StringFlag{
				Name:  "expires",
				Value: "18 months",
				Usage: "How long until the certificate expires (example: 1 year 2 days 3 months 4 hours)",
			},
			cli.StringFlag{
				Name:  "organization, o",
				Usage: "Sets the Organization (O) field of the certificate",
			},
			cli.StringFlag{
				Name:  "organizational-unit, ou",
				Usage: "Sets the Organizational Unit (OU) field of the certificate",
			},
			cli.StringFlag{
				Name:  "country, c",
				Usage: "Sets the Country (C) field of the certificate",
			},
			cli.StringFlag{
				Name:  "common-name, cn",
				Usage: "Sets the Common Name (CN) field of the certificate",
			},
			cli.StringFlag{
				Name:  "province, st",
				Usage: "Sets the State/Province (ST) field of the certificate",
			},
			cli.StringFlag{
				Name:  "locality, l",
				Usage: "Sets the Locality (L) field of the certificate",
			},
			cli.StringFlag{
				Name:  "key",
				Usage: "Path to private key PEM file (if blank, will generate new key pair)",
			},
			cli.BoolFlag{
				Name:  "stdout",
				Usage: "Print certificate to stdout in addition to saving file",
			},
			cli.StringSliceFlag{
				Name:  "permit-domain",
				Usage: "Create a CA restricted to subdomains of this domain (can be specified multiple times)",
			},
			cli.StringFlag{
				Name:  "root-ca",
				Usage: "Create a CA with RootCA and RootKey",
			},
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

	if depot.CheckCertificate(d, formattedName) || depot.CheckPrivateKey(d, formattedName) {
		fmt.Fprintf(os.Stderr, "CA with specified name \"%s\" already exists!\n", formattedName)
		os.Exit(1)
	}

	var err error
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
		if err != nil {
			fmt.Fprintln(os.Stderr, "Read Key error:", err)
			os.Exit(1)
		}

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

	var rootCA *pkix.RootCA

	if c.IsSet("root-ca") {
		formattedCAName := strings.Replace(c.String("root-ca"), " ", "_", -1)

		crt, err := depot.GetCertificate(d, formattedCAName)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Get CA certificate error:", err)
			os.Exit(1)
		}
		cert, err := crt.GetRawCertificate()
		if err != nil {
			fmt.Fprintln(os.Stderr, "Get CA certificate error:", err)
			os.Exit(1)
		}

		if !cert.IsCA {
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
		rootCA = &pkix.RootCA{}
		rootCA.RootCA = cert
		rootCA.PriKey = key.Private
	}

	crt, err := pkix.CreateCertificateAuthority(key, rootCA,
		c.String("organizational-unit"), expiresTime, c.String("organization"),
		c.String("country"), c.String("province"), c.String("locality"),
		c.String("common-name"), c.StringSlice("permit-domain"))
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
			fmt.Println(string(crtBytes))
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
