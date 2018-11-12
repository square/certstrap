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
	"regexp"
	"strings"

	"github.com/codegangsta/cli"
	"github.com/square/certstrap/depot"
	"github.com/square/certstrap/pkix"

	"strconv"
	"encoding/asn1"
	x509pkix "crypto/x509/pkix"
)

// NewCertRequestCommand sets up a "request-cert" command to create a request for a new certificate (CSR)
func NewCertRequestCommand() cli.Command {
	return cli.Command{
		Name:        "request-cert",
		Usage:       "Create certificate request for host",
		Description: "Create certificate for host, including certificate signing request and key.  Must sign the request in order to generate a certificate.",
		Flags: []cli.Flag{
			cli.StringFlag{"passphrase", "", "Passphrase to encrypt private-key PEM block", ""},
			cli.IntFlag{"key-bits", 2048, "Bit size of RSA keypair to generate", ""},
			cli.StringFlag{"organization, o", "", "Certificate organization", ""},
			cli.StringFlag{"country, c", "", "Certificate country", ""},
			cli.StringFlag{"locality, l", "", "Certificate locality", ""},
			cli.StringFlag{"common-name, cn", "", "Certificate common name, will be domain if left empty, fail otherwise", ""},
			cli.StringFlag{"organizational-unit, ou", "", "Certificate organizational unit", ""},
			cli.StringFlag{"province, st", "", "Certificate state/province", ""},
			cli.StringFlag{"ip", "", "IP address entries for subject alt name (comma separated)", ""},
			cli.StringFlag{"domain", "", "DNS entries for subject alt name (comma separated)", ""},
			cli.StringFlag{"uri", "", "URI for subject alt name (comma separated)", ""},
			cli.StringFlag{"key", "", "Path to private key PEM file.  If blank, will generate new keypair.", ""},
			cli.BoolFlag{"stdout", "Print signing request to stdout in addition to saving file", ""},

			cli.StringFlag{"eku", "", "Comma-separated list of EKU OIDs. If the anyExtendedKeyUsage OID (2.5.29.37.0) is not in this list, the extension will be marked critical.", ""},
		},
		Action: newCertAction,
	}
}

func newCertAction(c *cli.Context) {
	var name = ""
	var err error

	// The CLI Context returns an empty string ("") if no value is available
	ips, err := pkix.ParseAndValidateIPs(c.String("ip"))

	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	// The CLI Context returns an empty string ("") if no value is available
	uris, err := pkix.ParseAndValidateURIs(c.String("uri"))

	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	domains := strings.Split(c.String("domain"), ",")
	if c.String("domain") == "" {
		domains = nil
	}

	switch {
	case len(c.String("common-name")) != 0:
		name = c.String("common-name")
	case len(domains) != 0:
		name = domains[0]
	default:
		fmt.Fprintln(os.Stderr, "Must provide Common Name or domain")
		os.Exit(1)
	}

	var formattedName = formatName(name)

	if depot.CheckCertificateSigningRequest(d, formattedName) || depot.CheckPrivateKey(d, formattedName) {
		fmt.Fprintln(os.Stderr, "Certificate request has existed!")
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
		fmt.Printf("Read %s.key\n", name)
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

	var ekuExtension *x509pkix.Extension
	if c.IsSet("eku") {
		var anyEKUOid asn1.ObjectIdentifier = asn1.ObjectIdentifier{2, 5, 29, 37, 0}
		var sawAnyEKUOid bool = false
		var oids []asn1.ObjectIdentifier
		for _, oidString := range strings.Split(c.String("eku"), ",") {
			var thisOid asn1.ObjectIdentifier
			var isAnyEKUOid bool = true
			for i, oidComponent := range strings.Split(oidString, ".") {
				var thisOidComponent int
				if val, err := strconv.Atoi(oidComponent); err == nil {
					thisOidComponent = val
				} else {
					fmt.Fprintln(os.Stderr, "OID component parsing error:", err)
					os.Exit(1)
				}
				thisOid = append(thisOid, thisOidComponent)
				if i < len(anyEKUOid) {
					isAnyEKUOid = isAnyEKUOid && (thisOidComponent == anyEKUOid[i])
				} else {
					isAnyEKUOid = false
				}
			}
			if len(thisOid) > 0 {
				oids = append(oids, thisOid)
				sawAnyEKUOid = sawAnyEKUOid || isAnyEKUOid
			}
		}
		if len(oids) > 0 {
			if val, err := asn1.Marshal(oids); err == nil {
				ekuExtension = &x509pkix.Extension{
					Id: asn1.ObjectIdentifier{2, 5, 29, 37},
					Critical: !sawAnyEKUOid,
					Value: val,
				}
			} else {
				fmt.Fprintln(os.Stderr, "Error marshalling EKU extension:", err)
				os.Exit(1)
			}
		}
	}

	var extensionsList []x509pkix.Extension
	var extensions *[]x509pkix.Extension = nil
	if ekuExtension != nil {
		extensionsList = append(extensionsList, *ekuExtension)
	}
	if len(extensionsList) > 0 {
		extensions = &extensionsList
	}

	csr, err := pkix.CreateCertificateSigningRequest(key, c.String("organizational-unit"), ips, domains, uris, c.String("organization"), c.String("country"), c.String("province"), c.String("locality"), name, extensions)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Create certificate request error:", err)
		os.Exit(1)
	} else {
		fmt.Printf("Created %s/%s.csr\n", depotDir, formattedName)
	}

	if c.Bool("stdout") {
		csrBytes, err := csr.Export()
		if err != nil {
			fmt.Fprintln(os.Stderr, "Print certificate request error:", err)
			os.Exit(1)
		} else {
			fmt.Printf(string(csrBytes))
		}
	}

	if err = depot.PutCertificateSigningRequest(d, formattedName, csr); err != nil {
		fmt.Fprintln(os.Stderr, "Save certificate request error:", err)
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
}

func formatName(name string) string {
	var filenameAcceptable, err = regexp.Compile("[^a-zA-Z0-9._-]")
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error compiling regex:", err)
		os.Exit(1)
	}
	return string(filenameAcceptable.ReplaceAll([]byte(name), []byte("_")))
}
