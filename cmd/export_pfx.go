/*-
 * Copyright (c) 2018 Marco Stolze (alias mcpride)
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

// ExportPfxCommand sets up a "export-pfx" command to export certificate chain to personal information exchange format
func NewExportPfxCommand() cli.Command {
	return cli.Command{
		Name:        "export-pfx",
		Usage:       "Export certificate chain to personal information exchange format",
		Description: "Export certificate chain for host to personal information exchange format, including root certificate and key.",
		Flags: []cli.Flag{
			cli.StringFlag{Name: "passphrase", Value: "", Usage: "Passphrase to de- and encrypt private-key PEM block"},
			cli.StringFlag{Name: "chain", Value: "", Usage: "Names of chained parent certificates; comma delimited"},
			cli.BoolFlag{Name: "stdout", Usage: "Print signing request to stdout in addition to saving file"},
		},
		Action: exportPfxAction,
	}
}

func exportPfxAction(c *cli.Context) {
	var err error

	if len(c.Args()) != 1 {
		fmt.Fprintln(os.Stderr, "One name must be provided.")
		os.Exit(1)
	}

	formattedName := strings.Replace(c.Args()[0], " ", "_", -1)

	if depot.CheckPersonalInformationExchange(d, formattedName) {
		fmt.Fprintln(os.Stderr, "PFX has existed!")
		os.Exit(1)
	}

	passphrase := []byte{}

	key, err := depot.GetPrivateKey(d, formattedName)
	if err != nil {
		passphrase, err = getPassPhrase(c, "Certificate key")
		if err != nil {
			fmt.Fprintln(os.Stderr, "Get certificate key error:", err)
			os.Exit(1)
		}
		key, err = depot.GetEncryptedPrivateKey(d, formattedName, passphrase)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Get certificate key error:", err)
			os.Exit(1)
		}
	}

	cert, err := depot.GetCertificate(d, formattedName)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Get certificate error:", err)
		os.Exit(1)
	}

	caCrts := []*pkix.Certificate{}
	var formattedCANames []string = []string{}
	if c.IsSet("chain") {
		var formattedCAName string
		chain := strings.Split(c.String("chain"), ",")
		for i := range chain {
			formattedCAName = strings.Replace(chain[i], " ", "_", -1)
			ca, err := depot.GetCertificate(d, formattedCAName)
			if err != nil {
				fmt.Fprintln(os.Stderr, "Get chained certificate error:", err)
				os.Exit(1)
			}
			caCrts = append(caCrts, ca)
			formattedCANames = append(formattedCANames, fmt.Sprintf("%s/%s.crt", depotDir, formattedCAName))
		}
	}

	pfxBytes, err := depot.PutPersonalInformationExchange(d, formattedName, cert, key, caCrts, passphrase)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Export certificate chain to personal information exchange format failed:", err)
		os.Exit(1)
	} else {
		fmt.Printf("Created %s/%s.pfx from %s/%s.crt and %s/%s.key", depotDir, formattedName, depotDir, formattedName, depotDir, formattedName)
		if len(formattedCANames) > 0 {
			fmt.Printf(" with chain %s", formattedCANames)
		}
		fmt.Printf("\n")
	}

	if c.Bool("stdout") {
		fmt.Printf(string(pfxBytes[:]))
	}
}
