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

package main

import (
	"os"

	"github.com/mcpride/certstrap/Godeps/_workspace/src/github.com/codegangsta/cli"
	"github.com/mcpride/certstrap/cmd"
	"github.com/mcpride/certstrap/depot"
)

func main() {
	app := cli.NewApp()
	app.Name = "certstrap"
	app.Version = "1.1.1"
	app.Usage = "A simple certificate manager written in Go, to bootstrap your own certificate authority and public key infrastructure."
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:   "depot-path",
			Value:  depot.DefaultFileDepotDir,
			Usage:  "Location to store certificates, keys and other files.",
			EnvVar: "",
		},
	}
	app.Author = "M. Stolze, Square Inc., CoreOS"
	app.Email = ""
	app.Commands = []cli.Command{
		cmd.NewInitCommand(),
		cmd.NewCertRequestCommand(),
		cmd.NewSignCommand(),
		cmd.ExportPfxCommand(),
	}
	app.Before = func(c *cli.Context) error {
		cmd.InitDepot(c.String("depot-path"))
		return nil
	}

	if err := app.Run(os.Args); err != nil {
		os.Exit(1)
	}
}
