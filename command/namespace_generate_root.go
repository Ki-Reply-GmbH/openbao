// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package command

import (
	"fmt"
	"strings"

	"github.com/hashicorp/cli"
	"github.com/posener/complete"
)

var (
	_ cli.Command             = (*NamespaceGenerateRootCommand)(nil)
	_ cli.CommandAutocomplete = (*NamespaceGenerateRootCommand)(nil)
)

type NamespaceGenerateRootCommand struct {
	*BaseCommand

	flagGenerateRootInit bool
}

func (c *NamespaceGenerateRootCommand) Synopsis() string {
	return "List child namespaces"
}

func (c *NamespaceGenerateRootCommand) Help() string {
	helpText := `
Usage: bao namespace generate-root [options] PATH

    - A base64-encoded one-time-password (OTP) provided via the "-otp" flag.
      Use the "-generate-otp" flag to generate a usable value. The resulting
      token is XORed with this value when it is returned. Use the "-decode"
      flag to output the final value.

    - A file containing a PGP key or a keybase username in the "-pgp-key"
      flag. The resulting token is encrypted with this public key.

  An unseal key may be provided directly on the command line as an argument to
  the command. If key is specified as "-", the command will read from stdin. If
  a TTY is available, the command will prompt for text.

  Generate an OTP code for the final token:

      $ bao namespace generate-root -generate-otp

  Start a root token generation:

      $ bao namespace generate-root -init -otp="..." PATH
      $ bao namespace generate-root -init -pgp-key="..." PATH

  Enter an unseal key to progress root token generation:

      $ bao namespace generate-root -otp="..." PATH

` + c.Flags().Help()

	return strings.TrimSpace(helpText)
}

func (c *NamespaceGenerateRootCommand) Flags() *FlagSets {
	set := c.flagSet(FlagSetHTTP | FlagSetOutputFormat)

	f := set.NewFlagSet("Command Options")

	f.BoolVar(&BoolVar{
		Name:    "init",
		Target:  &c.flagGenerateRootInit,
		Default: false,
		Usage:   "Init a new root key generation for a given namespace.",
	})

	return set
}

func (c *NamespaceGenerateRootCommand) AutocompleteArgs() complete.Predictor {
	return complete.PredictNothing
}

func (c *NamespaceGenerateRootCommand) AutocompleteFlags() complete.Flags {
	return c.Flags().Completions()
}

func (c *NamespaceGenerateRootCommand) Run(args []string) int {
	f := c.Flags()

	if err := f.Parse(args); err != nil {
		c.UI.Error(err.Error())
		return 1
	}

	args = f.Args()
	if len(args) > 1 {
		c.UI.Error(fmt.Sprintf("Too many arguments (expected 1, got %d)", len(args)))
		return 1
	}

	namespacePath := strings.TrimSpace(args[0])

	client, err := c.Client()
	if err != nil {
		c.UI.Error(err.Error())
		return 2
	}

	var requestSuffix string
	if c.flagGenerateRootInit {
		requestSuffix = "/generate/root/attempt"
	} else {
		requestSuffix = "/generate-root/update"
	}

	secret, err := client.Logical().Write("sys/namespaces"+namespacePath+requestSuffix, map[string]interface{}{})
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error listing namespaces: %s", err))
		return 2
	}

	_, ok := extractListData(secret)
	if Format(c.UI) != "table" {
		if secret == nil || secret.Data == nil || !ok {
			OutputData(c.UI, map[string]interface{}{})
			return 2
		}
	}

	if secret == nil {
		c.UI.Error("No namespaces found")
		return 2
	}

	// There could be e.g. warnings
	if secret.Data == nil {
		return OutputSecret(c.UI, secret)
	}

	if secret.WrapInfo != nil && secret.WrapInfo.TTL != 0 {
		return OutputSecret(c.UI, secret)
	}

	if !ok {
		c.UI.Error("No entries found")
		return 2
	}

	if c.flagDetailed && Format(c.UI) != "table" {
		return OutputData(c.UI, secret.Data["key_info"])
	}

	return OutputList(c.UI, secret)
}
