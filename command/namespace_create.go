// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package command

import (
	"fmt"
	"strings"

	"github.com/go-viper/mapstructure/v2"
	"github.com/hashicorp/cli"
	"github.com/openbao/openbao/api/v2"
	"github.com/posener/complete"
)

var (
	_ cli.Command             = (*NamespaceCreateCommand)(nil)
	_ cli.CommandAutocomplete = (*NamespaceCreateCommand)(nil)
)

type NamespaceCreateCommand struct {
	*BaseCommand

	flagCustomMetadata map[string]string
}

func (c *NamespaceCreateCommand) Synopsis() string {
	return "Create a new namespace"
}

func (c *NamespaceCreateCommand) Help() string {
	helpText := `
Usage: bao namespace create [options] PATH

  Create a child namespace. The namespace created will be relative to the
  namespace provided in either the BAO_NAMESPACE environment variable or
  -namespace CLI flag.

  Create a child namespace (e.g. ns1/):

      $ bao namespace create ns1

  Create a child namespace from a parent namespace (e.g. ns1/ns2/):

      $ bao namespace create -namespace=ns1 ns2

` + c.Flags().Help()

	return strings.TrimSpace(helpText)
}

func (c *NamespaceCreateCommand) Flags() *FlagSets {
	set := c.flagSet(FlagSetHTTP | FlagSetOutputField | FlagSetOutputFormat)

	f := set.NewFlagSet("Command Options")
	f.StringMapVar(&StringMapVar{
		Name:    "custom-metadata",
		Target:  &c.flagCustomMetadata,
		Default: map[string]string{},
		Usage: "Specifies arbitrary key=value metadata meant to describe a namespace." +
			"This can be specified multiple times to add multiple pieces of metadata.",
	})

	return set
}

func (c *NamespaceCreateCommand) AutocompleteArgs() complete.Predictor {
	return complete.PredictNothing
}

func (c *NamespaceCreateCommand) AutocompleteFlags() complete.Flags {
	return c.Flags().Completions()
}

func (c *NamespaceCreateCommand) Run(args []string) int {
	f := c.Flags()

	if err := f.Parse(args); err != nil {
		c.UI.Error(err.Error())
		return 1
	}

	args = f.Args()
	switch {
	case len(args) < 1:
		c.UI.Error(fmt.Sprintf("Not enough arguments (expected 1, got %d)", len(args)))
		return 1
	case len(args) > 1:
		c.UI.Error(fmt.Sprintf("Too many arguments (expected 1, got %d)", len(args)))
		return 1
	}

	namespacePath := strings.TrimSpace(args[0])

	client, err := c.Client()
	if err != nil {
		c.UI.Error(err.Error())
		return 2
	}

	resp, err := client.Sys().CreateNamespace(namespacePath, &api.CreateNamespaceInput{
		CustomMetadata: c.flagCustomMetadata,
	})
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error creating namespace: %s", err))
		return 2
	}

	out, err := structToMap(resp)
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error formatting response: %s", err))
		return 2
	}

	if c.flagField != "" {
		return PrintRawField(c.UI, out, c.flagField)
	}

	return OutputData(c.UI, out)
}

func structToMap(v interface{}) (map[string]interface{}, error) {
	m := map[string]interface{}{}
	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		TagName: "json",
		Result:  &m,
	})
	if err != nil {
		return nil, err
	}
	if err := decoder.Decode(v); err != nil {
		return nil, err
	}
	return m, nil
}
