package main

import (
	"os"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/plugin"
	example "github.com/nicholasjackson/vault-plugin-template"
)

func main() {
	apiClientMeta := &api.PluginAPIClientMeta{}
	flags := apiClientMeta.FlagSet()
	flags.Parse(os.Args[1:])

	tlsConfig := apiClientMeta.GetTLSConfig()
	tlsProviderFunc := api.VaultPluginTLSProvider(tlsConfig)

	logger := hclog.New(&hclog.LoggerOptions{})
	err := plugin.Serve(&plugin.ServeOpts{
		BackendFactoryFunc: example.Factory,
		TLSProviderFunc:    tlsProviderFunc,
		Logger:             logger,
	})

	if err != nil {
		logger.Error("plugin shutting down", "error", err)
		os.Exit(1)
	}
}
