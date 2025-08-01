// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package command

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	systemd "github.com/coreos/go-systemd/v22/daemon"
	"github.com/hashicorp/cli"
	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/go-secure-stdlib/gatedwriter"
	"github.com/hashicorp/go-secure-stdlib/parseutil"
	"github.com/hashicorp/go-secure-stdlib/reloadutil"
	"github.com/mitchellh/go-testing-interface"
	wrapping "github.com/openbao/go-kms-wrapping/v2"
	aeadwrapper "github.com/openbao/go-kms-wrapping/wrappers/aead/v2"
	"github.com/openbao/openbao/api/v2"
	"github.com/openbao/openbao/audit"
	config2 "github.com/openbao/openbao/command/config"
	"github.com/openbao/openbao/command/server"
	"github.com/openbao/openbao/helper/builtinplugins"
	loghelper "github.com/openbao/openbao/helper/logging"
	"github.com/openbao/openbao/helper/metricsutil"
	"github.com/openbao/openbao/helper/namespace"
	"github.com/openbao/openbao/helper/profiles"
	"github.com/openbao/openbao/helper/testhelpers/teststorage"
	"github.com/openbao/openbao/helper/useragent"
	vaulthttp "github.com/openbao/openbao/http"
	"github.com/openbao/openbao/internalshared/configutil"
	"github.com/openbao/openbao/internalshared/listenerutil"
	"github.com/openbao/openbao/sdk/v2/helper/consts"
	"github.com/openbao/openbao/sdk/v2/helper/jsonutil"
	"github.com/openbao/openbao/sdk/v2/helper/strutil"
	"github.com/openbao/openbao/sdk/v2/helper/testcluster"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/sdk/v2/physical"
	sr "github.com/openbao/openbao/serviceregistration"
	"github.com/openbao/openbao/vault"
	vaultseal "github.com/openbao/openbao/vault/seal"
	"github.com/openbao/openbao/version"
	"github.com/pkg/errors"
	"github.com/posener/complete"
	"github.com/sasha-s/go-deadlock"
	"go.uber.org/atomic"
	"golang.org/x/net/http/httpproxy"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
	"google.golang.org/grpc/grpclog"
)

var (
	_ cli.Command             = (*ServerCommand)(nil)
	_ cli.CommandAutocomplete = (*ServerCommand)(nil)
)

var memProfilerEnabled = false

const (
	storageMigrationLock = "core/migration"

	// Even though there are more types than the ones below, the following consts
	// are declared internally for value comparison and reusability.
	storageTypeRaft = "raft"
)

type ServerCommand struct {
	*BaseCommand
	logFlags logFlags

	AuditBackends      map[string]audit.Factory
	CredentialBackends map[string]logical.Factory
	LogicalBackends    map[string]logical.Factory
	PhysicalBackends   map[string]physical.Factory

	ServiceRegistrations map[string]sr.Factory

	ShutdownCh chan struct{}
	SighupCh   chan struct{}
	SigUSR2Ch  chan struct{}

	WaitGroup *sync.WaitGroup

	logWriter io.Writer
	logGate   *gatedwriter.Writer
	logger    hclog.InterceptLogger

	cleanupGuard sync.Once

	reloadFuncsLock *sync.RWMutex
	reloadFuncs     *map[string][]reloadutil.ReloadFunc
	startedCh       chan (struct{}) // for tests
	reloadedCh      chan (struct{}) // for tests

	allLoggers []hclog.Logger

	flagConfigs            []string
	flagRecovery           bool
	flagDev                bool
	flagDevTLS             bool
	flagDevTLSCertDir      string
	flagDevRootTokenID     string
	flagDevListenAddr      string
	flagDevNoStoreToken    bool
	flagDevPluginDir       string
	flagDevPluginInit      bool
	flagDevHA              bool
	flagDevLatency         int
	flagDevLatencyJitter   int
	flagDevLeasedKV        bool
	flagDevKVV1            bool
	flagDevSkipInit        bool
	flagDevThreeNode       bool
	flagDevAutoSeal        bool
	flagDevClusterJson     string
	flagTestVerifyOnly     bool
	flagTestServerConfig   bool
	flagExitOnCoreShutdown bool
}

func (c *ServerCommand) Synopsis() string {
	return "Start an OpenBao server"
}

func (c *ServerCommand) Help() string {
	helpText := `
Usage: bao server [options]

  This command starts an OpenBao server that responds to API requests. By default,
  OpenBao will start in a "sealed" state. The OpenBao cluster must be initialized
  before use, usually by the "bao operator init" command. Each OpenBao server must
  also be unsealed using the "bao operator unseal" command or the API before the
  server can respond to requests.

  Start a server with a configuration file:

      $ bao server -config=/etc/openbao/config.hcl

  Run in "dev" mode:

      $ bao server -dev -dev-root-token-id="root"

  For a full list of examples, please see the documentation.

` + c.Flags().Help()
	return strings.TrimSpace(helpText)
}

func (c *ServerCommand) Flags() *FlagSets {
	set := c.flagSet(FlagSetHTTP)

	f := set.NewFlagSet("Command Options")

	// Augment with the log flags
	f.addLogFlags(&c.logFlags)

	f.StringSliceVar(&StringSliceVar{
		Name:   "config",
		Target: &c.flagConfigs,
		Completion: complete.PredictOr(
			complete.PredictFiles("*.hcl"),
			complete.PredictFiles("*.json"),
			complete.PredictDirs("*"),
		),
		Usage: "Path to a configuration file or directory of configuration " +
			"files. This flag can be specified multiple times to load multiple " +
			"configurations. If the path is a directory, all files which end in " +
			".hcl or .json are loaded.",
	})

	f.BoolVar(&BoolVar{
		Name:    "exit-on-core-shutdown",
		Target:  &c.flagExitOnCoreShutdown,
		Default: false,
		Usage:   "Exit the OpenBao server if the OpenBao core is shutdown.",
	})

	f.BoolVar(&BoolVar{
		Name:   "recovery",
		Target: &c.flagRecovery,
		Usage: "Enable recovery mode. In this mode, OpenBao is used to perform recovery actions." +
			"Using a recovery operation token, \"sys/raw\" API can be used to manipulate the storage.",
	})

	f = set.NewFlagSet("Dev Options")

	f.BoolVar(&BoolVar{
		Name:   "dev",
		Target: &c.flagDev,
		Usage: "Enable development mode. In this mode, OpenBao runs in-memory and " +
			"starts unsealed. As the name implies, do not run \"dev\" mode in " +
			"production.",
	})

	f.BoolVar(&BoolVar{
		Name:   "dev-tls",
		Target: &c.flagDevTLS,
		Usage: "Enable TLS development mode. In this mode, OpenBao runs in-memory and " +
			"starts unsealed, with a generated TLS CA, certificate and key. " +
			"As the name implies, do not run \"dev-tls\" mode in " +
			"production.",
	})

	f.StringVar(&StringVar{
		Name:    "dev-tls-cert-dir",
		Target:  &c.flagDevTLSCertDir,
		Default: "",
		Usage: "Directory where generated TLS files are created if `-dev-tls` is " +
			"specified. If left unset, files are generated in a temporary directory.",
	})

	f.StringVar(&StringVar{
		Name:    "dev-root-token-id",
		Target:  &c.flagDevRootTokenID,
		Default: "",
		EnvVar:  "BAO_DEV_ROOT_TOKEN_ID",
		Usage: "Initial root token. This only applies when running in \"dev\" " +
			"mode.",
	})

	f.StringVar(&StringVar{
		Name:    "dev-listen-address",
		Target:  &c.flagDevListenAddr,
		Default: "127.0.0.1:8200",
		EnvVar:  "BAO_DEV_LISTEN_ADDRESS",
		Usage:   "Address to bind to in \"dev\" mode.",
	})
	f.BoolVar(&BoolVar{
		Name:    "dev-no-store-token",
		Target:  &c.flagDevNoStoreToken,
		Default: false,
		Usage: "Do not persist the dev root token to the token helper " +
			"(usually the local filesystem) for use in future requests. " +
			"The token will only be displayed in the command output.",
	})

	// Internal-only flags to follow.
	//
	// Why hello there little source code reader! Welcome to the OpenBao source
	// code. The remaining options are intentionally undocumented and come with
	// no warranty or backwards-compatibility promise. Do not use these flags
	// in production. Do not build automation using these flags. Unless you are
	// developing against OpenBao, you should not need any of these flags.

	f.StringVar(&StringVar{
		Name:       "dev-plugin-dir",
		Target:     &c.flagDevPluginDir,
		Default:    "",
		Completion: complete.PredictDirs("*"),
		Hidden:     true,
	})

	f.BoolVar(&BoolVar{
		Name:    "dev-plugin-init",
		Target:  &c.flagDevPluginInit,
		Default: true,
		Hidden:  true,
	})

	f.BoolVar(&BoolVar{
		Name:    "dev-ha",
		Target:  &c.flagDevHA,
		Default: false,
		Hidden:  true,
	})

	f.IntVar(&IntVar{
		Name:   "dev-latency",
		Target: &c.flagDevLatency,
		Hidden: true,
	})

	f.IntVar(&IntVar{
		Name:   "dev-latency-jitter",
		Target: &c.flagDevLatencyJitter,
		Hidden: true,
	})

	f.BoolVar(&BoolVar{
		Name:    "dev-leased-kv",
		Target:  &c.flagDevLeasedKV,
		Default: false,
		Hidden:  true,
	})

	f.BoolVar(&BoolVar{
		Name:    "dev-kv-v1",
		Target:  &c.flagDevKVV1,
		Default: false,
		Hidden:  true,
	})

	f.BoolVar(&BoolVar{
		Name:    "dev-auto-seal",
		Target:  &c.flagDevAutoSeal,
		Default: false,
		Hidden:  true,
	})

	f.BoolVar(&BoolVar{
		Name:    "dev-skip-init",
		Target:  &c.flagDevSkipInit,
		Default: false,
		Hidden:  true,
	})

	f.BoolVar(&BoolVar{
		Name:    "dev-three-node",
		Target:  &c.flagDevThreeNode,
		Default: false,
		Hidden:  true,
	})

	f.StringVar(&StringVar{
		Name:   "dev-cluster-json",
		Target: &c.flagDevClusterJson,
		Usage:  "File to write cluster definition to",
	})

	// TODO: should the below flags be public?
	f.BoolVar(&BoolVar{
		Name:    "test-verify-only",
		Target:  &c.flagTestVerifyOnly,
		Default: false,
		Hidden:  true,
	})

	f.BoolVar(&BoolVar{
		Name:    "test-server-config",
		Target:  &c.flagTestServerConfig,
		Default: false,
		Hidden:  true,
	})

	// End internal-only flags.

	return set
}

func (c *ServerCommand) AutocompleteArgs() complete.Predictor {
	return complete.PredictNothing
}

func (c *ServerCommand) AutocompleteFlags() complete.Flags {
	return c.Flags().Completions()
}

func (c *ServerCommand) flushLog() {
	c.logger.(hclog.OutputResettable).ResetOutputWithFlush(&hclog.LoggerOptions{
		Output: c.logWriter,
	}, c.logGate)
}

func (c *ServerCommand) parseConfig() (*server.Config, []configutil.ConfigError, error) {
	var configErrors []configutil.ConfigError
	// Load the configuration
	var config *server.Config
	for _, path := range c.flagConfigs {
		current, err := server.LoadConfig(path, c.flagConfigs)
		if err != nil {
			return nil, nil, fmt.Errorf("error loading configuration from %s: %w", path, err)
		}

		// While current may be nil, we'll never get a nil configuration as a
		// result of ignoring a configuration file present in a directory.
		if current != nil {
			configErrors = append(configErrors, current.Validate(path)...)

			if config == nil {
				config = current
			} else {
				config = config.Merge(current)
			}
		} else {
			c.UI.Warn(fmt.Sprintf("WARNING: ignoring duplicate configuration found in directory: %v", path))
		}
	}

	return config, configErrors, nil
}

func (c *ServerCommand) runRecoveryMode() int {
	config, configErrors, err := c.parseConfig()
	if err != nil {
		c.UI.Error(err.Error())
		return 1
	}

	// Ensure at least one config was found.
	if config == nil {
		c.UI.Output(wrapAtLength(
			"No configuration files found. Please provide configurations with the " +
				"-config flag. If you are supplying the path to a directory, please " +
				"ensure the directory contains files with the .hcl or .json " +
				"extension."))
		return 1
	}

	// Update the 'log' related aspects of shared config based on config/env var/cli
	c.flags.applyLogConfigOverrides(config.SharedConfig)
	l, err := c.configureLogging(config)
	if err != nil {
		c.UI.Error(err.Error())
		return 1
	}
	c.logger = l
	c.allLoggers = append(c.allLoggers, l)

	// reporting Errors found in the config
	for _, cErr := range configErrors {
		c.logger.Warn(cErr.String())
	}

	// Ensure logging is flushed if initialization fails
	defer c.flushLog()

	// create GRPC logger
	namedGRPCLogFaker := c.logger.Named("grpclogfaker")
	grpclog.SetLogger(&grpclogFaker{
		logger: namedGRPCLogFaker,
		log:    api.ReadBaoVariable("BAO_GRPC_LOGGING") != "",
	})

	if config.Storage == nil {
		c.UI.Output("A storage backend must be specified")
		return 1
	}

	if config.DefaultMaxRequestDuration != 0 {
		vault.DefaultMaxRequestDuration = config.DefaultMaxRequestDuration
	}

	logProxyEnvironmentVariables(c.logger)

	// Initialize the storage backend
	factory, exists := c.PhysicalBackends[config.Storage.Type]
	if !exists {
		c.UI.Error(fmt.Sprintf("Unknown storage type %s", config.Storage.Type))
		return 1
	}
	if config.Storage.Type == storageTypeRaft || (config.HAStorage != nil && config.HAStorage.Type == storageTypeRaft) {
		if envCA := api.ReadBaoVariable("BAO_CLUSTER_ADDR"); envCA != "" {
			config.ClusterAddr = envCA
		}

		if len(config.ClusterAddr) == 0 {
			c.UI.Error("Cluster address must be set when using raft storage")
			return 1
		}
	}

	namedStorageLogger := c.logger.Named("storage." + config.Storage.Type)
	backend, err := factory(config.Storage.Config, namedStorageLogger)
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error initializing storage of type %s: %s", config.Storage.Type, err))
		return 1
	}

	infoKeys := make([]string, 0, 10)
	info := make(map[string]string)
	info["log level"] = config.LogLevel
	infoKeys = append(infoKeys, "log level")

	var barrierSeal vault.Seal
	var sealConfigError error
	var wrapper wrapping.Wrapper

	if len(config.Seals) == 0 {
		config.Seals = append(config.Seals, &configutil.KMS{Type: wrapping.WrapperTypeShamir.String()})
	}

	if len(config.Seals) > 1 {
		c.UI.Error("Only one seal block is accepted in recovery mode")
		return 1
	}

	configSeal := config.Seals[0]
	sealType := wrapping.WrapperTypeShamir.String()
	if !configSeal.Disabled && api.ReadBaoVariable("BAO_SEAL_TYPE") != "" {
		sealType = api.ReadBaoVariable("BAO_SEAL_TYPE")
		configSeal.Type = sealType
	} else {
		sealType = configSeal.Type
	}

	infoKeys = append(infoKeys, "Seal Type")
	info["Seal Type"] = sealType

	var seal vault.Seal
	defaultSeal := vault.NewDefaultSeal(vaultseal.NewAccess(aeadwrapper.NewShamirWrapper()))
	sealLogger := c.logger.ResetNamed(fmt.Sprintf("seal.%s", sealType))
	wrapper, sealConfigError = configutil.ConfigureWrapper(configSeal, &infoKeys, &info, sealLogger)
	if sealConfigError != nil {
		if !errwrap.ContainsType(sealConfigError, new(logical.KeyNotFoundError)) {
			c.UI.Error(fmt.Sprintf(
				"Error parsing Seal configuration: %s", sealConfigError))
			return 1
		}
	}
	if wrapper == nil {
		seal = defaultSeal
	} else {
		seal, err = vault.NewAutoSeal(vaultseal.NewAccess(wrapper))
		if err != nil {
			c.UI.Error(fmt.Sprintf("error creating auto seal: %v", err))
		}
	}
	barrierSeal = seal

	// Ensure that the seal finalizer is called, even if using verify-only
	defer func() {
		err = seal.Finalize(context.Background())
		if err != nil {
			c.UI.Error(fmt.Sprintf("Error finalizing seals: %v", err))
		}
	}()

	coreConfig := &vault.CoreConfig{
		Physical:     backend,
		StorageType:  config.Storage.Type,
		Seal:         barrierSeal,
		LogLevel:     config.LogLevel,
		Logger:       c.logger,
		RecoveryMode: c.flagRecovery,
		ClusterAddr:  config.ClusterAddr,
	}

	core, newCoreError := vault.NewCore(coreConfig)
	if newCoreError != nil {
		if vault.IsFatalError(newCoreError) {
			c.UI.Error(fmt.Sprintf("Error initializing core: %s", newCoreError))
			return 1
		}
	}

	if err := core.InitializeRecovery(context.Background()); err != nil {
		c.UI.Error(fmt.Sprintf("Error initializing core in recovery mode: %s", err))
		return 1
	}

	// Compile server information for output later
	infoKeys = append(infoKeys, "storage")
	info["storage"] = config.Storage.Type

	if coreConfig.ClusterAddr != "" {
		info["cluster address"] = coreConfig.ClusterAddr
		infoKeys = append(infoKeys, "cluster address")
	}

	// Initialize the listeners
	lns := make([]listenerutil.Listener, 0, len(config.Listeners))
	for _, lnConfig := range config.Listeners {
		ln, _, _, err := server.NewListener(lnConfig, c.logger, c.logGate, c.UI)
		if err != nil {
			c.UI.Error(fmt.Sprintf("Error initializing listener of type %s: %s", lnConfig.Type, err))
			return 1
		}

		lns = append(lns, listenerutil.Listener{
			Listener: ln,
			Config:   lnConfig,
		})
	}

	listenerCloseFunc := func() {
		for _, ln := range lns {
			ln.Listener.Close()
		}
	}

	defer c.cleanupGuard.Do(listenerCloseFunc)

	infoKeys = append(infoKeys, "version")
	verInfo := version.GetVersion()
	info["version"] = verInfo.FullVersionNumber(false)

	if verInfo.Revision != "" {
		info["version sha"] = strings.Trim(verInfo.Revision, "'")
		infoKeys = append(infoKeys, "version sha")
	}

	infoKeys = append(infoKeys, "recovery mode")
	info["recovery mode"] = "true"

	infoKeys = append(infoKeys, "go version")
	info["go version"] = runtime.Version()

	// Server configuration output
	padding := 24

	sort.Strings(infoKeys)
	c.UI.Output("==> OpenBao server configuration:\n")

	titleCaser := cases.Title(language.English, cases.NoLower)

	for _, k := range infoKeys {
		c.UI.Output(fmt.Sprintf(
			"%s%s: %s",
			strings.Repeat(" ", padding-len(k)),
			titleCaser.String(k),
			info[k]))
	}

	c.UI.Output("")

	// Tests might not want to start a vault server and just want to verify
	// the configuration.
	if c.flagTestVerifyOnly {
		return 0
	}

	for _, ln := range lns {
		handler := vaulthttp.Handler.Handler(&vault.HandlerProperties{
			Core:                  core,
			ListenerConfig:        ln.Config,
			AllListeners:          lns,
			DisablePrintableCheck: config.DisablePrintableCheck,
			RecoveryMode:          c.flagRecovery,
			RecoveryToken:         atomic.NewString(""),
		})

		server := &http.Server{
			Handler:           handler,
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       30 * time.Second,
			IdleTimeout:       5 * time.Minute,
			ErrorLog:          c.logger.StandardLogger(nil),
		}

		go server.Serve(ln.Listener)
	}

	if sealConfigError != nil {
		init, err := core.InitializedLocally(context.Background())
		if err != nil {
			c.UI.Error(fmt.Sprintf("Error checking if core is initialized: %v", err))
			return 1
		}
		if init {
			c.UI.Error("Vault is initialized but no Seal key could be loaded")
			return 1
		}
	}

	if newCoreError != nil {
		c.UI.Warn(wrapAtLength(
			"WARNING! A non-fatal error occurred during initialization. Please " +
				"check the logs for more information."))
		c.UI.Warn("")
	}

	if !c.logFlags.flagCombineLogs {
		c.UI.Output("==> OpenBao server started! Log data will stream in below:\n")
	}

	c.flushLog()

	for {
		select {
		case <-c.ShutdownCh:
			c.UI.Output("==> OpenBao shutdown triggered")

			c.cleanupGuard.Do(listenerCloseFunc)

			if err := core.Shutdown(); err != nil {
				c.UI.Error(fmt.Sprintf("Error with core shutdown: %s", err))
			}

			return 0

		case <-c.SigUSR2Ch:
			buf := make([]byte, 32*1024*1024)
			n := runtime.Stack(buf[:], true)
			c.logger.Info("goroutine trace", "stack", string(buf[:n]))
		}
	}
}

func logProxyEnvironmentVariables(logger hclog.Logger) {
	proxyCfg := httpproxy.FromEnvironment()
	cfgMap := map[string]string{
		"http_proxy":  proxyCfg.HTTPProxy,
		"https_proxy": proxyCfg.HTTPSProxy,
		"no_proxy":    proxyCfg.NoProxy,
	}
	for k, v := range cfgMap {
		u, err := url.Parse(v)
		if err != nil {
			// Env vars may contain URLs or host:port values.  We only care
			// about the former.
			continue
		}
		if _, ok := u.User.Password(); ok {
			u.User = url.UserPassword("redacted-username", "redacted-password")
		} else if user := u.User.Username(); user != "" {
			u.User = url.User("redacted-username")
		}
		cfgMap[k] = u.String()
	}
	logger.Info("proxy environment", "http_proxy", cfgMap["http_proxy"],
		"https_proxy", cfgMap["https_proxy"], "no_proxy", cfgMap["no_proxy"])
}

type quiescenceSink struct {
	t *time.Timer
}

func (q quiescenceSink) Accept(name string, level hclog.Level, msg string, args ...interface{}) {
	q.t.Reset(100 * time.Millisecond)
}

func (c *ServerCommand) setupStorage(config *server.Config) (physical.Backend, error) {
	// Ensure that a backend is provided
	if config.Storage == nil {
		return nil, errors.New("A storage backend must be specified")
	}

	// Initialize the backend
	factory, exists := c.PhysicalBackends[config.Storage.Type]
	if !exists {
		return nil, fmt.Errorf("Unknown storage type %s", config.Storage.Type)
	}

	// Do any custom configuration needed per backend
	switch config.Storage.Type {
	case storageTypeRaft:
		if envCA := api.ReadBaoVariable("BAO_CLUSTER_ADDR"); envCA != "" {
			config.ClusterAddr = envCA
		}
		if len(config.ClusterAddr) == 0 {
			return nil, errors.New("Cluster address must be set when using raft storage")
		}
	}

	namedStorageLogger := c.logger.Named("storage." + config.Storage.Type)
	c.allLoggers = append(c.allLoggers, namedStorageLogger)
	backend, err := factory(config.Storage.Config, namedStorageLogger)
	if err != nil {
		return nil, fmt.Errorf("Error initializing storage of type %s: %w", config.Storage.Type, err)
	}

	return backend, nil
}

func beginServiceRegistration(c *ServerCommand, config *server.Config) (sr.ServiceRegistration, error) {
	sdFactory, ok := c.ServiceRegistrations[config.ServiceRegistration.Type]
	if !ok {
		return nil, fmt.Errorf("Unknown service_registration type %s", config.ServiceRegistration.Type)
	}

	namedSDLogger := c.logger.Named("service_registration." + config.ServiceRegistration.Type)
	c.allLoggers = append(c.allLoggers, namedSDLogger)

	// Since we haven't even begun starting OpenBao's core yet,
	// we know that OpenBao is in its pre-running state.
	state := sr.State{
		VaultVersion:         version.GetVersion().VersionNumber(),
		IsInitialized:        false,
		IsSealed:             true,
		IsActive:             false,
		IsPerformanceStandby: false,
	}
	var err error
	configSR, err := sdFactory(config.ServiceRegistration.Config, namedSDLogger, state)
	if err != nil {
		return nil, fmt.Errorf("Error initializing service_registration of type %s: %s", config.ServiceRegistration.Type, err)
	}

	return configSR, nil
}

// InitListeners returns a response code, error message, Listeners, and a TCP Address list.
func (c *ServerCommand) InitListeners(logger hclog.Logger, config *server.Config, disableClustering bool, infoKeys *[]string, info *map[string]string) (int, []listenerutil.Listener, []*net.TCPAddr, error) {
	clusterAddrs := []*net.TCPAddr{}

	// Initialize the listeners
	lns := make([]listenerutil.Listener, 0, len(config.Listeners))

	c.reloadFuncsLock.Lock()

	defer c.reloadFuncsLock.Unlock()

	var errMsg error
	for i, lnConfig := range config.Listeners {
		ln, props, cg, err := server.NewListener(lnConfig, c.logger, c.logGate, c.UI)
		if err != nil {
			errMsg = fmt.Errorf("Error initializing listener of type %s: %s", lnConfig.Type, err)
			return 1, nil, nil, errMsg
		}

		if cg != nil {
			relSlice := (*c.reloadFuncs)["listener|"+lnConfig.Type]
			relSlice = append(relSlice, cg.Reload)
			(*c.reloadFuncs)["listener|"+lnConfig.Type] = relSlice
		}

		if !disableClustering && lnConfig.Type == "tcp" {
			addr := lnConfig.ClusterAddress
			if addr != "" {
				tcpAddr, err := net.ResolveTCPAddr("tcp", lnConfig.ClusterAddress)
				if err != nil {
					errMsg = fmt.Errorf("Error resolving cluster_address: %s", err)
					return 1, nil, nil, errMsg
				}
				clusterAddrs = append(clusterAddrs, tcpAddr)
			} else {
				tcpAddr, ok := ln.Addr().(*net.TCPAddr)
				if !ok {
					errMsg = errors.New("Failed to parse tcp listener")
					return 1, nil, nil, errMsg
				}
				clusterAddr := &net.TCPAddr{
					IP:   tcpAddr.IP,
					Port: tcpAddr.Port + 1,
				}
				clusterAddrs = append(clusterAddrs, clusterAddr)
				addr = clusterAddr.String()
			}
			props["cluster address"] = addr
		}

		if lnConfig.MaxRequestSize == 0 {
			lnConfig.MaxRequestSize = vaulthttp.DefaultMaxRequestSize
		}
		props["max_request_size"] = fmt.Sprintf("%d", lnConfig.MaxRequestSize)

		if lnConfig.MaxRequestDuration == 0 {
			lnConfig.MaxRequestDuration = vault.DefaultMaxRequestDuration
		}
		props["max_request_duration"] = lnConfig.MaxRequestDuration.String()

		lns = append(lns, listenerutil.Listener{
			Listener: ln,
			Config:   lnConfig,
		})

		// Store the listener props for output later
		key := fmt.Sprintf("listener %d", i+1)
		propsList := make([]string, 0, len(props))
		for k, v := range props {
			propsList = append(propsList, fmt.Sprintf(
				"%s: %q", k, v))
		}
		sort.Strings(propsList)
		*infoKeys = append(*infoKeys, key)
		(*info)[key] = fmt.Sprintf(
			"%s (%s)", lnConfig.Type, strings.Join(propsList, ", "))

	}
	if !disableClustering {
		if c.logger.IsDebug() {
			c.logger.Debug("cluster listener addresses synthesized", "cluster_addresses", clusterAddrs)
		}
	}
	return 0, lns, clusterAddrs, nil
}

func configureDevTLS(c *ServerCommand) (func(), *server.Config, string, error) {
	var devStorageType string

	switch {
	case c.flagDevHA:
		devStorageType = "inmem_ha"
	default:
		devStorageType = "inmem"
	}

	var certDir string
	var err error
	var config *server.Config
	var f func()

	if c.flagDevTLS {
		if c.flagDevTLSCertDir != "" {
			if _, err = os.Stat(c.flagDevTLSCertDir); err != nil {
				return nil, nil, "", err
			}

			certDir = c.flagDevTLSCertDir
		} else {
			if certDir, err = os.MkdirTemp("", "vault-tls"); err != nil {
				return nil, nil, certDir, err
			}
		}
		config, err = server.DevTLSConfig(devStorageType, certDir)

		f = func() {
			if err := os.Remove(fmt.Sprintf("%s/%s", certDir, server.VaultDevCAFilename)); err != nil {
				c.UI.Error(err.Error())
			}

			if err := os.Remove(fmt.Sprintf("%s/%s", certDir, server.VaultDevCertFilename)); err != nil {
				c.UI.Error(err.Error())
			}

			if err := os.Remove(fmt.Sprintf("%s/%s", certDir, server.VaultDevKeyFilename)); err != nil {
				c.UI.Error(err.Error())
			}

			// Only delete temp directories we made.
			if c.flagDevTLSCertDir == "" {
				if err := os.Remove(certDir); err != nil {
					c.UI.Error(err.Error())
				}
			}
		}

	} else {
		config, err = server.DevConfig(devStorageType)
	}

	return f, config, certDir, err
}

func (c *ServerCommand) Run(args []string) int {
	f := c.Flags()

	if err := f.Parse(args); err != nil {
		c.UI.Error(err.Error())
		return 1
	}

	// Don't exit just because we saw a potential deadlock.
	deadlock.Opts.OnPotentialDeadlock = func() {}

	c.logGate = gatedwriter.NewWriter(os.Stderr)
	c.logWriter = c.logGate

	if c.logFlags.flagCombineLogs {
		c.logWriter = os.Stdout
	}

	if c.flagRecovery {
		return c.runRecoveryMode()
	}

	// Automatically enable dev mode if other dev flags are provided.
	if c.flagDevHA || c.flagDevLeasedKV || c.flagDevThreeNode || c.flagDevAutoSeal || c.flagDevKVV1 || c.flagDevTLS {
		c.flagDev = true
	}

	// Validation
	if !c.flagDev {
		switch {
		case len(c.flagConfigs) == 0:
			c.UI.Error("Must specify at least one config path using -config")
			return 1
		case c.flagDevRootTokenID != "":
			c.UI.Warn(wrapAtLength(
				"You cannot specify a custom root token ID outside of \"dev\" mode. " +
					"Your request has been ignored."))
			c.flagDevRootTokenID = ""
		}
	}

	// Load the configuration
	var config *server.Config
	var certDir string
	if c.flagDev {
		df, cfg, dir, err := configureDevTLS(c)
		if df != nil {
			defer df()
		}

		if err != nil {
			c.UI.Error(err.Error())
			return 1
		}

		config = cfg
		certDir = dir

		if c.flagDevListenAddr != "" {
			config.Listeners[0].Address = c.flagDevListenAddr
		}
		config.Listeners[0].Telemetry.UnauthenticatedMetricsAccess = true
	}

	parsedConfig, configErrors, err := c.parseConfig()
	if err != nil {
		c.UI.Error(err.Error())
		return 1
	}
	if config == nil {
		config = parsedConfig
	} else {
		config = config.Merge(parsedConfig)
	}

	// Ensure at least one config was found.
	if config == nil {
		c.UI.Output(wrapAtLength(
			"No configuration files found. Please provide configurations with the " +
				"-config flag. If you are supplying the path to a directory, please " +
				"ensure the directory contains files with the .hcl or .json " +
				"extension."))
		return 1
	}

	f.applyLogConfigOverrides(config.SharedConfig)

	// Set 'trace' log level for the following 'dev' clusters
	if c.flagDevThreeNode {
		config.LogLevel = "trace"
	}

	l, err := c.configureLogging(config)
	if err != nil {
		c.UI.Error(err.Error())
		return 1
	}
	c.logger = l
	c.allLoggers = append(c.allLoggers, l)

	// flush logs right away if the server is started with the disable-gated-logs flag
	if c.logFlags.flagDisableGatedLogs {
		c.flushLog()
	}

	// reporting Errors found in the config
	for _, cErr := range configErrors {
		c.logger.Warn(cErr.String())
	}

	// Ensure logging is flushed if initialization fails
	defer c.flushLog()

	// create GRPC logger
	namedGRPCLogFaker := c.logger.Named("grpclogfaker")
	c.allLoggers = append(c.allLoggers, namedGRPCLogFaker)
	grpclog.SetLogger(&grpclogFaker{
		logger: namedGRPCLogFaker,
		log:    api.ReadBaoVariable("BAO_GRPC_LOGGING") != "",
	})

	if memProfilerEnabled {
		c.startMemProfiler()
	}

	if config.DefaultMaxRequestDuration != 0 {
		vault.DefaultMaxRequestDuration = config.DefaultMaxRequestDuration
	}

	logProxyEnvironmentVariables(c.logger)

	inmemMetrics, metricSink, prometheusEnabled, err := configutil.SetupTelemetry(&configutil.SetupTelemetryOpts{
		Config:      config.Telemetry,
		Ui:          c.UI,
		ServiceName: "vault",
		DisplayName: "Vault",
		UserAgent:   useragent.String(),
		ClusterName: config.ClusterName,
	})
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error initializing telemetry: %s", err))
		return 1
	}
	metricsHelper := metricsutil.NewMetricsHelper(inmemMetrics, prometheusEnabled)

	// Initialize the storage backend
	var backend physical.Backend
	if !c.flagDev || config.Storage != nil {
		backend, err = c.setupStorage(config)
		if err != nil {
			c.UI.Error(err.Error())
			return 1
		}
		// Prevent server startup if migration is active
		// TODO: Use OpenTelemetry to integrate this into Diagnose
		if c.storageMigrationActive(backend) {
			return 1
		}
	}

	// Initialize the Service Discovery, if there is one
	var configSR sr.ServiceRegistration
	if config.ServiceRegistration != nil {
		configSR, err = beginServiceRegistration(c, config)
		if err != nil {
			c.UI.Output(err.Error())
			return 1
		}
	}

	infoKeys := make([]string, 0, 10)
	info := make(map[string]string)
	info["log level"] = config.LogLevel
	infoKeys = append(infoKeys, "log level")

	// returns a slice of env vars formatted as "key=value"
	envVars := os.Environ()
	var envVarKeys []string
	for _, v := range envVars {
		splitEnvVars := strings.Split(v, "=")
		envVarKeys = append(envVarKeys, splitEnvVars[0])
	}

	sort.Strings(envVarKeys)

	key := "environment variables"
	info[key] = strings.Join(envVarKeys, ", ")
	infoKeys = append(infoKeys, key)

	barrierSeal, barrierWrapper, unwrapSeal, seals, sealConfigError, err := setSeal(c, config, &infoKeys, info)
	// Check error here
	if err != nil {
		c.UI.Error(err.Error())
		return 1
	}

	for _, seal := range seals {
		// There is always one nil seal. We need to skip it so we don't start an empty Finalize-Seal-Shamir
		// section.
		if seal == nil {
			continue
		}
		seal := seal // capture range variable
		// Ensure that the seal finalizer is called, even if using verify-only
		defer func(seal *vault.Seal) {
			err = (*seal).Finalize(context.Background())
			if err != nil {
				c.UI.Error(fmt.Sprintf("Error finalizing seals: %v", err))
			}
		}(&seal)
	}

	if barrierSeal == nil {
		c.UI.Error("Could not create barrier seal! Most likely proper Seal configuration information was not set, but no error was generated.")
		return 1
	}

	// prepare a secure random reader for core
	secureRandomReader, err := configutil.CreateSecureRandomReaderFunc(config.SharedConfig, barrierWrapper)
	if err != nil {
		c.UI.Error(err.Error())
		return 1
	}

	coreConfig := createCoreConfig(c, config, backend, configSR, barrierSeal, unwrapSeal, metricsHelper, metricSink, secureRandomReader)
	if c.flagDevThreeNode {
		return c.enableThreeNodeDevCluster(&coreConfig, info, infoKeys, c.flagDevListenAddr, api.ReadBaoVariable("BAO_DEV_TEMP_DIR"))
	}

	if allowPendingRemoval := api.ReadBaoVariable(consts.EnvVaultAllowPendingRemovalMounts); allowPendingRemoval != "" {
		var err error
		coreConfig.PendingRemovalMountsAllowed, err = strconv.ParseBool(allowPendingRemoval)
		if err != nil {
			c.UI.Warn(wrapAtLength("WARNING! failed to parse " +
				consts.EnvVaultAllowPendingRemovalMounts + " env var: " +
				"defaulting to false."))
		}
	}

	// Initialize the separate HA storage backend, if it exists
	disableClustering, err := initHaBackend(c, config, &coreConfig, backend)
	if err != nil {
		c.UI.Output(err.Error())
		return 1
	}

	// Determine the redirect address from environment variables
	err = determineRedirectAddr(c, &coreConfig, config)
	if err != nil {
		c.UI.Output(err.Error())
	}

	// After the redirect bits are sorted out, if no cluster address was
	// explicitly given, derive one from the redirect addr
	err = findClusterAddress(c, &coreConfig, config, disableClustering)
	if err != nil {
		c.UI.Output(err.Error())
		return 1
	}

	// Override the UI enabling config by the environment variable
	if enableUI := api.ReadBaoVariable("BAO_UI"); enableUI != "" {
		var err error
		coreConfig.EnableUI, err = strconv.ParseBool(enableUI)
		if err != nil {
			c.UI.Output("Error parsing the environment variable BAO_UI")
			return 1
		}
	}

	// If ServiceRegistration is configured, then the backend must support HA
	isBackendHA := coreConfig.HAPhysical != nil && coreConfig.HAPhysical.HAEnabled()
	if !c.flagDev && (coreConfig.GetServiceRegistration() != nil) && !isBackendHA {
		c.UI.Output("service_registration is configured, but storage does not support HA")
		return 1
	}

	if !c.flagDev {
		inMemStorageTypes := []string{
			"inmem", "inmem_ha",
		}

		if strutil.StrListContains(inMemStorageTypes, coreConfig.StorageType) {
			c.UI.Warn("")
			c.UI.Warn(wrapAtLength(fmt.Sprintf("WARNING: storage configured to use %q which should NOT be used in production", coreConfig.StorageType)))
			c.UI.Warn("")
		}
	}

	// Initialize the core
	core, newCoreError := vault.NewCore(&coreConfig)
	if newCoreError != nil {
		if vault.IsFatalError(newCoreError) {
			c.UI.Error(fmt.Sprintf("Error initializing core: %s", newCoreError))
			return 1
		}
		c.UI.Warn(wrapAtLength(
			"WARNING! A non-fatal error occurred during initialization. Please " +
				"check the logs for more information."))
		c.UI.Warn("")

	}

	// Copy the reload funcs pointers back
	c.reloadFuncs = coreConfig.ReloadFuncs
	c.reloadFuncsLock = coreConfig.ReloadFuncsLock

	// Compile server information for output later
	info["storage"] = config.Storage.Type
	infoKeys = append(infoKeys, "storage")

	if coreConfig.ClusterAddr != "" {
		info["cluster address"] = coreConfig.ClusterAddr
		infoKeys = append(infoKeys, "cluster address")
	}
	if coreConfig.RedirectAddr != "" {
		info["api address"] = coreConfig.RedirectAddr
		infoKeys = append(infoKeys, "api address")
	}

	if config.HAStorage != nil {
		info["HA storage"] = config.HAStorage.Type
		infoKeys = append(infoKeys, "HA storage")
	} else {
		// If the storage supports HA, then note it
		if coreConfig.HAPhysical != nil {
			if coreConfig.HAPhysical.HAEnabled() {
				info["storage"] += " (HA available)"
			} else {
				info["storage"] += " (HA disabled)"
			}
		}
	}

	status, lns, clusterAddrs, errMsg := c.InitListeners(c.logger, config, disableClustering, &infoKeys, &info)

	if status != 0 {
		c.UI.Output("Error parsing listener configuration.")
		c.UI.Error(errMsg.Error())
		return 1
	}

	// Make sure we close all listeners from this point on
	listenerCloseFunc := func() {
		for _, ln := range lns {
			ln.Listener.Close()
		}
	}

	defer c.cleanupGuard.Do(listenerCloseFunc)

	infoKeys = append(infoKeys, "version")
	verInfo := version.GetVersion()
	info["version"] = verInfo.FullVersionNumber(false)
	if verInfo.Revision != "" {
		info["version sha"] = strings.Trim(verInfo.Revision, "'")
		infoKeys = append(infoKeys, "version sha")
	}

	infoKeys = append(infoKeys, "cgo")
	info["cgo"] = "disabled"
	if version.CgoEnabled {
		info["cgo"] = "enabled"
	}

	infoKeys = append(infoKeys, "recovery mode")
	info["recovery mode"] = "false"

	infoKeys = append(infoKeys, "go version")
	info["go version"] = runtime.Version()

	infoKeys = append(infoKeys, "administrative namespace")
	info["administrative namespace"] = config.AdministrativeNamespacePath

	sort.Strings(infoKeys)
	c.UI.Output("==> OpenBao server configuration:\n")

	titleCaser := cases.Title(language.English, cases.NoLower)

	for _, k := range infoKeys {
		c.UI.Output(fmt.Sprintf(
			"%24s: %s",
			titleCaser.String(k),
			info[k]))
	}

	c.UI.Output("")

	// Tests might not want to start a vault server and just want to verify
	// the configuration.
	if c.flagTestVerifyOnly {
		return 0
	}

	// This needs to happen before we first unseal, so before we trigger dev
	// mode if it's set
	core.SetClusterListenerAddrs(clusterAddrs)
	core.SetClusterHandler(vaulthttp.Handler.Handler(&vault.HandlerProperties{
		Core: core,
	}))

	// Attempt unsealing in a background goroutine. This is needed for when a
	// OpenBao cluster with multiple servers is configured with auto-unseal but is
	// uninitialized. Once one server initializes the storage backend, this
	// goroutine will pick up the unseal keys and unseal this instance.
	if !core.IsInSealMigrationMode(true) {
		go runUnseal(c, core, context.Background())
	}

	// When the underlying storage is raft, kick off retry join if it was specified
	// in the configuration
	// TODO: Should we also support retry_join for ha_storage?
	if config.Storage.Type == storageTypeRaft {
		if err := core.InitiateRetryJoin(context.Background()); err != nil {
			c.UI.Error(fmt.Sprintf("Failed to initiate raft retry join, %q", err.Error()))
			return 1
		}
	}

	// Perform initialization of HTTP server after the verifyOnly check.

	// Instantiate the wait group
	c.WaitGroup = &sync.WaitGroup{}

	// If service discovery is available, run service discovery
	err = runListeners(c, &coreConfig, config, configSR)
	if err != nil {
		c.UI.Error(err.Error())
		return 1
	}

	// If we're in Dev mode, then initialize the core
	clusterJson := &testcluster.ClusterJson{}
	err = initDevCore(c, &coreConfig, config, core, certDir, clusterJson)
	if err != nil {
		c.UI.Error(err.Error())
		return 1
	}

	// Else if we're in production mode, initialize the core as well.
	err = c.Initialize(core, config)
	if err != nil {
		c.UI.Error(err.Error())
		return 1
	}

	// Initialize the HTTP servers
	err = startHttpServers(c, core, config, lns)
	if err != nil {
		c.UI.Error(err.Error())
		return 1
	}

	if c.flagTestServerConfig {
		return 0
	}

	if sealConfigError != nil {
		init, err := core.InitializedLocally(context.Background())
		if err != nil {
			c.UI.Error(fmt.Sprintf("Error checking if core is initialized: %v", err))
			return 1
		}
		if init {
			c.UI.Error("Vault is initialized but no Seal key could be loaded")
			return 1
		}
	}

	// Output the header that the server has started
	if !c.logFlags.flagCombineLogs {
		c.UI.Output("==> OpenBao server started! Log data will stream in below:\n")
	}

	// Inform any tests that the server is ready
	select {
	case c.startedCh <- struct{}{}:
	default:
	}

	// Release the log gate.
	c.flushLog()

	// Write out the PID to the file now that server has successfully started
	if err := c.storePidFile(config.PidFile); err != nil {
		c.UI.Error(fmt.Sprintf("Error storing PID: %s", err))
		return 1
	}

	// Notify systemd that the server is ready (if applicable)
	c.notifySystemd(systemd.SdNotifyReady)

	if c.flagDev {
		protocol := "http://"
		if c.flagDevTLS {
			protocol = "https://"
		}
		clusterJson.Nodes = []testcluster.ClusterNode{
			{
				APIAddress: protocol + config.Listeners[0].Address,
			},
		}
		if c.flagDevTLS {
			clusterJson.CACertPath = fmt.Sprintf("%s/%s", certDir, server.VaultDevCAFilename)
		}

		if c.flagDevClusterJson != "" && !c.flagDevThreeNode {
			b, err := jsonutil.EncodeJSON(clusterJson)
			if err != nil {
				c.UI.Error(fmt.Sprintf("Error encoding cluster.json: %s", err))
				return 1
			}
			err = os.WriteFile(c.flagDevClusterJson, b, 0o600)
			if err != nil {
				c.UI.Error(fmt.Sprintf("Error writing cluster.json %q: %s", c.flagDevClusterJson, err))
				return 1
			}
		}
	}

	defer func() {
		if err := c.removePidFile(config.PidFile); err != nil {
			c.UI.Error(fmt.Sprintf("Error deleting the PID file: %s", err))
		}
	}()

	var coreShutdownDoneCh <-chan struct{}
	if c.flagExitOnCoreShutdown {
		coreShutdownDoneCh = core.ShutdownDone()
	}

	// Wait for shutdown
	shutdownTriggered := false
	retCode := 0

	for !shutdownTriggered {
		select {
		case <-coreShutdownDoneCh:
			c.UI.Output("==> OpenBao core was shut down")
			retCode = 1
			shutdownTriggered = true
		case <-c.ShutdownCh:
			c.UI.Output("==> OpenBao shutdown triggered")
			shutdownTriggered = true
		case <-c.SighupCh:
			c.UI.Output("==> OpenBao reload triggered")

			// Notify systemd that the server is reloading config
			c.notifySystemd(systemd.SdNotifyReloading)

			// Check for new log level
			var config *server.Config
			var configErrors []configutil.ConfigError
			for _, path := range c.flagConfigs {
				current, err := server.LoadConfig(path, c.flagConfigs)
				if err != nil {
					c.logger.Error("could not reload config", "path", path, "error", err)
					goto RUNRELOADFUNCS
				}

				if current != nil {
					configErrors = append(configErrors, current.Validate(path)...)

					if config == nil {
						config = current
					} else {
						config = config.Merge(current)
					}
				} else {
					c.UI.Warn(fmt.Sprintf("WARNING: ignoring duplicate configuration found in directory: %v", path))
				}
			}

			// Ensure at least one config was found.
			if config == nil {
				c.logger.Error("no config found at reload time")
				goto RUNRELOADFUNCS
			}

			// reporting Errors found in the config
			for _, cErr := range configErrors {
				c.logger.Warn(cErr.String())
			}

			core.SetConfig(config)

			// reloading custom response headers to make sure we have
			// the most up to date headers after reloading the config file
			if err = core.ReloadCustomResponseHeaders(); err != nil {
				c.logger.Error(err.Error())
			}

			// Setting log request with the new value in the config after reload
			core.ReloadLogRequestsLevel()

			// Reload log level for loggers
			if config.LogLevel != "" {
				level, err := loghelper.ParseLogLevel(config.LogLevel)
				if err != nil {
					c.logger.Error("unknown log level found on reload", "level", config.LogLevel)
					goto RUNRELOADFUNCS
				}
				core.SetLogLevel(level)
			}

		RUNRELOADFUNCS:
			if err := c.Reload(c.reloadFuncsLock, c.reloadFuncs, c.flagConfigs, core); err != nil {
				c.UI.Error(fmt.Sprintf("Error(s) were encountered during reload: %s", err))
			}

			// Notify systemd that the server has completed reloading config
			c.notifySystemd(systemd.SdNotifyReady)

		case <-c.SigUSR2Ch:
			logWriter := c.logger.StandardWriter(&hclog.StandardLoggerOptions{})
			pprof.Lookup("goroutine").WriteTo(logWriter, 2)

			if api.ReadBaoVariable("BAO_STACKTRACE_WRITE_TO_FILE") != "" {
				c.logger.Info("Writing stacktrace to file")

				dir := ""
				path := api.ReadBaoVariable("BAO_STACKTRACE_FILE_PATH")
				if path != "" {
					if _, err := os.Stat(path); err != nil {
						c.logger.Error("Checking stacktrace path failed", "error", err)
						continue
					}
					dir = path
				} else {
					dir, err = os.MkdirTemp("", "vault-stacktrace")
					if err != nil {
						c.logger.Error("Could not create temporary directory for stacktrace", "error", err)
						continue
					}
				}

				f, err := os.CreateTemp(dir, "stacktrace")
				if err != nil {
					c.logger.Error("Could not create stacktrace file", "error", err)
					continue
				}

				if err := pprof.Lookup("goroutine").WriteTo(f, 2); err != nil {
					f.Close()
					c.logger.Error("Could not write stacktrace to file", "error", err)
					continue
				}

				c.logger.Info(fmt.Sprintf("Wrote stacktrace to: %s", f.Name()))
				f.Close()
			}

			// We can only get pprof outputs via the API but sometimes OpenBao can get
			// into a state where it cannot process requests so we can get pprof outputs
			// via SIGUSR2.
			if api.ReadBaoVariable("BAO_PPROF_WRITE_TO_FILE") != "" {
				dir := ""
				path := api.ReadBaoVariable("BAO_PPROF_FILE_PATH")
				if path != "" {
					if _, err := os.Stat(path); err != nil {
						c.logger.Error("Checking pprof path failed", "error", err)
						continue
					}
					dir = path
				} else {
					dir, err = os.MkdirTemp("", "vault-pprof")
					if err != nil {
						c.logger.Error("Could not create temporary directory for pprof", "error", err)
						continue
					}
				}

				dumps := []string{"goroutine", "heap", "allocs", "threadcreate"}
				for _, dump := range dumps {
					pFile, err := os.Create(filepath.Join(dir, dump))
					if err != nil {
						c.logger.Error("error creating pprof file", "name", dump, "error", err)
						break
					}

					err = pprof.Lookup(dump).WriteTo(pFile, 0)
					if err != nil {
						c.logger.Error("error generating pprof data", "name", dump, "error", err)
						pFile.Close()
						break
					}
					pFile.Close()
				}

				c.logger.Info(fmt.Sprintf("Wrote pprof files to: %s", dir))
			}
		}
	}
	// Notify systemd that the server is shutting down
	c.notifySystemd(systemd.SdNotifyStopping)

	// Stop the listeners so that we don't process further client requests.
	c.cleanupGuard.Do(listenerCloseFunc)

	// Finalize will wait until after OpenBao is sealed, which means the
	// request forwarding listeners will also be closed (and also
	// waited for).
	if err := core.Shutdown(); err != nil {
		c.UI.Error(fmt.Sprintf("Error with core shutdown: %s", err))
	}

	// Wait for dependent goroutines to complete
	c.WaitGroup.Wait()
	return retCode
}

// configureLogging takes the configuration and attempts to parse config values into 'log' friendly configuration values
// If all goes to plan, a logger is created and setup.
func (c *ServerCommand) configureLogging(config *server.Config) (hclog.InterceptLogger, error) {
	// Parse all the log related config
	logLevel, err := loghelper.ParseLogLevel(config.LogLevel)
	if err != nil {
		return nil, err
	}

	logFormat, err := loghelper.ParseLogFormat(config.LogFormat)
	if err != nil {
		return nil, err
	}

	logRotateDuration, err := parseutil.ParseDurationSecond(config.LogRotateDuration)
	if err != nil {
		return nil, err
	}

	logCfg, err := loghelper.NewLogConfig("vault")
	if err != nil {
		return nil, err
	}
	logCfg.LogLevel = logLevel
	logCfg.LogFormat = logFormat
	logCfg.LogFilePath = config.LogFile
	logCfg.LogRotateDuration = logRotateDuration
	logCfg.LogRotateBytes = config.LogRotateBytes
	logCfg.LogRotateMaxFiles = config.LogRotateMaxFiles

	return loghelper.Setup(logCfg, c.logWriter)
}

func (c *ServerCommand) notifySystemd(status string) {
	sent, err := systemd.SdNotify(false, status)
	if err != nil {
		c.logger.Error("error notifying systemd", "error", err)
	} else {
		if sent {
			c.logger.Debug("sent systemd notification", "notification", status)
		} else {
			c.logger.Debug("would have sent systemd notification (systemd not present)", "notification", status)
		}
	}
}

func (c *ServerCommand) waitForLeader(core *vault.Core) (bool, error) {
	// By definition of self-initialization, we can't have added any follower
	// nodes yet because key material was just created prior to this. We can
	// only ever become the leader unless we were somehow started as a
	// non-voting node. Assume we'll become leader.
	//
	// When HA mode is not enabled, core.Leader() returns ErrHANotEnabled,
	// which means we'll vacuously become the leader so we can skip the
	// subsequent loop to wait for leadership.
	isLeader, _, _, err := core.Leader()
	if err != nil && err != vault.ErrHANotEnabled {
		return false, fmt.Errorf("failed to check active status: %w", err)
	}
	if err == nil {
		// Raft is slower than dev mode. We allow up to 35 seconds for
		// a leader to be elected before failing with a stack trace.
		leaderCount := 35
		for !isLeader {
			if leaderCount == 0 {
				// We did not become leader in the specified time window;
				// give up and assume another node won. Unlike dev mode,
				// we don't really care about the stack trace here since
				// it is feasible another node beat us to leadership
				// acquisition.
				return false, nil
			}

			time.Sleep(1 * time.Second)
			isLeader, _, _, err = core.Leader()
			if err != nil {
				return false, fmt.Errorf("failed to check active status: %w", err)
			}
			leaderCount--
		}
	}

	return true, nil
}

// Initialize performs declarative self-initialization of a production-mode
// OpenBao core. This will exit early if there is no configuration for this
// or if the core is already initialized.
func (c *ServerCommand) Initialize(core *vault.Core, config *server.Config) error {
	if len(config.Initialization) == 0 {
		return nil
	}

	if !core.SealAccess().RecoveryKeySupported() {
		return errors.New("self-initialization requires auto-unseal as there is no way to persist the Shamir's keys")
	}

	ctx := namespace.RootContext(context.Background())

	// Fast path skipping self-initialization if already initialized.
	inited, err := core.Initialized(ctx)
	if err != nil {
		return fmt.Errorf("unable to check core initialization status: %w", err)
	}
	if inited {
		// We refuse to rerun self-initialization as it is a highly privileged
		// way of sidestepping authentication. At first startup there is no
		// other authentication information but on subsequent startups
		// presumably the admin has created an alternative mechanism we should
		// defer to.
		return nil
	}

	// Initialize the cluster without recovery keys; a root token can be
	// used to create recovery keys in the future.
	var recoveryConfig *vault.SealConfig
	barrierConfig := &vault.SealConfig{}
	recoveryConfig = &vault.SealConfig{}

	init, err := core.Initialize(ctx, &vault.InitParams{
		BarrierConfig:  barrierConfig,
		RecoveryConfig: recoveryConfig,
	})
	if err != nil {
		core.Logger().Error("failed to initialize", "error", err)
		if errors.Is(err, vault.ErrParallelInit) || errors.Is(err, vault.ErrAlreadyInit) {
			return nil
		}

		return fmt.Errorf("self-initialization failed: %w", err)
	}

	// Wait for leadership; if we don't get the leadership status, it means
	// that someone has brought up more than one node at a time and we've
	// lost the race. This is bad and they should reset storage and ensure
	// only one active node.
	isLeader, err := c.waitForLeader(core)
	if err != nil {
		return fmt.Errorf("failed to wait for leadership: %w", err)
	}
	if !isLeader {
		return fmt.Errorf("initializing node did not win leadership election: ensure only one active, voting node during initialization")
	}

	// Now perform the component requests of self-initialization.
	return c.doSelfInit(ctx, core, config, init.RootToken)
}

// doSelfInit is the internal helper that uses the profile system with this
// freshly initialized core to perform the component requests of the
// self-initialization process.
func (c *ServerCommand) doSelfInit(ctx context.Context, core *vault.Core, config *server.Config, rootToken string) error {
	c.UI.Warn("Beginning post-unseal configuration")
	p, err := profiles.NewEngine(
		// Set up the profile system with relevant parameter sources:
		// - Environment variables
		// - Files
		// - Other requests & responses
		profiles.WithEnvSource(),
		profiles.WithFileSource(),
		profiles.WithRequestSource(),
		profiles.WithResponseSource(),

		// Because we're initializing, we have a default (root) token to use.
		profiles.WithDefaultToken(rootToken),

		// Our outer block is called initialize, to contain multiple requests.
		profiles.WithOuterBlockName("initialize"),

		// The actual profile we're executing is contained in our
		// server configuration.
		profiles.WithProfile(config.Initialization),

		// Hook the profile system directly up to our core request handler.
		profiles.WithRequestHandler(func(ctx context.Context, req *logical.Request) (*logical.Response, error) {
			return core.HandleRequest(ctx, req)
		}),

		// Create a named logger for this, to allow operators to debug
		// initialization issues.
		profiles.WithLogger(c.logger.Named("self-init")),
	)
	if err != nil {
		return err
	}

	return p.Evaluate(ctx)
}

func (c *ServerCommand) enableDev(core *vault.Core, coreConfig *vault.CoreConfig) (*vault.InitResult, error) {
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	var recoveryConfig *vault.SealConfig
	barrierConfig := &vault.SealConfig{
		SecretShares:    1,
		SecretThreshold: 1,
	}

	if core.SealAccess().RecoveryKeySupported() {
		recoveryConfig = &vault.SealConfig{
			SecretShares:    1,
			SecretThreshold: 1,
		}
	}

	barrierConfig.StoredShares = 1

	// Initialize it with a basic single key
	init, err := core.Initialize(ctx, &vault.InitParams{
		BarrierConfig:  barrierConfig,
		RecoveryConfig: recoveryConfig,
	})
	if err != nil {
		return nil, err
	}

	// Handle unseal with stored keys
	if core.SealAccess().StoredKeysSupported() == vaultseal.StoredKeysSupportedGeneric {
		err := core.UnsealWithStoredKeys(ctx)
		if err != nil {
			return nil, err
		}
	} else {
		// Copy the key so that it can be zeroed
		key := make([]byte, len(init.SecretShares[0]))
		copy(key, init.SecretShares[0])

		// Unseal the core
		unsealed, err := core.Unseal(key)
		if err != nil {
			return nil, err
		}
		if !unsealed {
			return nil, errors.New("failed to unseal Vault for dev mode")
		}
	}

	isLeader, _, _, err := core.Leader()
	if err != nil && err != vault.ErrHANotEnabled {
		return nil, fmt.Errorf("failed to check active status: %w", err)
	}
	if err == nil {
		leaderCount := 5
		for !isLeader {
			if leaderCount == 0 {
				buf := make([]byte, 1<<16)
				runtime.Stack(buf, true)
				return nil, fmt.Errorf("failed to get active status after five seconds; call stack is\n%s", buf)
			}
			time.Sleep(1 * time.Second)
			isLeader, _, _, err = core.Leader()
			if err != nil {
				return nil, fmt.Errorf("failed to check active status: %w", err)
			}
			leaderCount--
		}
	}

	// Generate a dev root token if one is provided in the flag
	if coreConfig.DevToken != "" {
		req := &logical.Request{
			ID:          "dev-gen-root",
			Operation:   logical.UpdateOperation,
			ClientToken: init.RootToken,
			Path:        "auth/token/create",
			Data: map[string]interface{}{
				"id":                coreConfig.DevToken,
				"policies":          []string{"root"},
				"no_parent":         true,
				"no_default_policy": true,
			},
		}
		resp, err := core.HandleRequest(ctx, req)
		if err != nil {
			return nil, fmt.Errorf("failed to create root token with ID %q: %w", coreConfig.DevToken, err)
		}
		if resp == nil {
			return nil, fmt.Errorf("nil response when creating root token with ID %q", coreConfig.DevToken)
		}
		if resp.Auth == nil {
			return nil, fmt.Errorf("nil auth when creating root token with ID %q", coreConfig.DevToken)
		}

		init.RootToken = resp.Auth.ClientToken

		req.ID = "dev-revoke-init-root"
		req.Path = "auth/token/revoke-self"
		req.Data = nil
		_, err = core.HandleRequest(ctx, req)
		if err != nil {
			return nil, fmt.Errorf("failed to revoke initial root token: %w", err)
		}
	}

	// Set the token
	if !c.flagDevNoStoreToken {
		tokenHelper, err := c.TokenHelper("dev-server")
		if err != nil {
			return nil, err
		}
		if err := tokenHelper.Store(init.RootToken); err != nil {
			return nil, err
		}
	}

	kvVer := "2"
	if c.flagDevKVV1 || c.flagDevLeasedKV {
		kvVer = "1"
	}
	req := &logical.Request{
		Operation:   logical.UpdateOperation,
		ClientToken: init.RootToken,
		Path:        "sys/mounts/secret",
		Data: map[string]interface{}{
			"type":        "kv",
			"path":        "secret/",
			"description": "key/value secret storage",
			"options": map[string]string{
				"version": kvVer,
			},
		},
	}
	resp, err := core.HandleRequest(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("error creating default K/V store: %w", err)
	}
	if resp.IsError() {
		return nil, fmt.Errorf("failed to create default K/V store: %w", resp.Error())
	}

	return init, nil
}

func (c *ServerCommand) enableThreeNodeDevCluster(base *vault.CoreConfig, info map[string]string, infoKeys []string, devListenAddress, tempDir string) int {
	conf, opts := teststorage.ClusterSetup(base, &vault.TestClusterOptions{
		HandlerFunc:       vaulthttp.Handler,
		BaseListenAddress: c.flagDevListenAddr,
		Logger:            c.logger,
		TempDir:           tempDir,
		DefaultHandlerProperties: vault.HandlerProperties{
			ListenerConfig: &configutil.Listener{
				Profiling: configutil.ListenerProfiling{
					UnauthenticatedPProfAccess: true,
				},
				Telemetry: configutil.ListenerTelemetry{
					UnauthenticatedMetricsAccess: true,
				},
			},
		},
	}, nil)
	testCluster := vault.NewTestCluster(&testing.RuntimeT{}, conf, opts)
	defer c.cleanupGuard.Do(testCluster.Cleanup)

	info["cluster parameters path"] = testCluster.TempDir
	infoKeys = append(infoKeys, "cluster parameters path")

	for i, core := range testCluster.Cores {
		info[fmt.Sprintf("node %d api address", i)] = fmt.Sprintf("https://%s", core.Listeners[0].Address.String())
		infoKeys = append(infoKeys, fmt.Sprintf("node %d api address", i))
	}

	infoKeys = append(infoKeys, "version")
	verInfo := version.GetVersion()
	info["version"] = verInfo.FullVersionNumber(false)
	if verInfo.Revision != "" {
		info["version sha"] = strings.Trim(verInfo.Revision, "'")
		infoKeys = append(infoKeys, "version sha")
	}

	infoKeys = append(infoKeys, "cgo")
	info["cgo"] = "disabled"
	if version.CgoEnabled {
		info["cgo"] = "enabled"
	}

	infoKeys = append(infoKeys, "go version")
	info["go version"] = runtime.Version()

	// Server configuration output
	padding := 24

	sort.Strings(infoKeys)
	c.UI.Output("==> OpenBao server configuration:\n")

	titleCaser := cases.Title(language.English, cases.NoLower)

	for _, k := range infoKeys {
		c.UI.Output(fmt.Sprintf(
			"%s%s: %s",
			strings.Repeat(" ", padding-len(k)),
			titleCaser.String(k),
			info[k]))
	}

	c.UI.Output("")

	for _, core := range testCluster.Cores {
		core.Server.Handler = vaulthttp.Handler.Handler(&vault.HandlerProperties{
			Core: core.Core,
		})
		core.SetClusterHandler(core.Server.Handler)
	}

	testCluster.Start()

	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	if base.DevToken != "" {
		req := &logical.Request{
			ID:          "dev-gen-root",
			Operation:   logical.UpdateOperation,
			ClientToken: testCluster.RootToken,
			Path:        "auth/token/create",
			Data: map[string]interface{}{
				"id":                base.DevToken,
				"policies":          []string{"root"},
				"no_parent":         true,
				"no_default_policy": true,
			},
		}
		resp, err := testCluster.Cores[0].HandleRequest(ctx, req)
		if err != nil {
			c.UI.Error(fmt.Sprintf("failed to create root token with ID %s: %s", base.DevToken, err))
			return 1
		}
		if resp == nil {
			c.UI.Error(fmt.Sprintf("nil response when creating root token with ID %s", base.DevToken))
			return 1
		}
		if resp.Auth == nil {
			c.UI.Error(fmt.Sprintf("nil auth when creating root token with ID %s", base.DevToken))
			return 1
		}

		testCluster.RootToken = resp.Auth.ClientToken

		req.ID = "dev-revoke-init-root"
		req.Path = "auth/token/revoke-self"
		req.Data = nil
		_, err = testCluster.Cores[0].HandleRequest(ctx, req)
		if err != nil {
			c.UI.Output(fmt.Sprintf("failed to revoke initial root token: %s", err))
			return 1
		}
	}

	// Set the token
	tokenHelper, err := c.TokenHelper("dev-server")
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error getting token helper: %s", err))
		return 1
	}
	if err := tokenHelper.Store(testCluster.RootToken); err != nil {
		c.UI.Error(fmt.Sprintf("Error storing in token helper: %s", err))
		return 1
	}

	if err := os.WriteFile(filepath.Join(testCluster.TempDir, "root_token"), []byte(testCluster.RootToken), 0o600); err != nil {
		c.UI.Error(fmt.Sprintf("Error writing token to tempfile: %s", err))
		return 1
	}

	c.UI.Output(fmt.Sprintf(
		"==> Three node dev mode is enabled\n\n" +
			"The unseal key and root token are reproduced below in case you\n" +
			"want to seal/unseal the Vault or play with authentication.\n",
	))

	for i, key := range testCluster.BarrierKeys {
		c.UI.Output(fmt.Sprintf(
			"Unseal Key %d: %s",
			i+1, base64.StdEncoding.EncodeToString(key),
		))
	}

	c.UI.Output(fmt.Sprintf(
		"\nRoot Token: %s\n", testCluster.RootToken,
	))

	c.UI.Output(fmt.Sprintf(
		"\nUseful env vars:\n"+
			"BAO_TOKEN=%s\n"+
			"BAO_ADDR=%s\n"+
			"BAO_CACERT=%s/ca_cert.pem\n",
		testCluster.RootToken,
		testCluster.Cores[0].Client.Address(),
		testCluster.TempDir,
	))

	if c.flagDevClusterJson != "" {
		clusterJson := testcluster.ClusterJson{
			Nodes:      []testcluster.ClusterNode{},
			CACertPath: filepath.Join(testCluster.TempDir, "ca_cert.pem"),
			RootToken:  testCluster.RootToken,
		}
		for _, core := range testCluster.Cores {
			clusterJson.Nodes = append(clusterJson.Nodes, testcluster.ClusterNode{
				APIAddress: core.Client.Address(),
			})
		}
		b, err := jsonutil.EncodeJSON(clusterJson)
		if err != nil {
			c.UI.Error(fmt.Sprintf("Error encoding cluster.json: %s", err))
			return 1
		}
		err = os.WriteFile(c.flagDevClusterJson, b, 0o600)
		if err != nil {
			c.UI.Error(fmt.Sprintf("Error writing cluster.json %q: %s", c.flagDevClusterJson, err))
			return 1
		}
	}

	// Output the header that the server has started
	c.UI.Output("==> OpenBao server started! Log data will stream in below:\n")

	// Inform any tests that the server is ready
	select {
	case c.startedCh <- struct{}{}:
	default:
	}

	// Release the log gate.
	c.flushLog()

	// Wait for shutdown
	shutdownTriggered := false

	for !shutdownTriggered {
		select {
		case <-c.ShutdownCh:
			c.UI.Output("==> OpenBao shutdown triggered")

			// Stop the listeners so that we don't process further client requests.
			c.cleanupGuard.Do(testCluster.Cleanup)

			// Finalize will wait until after OpenBao is sealed, which means the
			// request forwarding listeners will also be closed (and also
			// waited for).
			for _, core := range testCluster.Cores {
				if err := core.Shutdown(); err != nil {
					c.UI.Error(fmt.Sprintf("Error with core shutdown: %s", err))
				}
			}

			shutdownTriggered = true

		case <-c.SighupCh:
			c.UI.Output("==> OpenBao reload triggered")
			for _, core := range testCluster.Cores {
				if err := c.Reload(core.ReloadFuncsLock, core.ReloadFuncs, nil, core.Core); err != nil {
					c.UI.Error(fmt.Sprintf("Error(s) were encountered during reload: %s", err))
				}
			}
		}
	}

	return 0
}

// addPlugin adds any plugins to the catalog
func (c *ServerCommand) addPlugin(path, token string, core *vault.Core) error {
	// Get the sha256 of the file at the given path.
	pluginSum := func(p string) (string, error) {
		hasher := sha256.New()
		f, err := os.Open(p)
		if err != nil {
			return "", err
		}
		defer f.Close()
		if _, err := io.Copy(hasher, f); err != nil {
			return "", err
		}
		return hex.EncodeToString(hasher.Sum(nil)), nil
	}

	// Mount any test plugins. We do this explicitly before we inform tests of
	// a completely booted server intentionally.
	sha256sum, err := pluginSum(path)
	if err != nil {
		return err
	}

	// Default the name to the basename of the binary
	name := filepath.Base(path)

	// File a request against core to enable the plugin
	req := &logical.Request{
		Operation:   logical.UpdateOperation,
		ClientToken: token,
		Path:        fmt.Sprintf("sys/plugins/catalog/%s", name),
		Data: map[string]interface{}{
			"sha256":  sha256sum,
			"command": name,
		},
	}
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)
	if _, err := core.HandleRequest(ctx, req); err != nil {
		return err
	}

	return nil
}

// detectRedirect is used to attempt redirect address detection
func (c *ServerCommand) detectRedirect(detect physical.RedirectDetect,
	config *server.Config,
) (string, error) {
	// Get the hostname
	host, err := detect.DetectHostAddr()
	if err != nil {
		return "", err
	}

	// set [] for ipv6 addresses
	if strings.Contains(host, ":") && !strings.Contains(host, "]") {
		host = "[" + host + "]"
	}

	// Default the port and scheme
	scheme := "https"
	port := 8200

	// Attempt to detect overrides
	for _, list := range config.Listeners {
		// Only attempt TCP
		if list.Type != "tcp" {
			continue
		}

		// Check if TLS is disabled
		if list.TLSDisable {
			scheme = "http"
		}

		// Check for address override
		addr := list.Address
		if addr == "" {
			addr = "127.0.0.1:8200"
		}

		// Check for localhost
		hostStr, portStr, err := net.SplitHostPort(addr)
		if err != nil {
			continue
		}
		if hostStr == "127.0.0.1" {
			host = hostStr
		}

		// Check for custom port
		listPort, err := strconv.Atoi(portStr)
		if err != nil {
			continue
		}
		port = listPort
	}

	// Build a URL
	url := &url.URL{
		Scheme: scheme,
		Host:   fmt.Sprintf("%s:%d", host, port),
	}

	// Return the URL string
	return url.String(), nil
}

func (c *ServerCommand) Reload(lock *sync.RWMutex, reloadFuncs *map[string][]reloadutil.ReloadFunc, configPath []string, core *vault.Core) error {
	lock.RLock()
	defer lock.RUnlock()

	var reloadErrors *multierror.Error

	for k, relFuncs := range *reloadFuncs {
		switch {
		case strings.HasPrefix(k, "listener|"):
			for _, relFunc := range relFuncs {
				if relFunc != nil {
					if err := relFunc(); err != nil {
						reloadErrors = multierror.Append(reloadErrors, fmt.Errorf("error encountered reloading listener: %w", err))
					}
				}
			}

		case strings.HasPrefix(k, "audit_file|"):
			for _, relFunc := range relFuncs {
				if relFunc != nil {
					if err := relFunc(); err != nil {
						reloadErrors = multierror.Append(reloadErrors, fmt.Errorf("error encountered reloading file audit device at path %q: %w", strings.TrimPrefix(k, "audit_file|"), err))
					}
				}
			}
		}
	}

	// Set Introspection Endpoint to enabled with new value in the config after reload
	core.ReloadIntrospectionEndpointEnabled()

	// Send a message that we reloaded. This prevents "guessing" sleep times
	// in tests.
	select {
	case c.reloadedCh <- struct{}{}:
	default:
	}

	return reloadErrors.ErrorOrNil()
}

// storePidFile is used to write out our PID to a file if necessary
func (c *ServerCommand) storePidFile(pidPath string) error {
	// Quit fast if no pidfile
	if pidPath == "" {
		return nil
	}

	// Open the PID file
	pidFile, err := os.OpenFile(pidPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("could not open pid file: %w", err)
	}
	defer pidFile.Close()

	// Write out the PID
	pid := os.Getpid()
	_, err = pidFile.WriteString(fmt.Sprintf("%d", pid))
	if err != nil {
		return fmt.Errorf("could not write to pid file: %w", err)
	}
	return nil
}

// removePidFile is used to cleanup the PID file if necessary
func (c *ServerCommand) removePidFile(pidPath string) error {
	if pidPath == "" {
		return nil
	}
	return os.Remove(pidPath)
}

// storageMigrationActive checks and warns against in-progress storage migrations.
// This function will block until storage is available.
func (c *ServerCommand) storageMigrationActive(backend physical.Backend) bool {
	first := true

	for {
		migrationStatus, err := CheckStorageMigration(backend)
		if err == nil {
			if migrationStatus != nil {
				startTime := migrationStatus.Start.Format(time.RFC3339)
				c.UI.Error(wrapAtLength(fmt.Sprintf("ERROR! Storage migration in progress (started: %s). "+
					"Server startup is prevented until the migration completes. Use 'bao operator migrate -reset' "+
					"to force clear the migration lock.", startTime)))
				return true
			}
			return false
		}
		if first {
			first = false
			c.UI.Warn("\nWARNING! Unable to read storage migration status.")

			// unexpected state, so stop buffering log messages
			c.flushLog()
		}
		c.logger.Warn("storage migration check error", "error", err.Error())

		timer := time.NewTimer(2 * time.Second)
		select {
		case <-timer.C:
		case <-c.ShutdownCh:
			timer.Stop()
			return true
		}
	}
}

type StorageMigrationStatus struct {
	Start time.Time `json:"start"`
}

func CheckStorageMigration(b physical.Backend) (*StorageMigrationStatus, error) {
	entry, err := b.Get(context.Background(), storageMigrationLock)
	if err != nil {
		return nil, err
	}

	if entry == nil {
		return nil, nil
	}

	var status StorageMigrationStatus
	if err := jsonutil.DecodeJSON(entry.Value, &status); err != nil {
		return nil, err
	}

	return &status, nil
}

// setSeal return barrierSeal, barrierWrapper, unwrapSeal, and all the created seals from the configs so we can close them in Run
// The two errors are the sealConfigError and the regular error
func setSeal(c *ServerCommand, config *server.Config, infoKeys *[]string, info map[string]string) (vault.Seal, wrapping.Wrapper, vault.Seal, []vault.Seal, error, error) {
	var barrierSeal vault.Seal
	var unwrapSeal vault.Seal

	var sealConfigError error
	var wrapper wrapping.Wrapper
	var barrierWrapper wrapping.Wrapper
	if c.flagDevAutoSeal {
		var err error
		access, _ := vaultseal.NewTestSeal(nil)
		barrierSeal, err = vault.NewAutoSeal(access)
		if err != nil {
			return nil, nil, nil, nil, nil, err
		}
		return barrierSeal, nil, nil, nil, nil, nil
	}

	// Handle the case where no seal is provided
	switch len(config.Seals) {
	case 0:
		config.Seals = append(config.Seals, &configutil.KMS{Type: wrapping.WrapperTypeShamir.String()})
	case 1:
		// If there's only one seal and it's disabled assume they want to
		// migrate to a shamir seal and simply didn't provide it
		if config.Seals[0].Disabled {
			config.Seals = append(config.Seals, &configutil.KMS{Type: wrapping.WrapperTypeShamir.String()})
		}
	}
	var createdSeals []vault.Seal = make([]vault.Seal, len(config.Seals))
	for _, configSeal := range config.Seals {
		sealType := wrapping.WrapperTypeShamir.String()
		if !configSeal.Disabled && api.ReadBaoVariable("BAO_SEAL_TYPE") != "" {
			sealType = api.ReadBaoVariable("BAO_SEAL_TYPE")
			configSeal.Type = sealType
		} else {
			sealType = configSeal.Type
		}

		var seal vault.Seal
		sealLogger := c.logger.ResetNamed(fmt.Sprintf("seal.%s", sealType))
		c.allLoggers = append(c.allLoggers, sealLogger)
		defaultSeal := vault.NewDefaultSeal(vaultseal.NewAccess(aeadwrapper.NewShamirWrapper()))
		var sealInfoKeys []string
		sealInfoMap := map[string]string{}
		wrapper, sealConfigError = configutil.ConfigureWrapper(configSeal, &sealInfoKeys, &sealInfoMap, sealLogger)
		if sealConfigError != nil {
			if !errwrap.ContainsType(sealConfigError, new(logical.KeyNotFoundError)) {
				return barrierSeal, barrierWrapper, unwrapSeal, createdSeals, sealConfigError, fmt.Errorf(
					"Error parsing Seal configuration: %s", sealConfigError)
			}
		}
		if wrapper == nil {
			seal = defaultSeal
		} else {
			var err error
			seal, err = vault.NewAutoSeal(vaultseal.NewAccess(wrapper))
			if err != nil {
				return nil, nil, nil, nil, nil, err
			}
		}
		infoPrefix := ""
		if configSeal.Disabled {
			unwrapSeal = seal
			infoPrefix = "Old "
		} else {
			barrierSeal = seal
			barrierWrapper = wrapper
		}
		for _, k := range sealInfoKeys {
			*infoKeys = append(*infoKeys, infoPrefix+k)
			info[infoPrefix+k] = sealInfoMap[k]
		}
		createdSeals = append(createdSeals, seal)
	}
	return barrierSeal, barrierWrapper, unwrapSeal, createdSeals, sealConfigError, nil
}

func initHaBackend(c *ServerCommand, config *server.Config, coreConfig *vault.CoreConfig, backend physical.Backend) (bool, error) {
	// Initialize the separate HA storage backend, if it exists
	var ok bool
	if config.HAStorage != nil {
		if config.Storage.Type == storageTypeRaft && config.HAStorage.Type == storageTypeRaft {
			return false, errors.New("Raft cannot be set both as 'storage' and 'ha_storage'. Setting 'storage' to 'raft' will automatically set it up for HA operations as well")
		}

		if config.Storage.Type == storageTypeRaft {
			return false, errors.New("HA storage cannot be declared when Raft is the storage type")
		}

		factory, exists := c.PhysicalBackends[config.HAStorage.Type]
		if !exists {
			return false, fmt.Errorf("Unknown HA storage type %s", config.HAStorage.Type)
		}

		namedHALogger := c.logger.Named("ha." + config.HAStorage.Type)
		c.allLoggers = append(c.allLoggers, namedHALogger)
		habackend, err := factory(config.HAStorage.Config, namedHALogger)
		if err != nil {
			return false, fmt.Errorf("Error initializing HA storage of type %s: %s", config.HAStorage.Type, err)
		}

		if coreConfig.HAPhysical, ok = habackend.(physical.HABackend); !ok {
			return false, errors.New("Specified HA storage does not support HA")
		}

		if !coreConfig.HAPhysical.HAEnabled() {
			return false, errors.New("Specified HA storage has HA support disabled; please consult documentation")
		}

		coreConfig.RedirectAddr = config.HAStorage.RedirectAddr
		disableClustering := config.HAStorage.DisableClustering

		if config.HAStorage.Type == storageTypeRaft && disableClustering {
			return disableClustering, errors.New("Disable clustering cannot be set to true when Raft is the HA storage type")
		}

		if !disableClustering {
			coreConfig.ClusterAddr = config.HAStorage.ClusterAddr
		}
	} else {
		if coreConfig.HAPhysical, ok = backend.(physical.HABackend); ok {
			coreConfig.RedirectAddr = config.Storage.RedirectAddr
			disableClustering := config.Storage.DisableClustering

			if (config.Storage.Type == storageTypeRaft) && disableClustering {
				return disableClustering, errors.New("Disable clustering cannot be set to true when Raft is the storage type")
			}

			if !disableClustering {
				coreConfig.ClusterAddr = config.Storage.ClusterAddr
			}
		}
	}
	return config.DisableClustering, nil
}

func determineRedirectAddr(c *ServerCommand, coreConfig *vault.CoreConfig, config *server.Config) error {
	var retErr error
	if envRA := api.ReadBaoVariable("BAO_API_ADDR"); envRA != "" {
		coreConfig.RedirectAddr = envRA
	} else if envRA := api.ReadBaoVariable("BAO_REDIRECT_ADDR"); envRA != "" {
		coreConfig.RedirectAddr = envRA
	} else if envAA := api.ReadBaoVariable("BAO_ADVERTISE_ADDR"); envAA != "" {
		coreConfig.RedirectAddr = envAA
	}

	// Attempt to detect the redirect address, if possible
	if coreConfig.RedirectAddr == "" {
		c.logger.Warn("no `api_addr` value specified in config or in BAO_API_ADDR; falling back to detection if possible, but this value should be manually set")
	}

	var ok bool
	var detect physical.RedirectDetect
	if coreConfig.HAPhysical != nil && coreConfig.HAPhysical.HAEnabled() {
		detect, ok = coreConfig.HAPhysical.(physical.RedirectDetect)
	} else {
		detect, ok = coreConfig.Physical.(physical.RedirectDetect)
	}
	if ok && coreConfig.RedirectAddr == "" {
		redirect, err := c.detectRedirect(detect, config)
		// the following errors did not cause Run to return, so I'm not returning these
		// as errors.
		if err != nil {
			retErr = fmt.Errorf("Error detecting api address: %s", err)
		} else if redirect == "" {
			retErr = errors.New("Failed to detect api address")
		} else {
			coreConfig.RedirectAddr = redirect
		}
	}
	if coreConfig.RedirectAddr == "" && c.flagDev {
		protocol := "http"
		if c.flagDevTLS {
			protocol = "https"
		}
		coreConfig.RedirectAddr = fmt.Sprintf("%s://%s", protocol, config.Listeners[0].Address)
	}
	return retErr
}

func findClusterAddress(c *ServerCommand, coreConfig *vault.CoreConfig, config *server.Config, disableClustering bool) error {
	if disableClustering {
		coreConfig.ClusterAddr = ""
	} else if envCA := api.ReadBaoVariable("BAO_CLUSTER_ADDR"); envCA != "" {
		coreConfig.ClusterAddr = envCA
	} else {
		var addrToUse string
		switch {
		case coreConfig.ClusterAddr == "" && coreConfig.RedirectAddr != "":
			addrToUse = coreConfig.RedirectAddr
		case c.flagDev:
			addrToUse = fmt.Sprintf("http://%s", config.Listeners[0].Address)
		default:
			goto CLUSTER_SYNTHESIS_COMPLETE
		}
		u, err := url.ParseRequestURI(addrToUse)
		if err != nil {
			return fmt.Errorf("Error parsing synthesized cluster address %s: %v", addrToUse, err)
		}
		host, port, err := net.SplitHostPort(u.Host)
		if err != nil {
			// This sucks, as it's a const in the function but not exported in the package
			if strings.Contains(err.Error(), "missing port in address") {
				host = u.Host
				port = "443"
			} else {
				return fmt.Errorf("Error parsing api address: %v", err)
			}
		}
		nPort, err := strconv.Atoi(port)
		if err != nil {
			return fmt.Errorf("Error parsing synthesized address; failed to convert %q to a numeric: %v", port, err)
		}
		u.Host = net.JoinHostPort(host, strconv.Itoa(nPort+1))
		// Will always be TLS-secured
		u.Scheme = "https"
		coreConfig.ClusterAddr = u.String()
	}

CLUSTER_SYNTHESIS_COMPLETE:

	if coreConfig.RedirectAddr == coreConfig.ClusterAddr && len(coreConfig.RedirectAddr) != 0 {
		return fmt.Errorf("Address %q used for both API and cluster addresses", coreConfig.RedirectAddr)
	}

	if coreConfig.ClusterAddr != "" {
		rendered, err := configutil.ParseSingleIPTemplate(coreConfig.ClusterAddr)
		if err != nil {
			return fmt.Errorf("Error parsing cluster address %s: %v", coreConfig.ClusterAddr, err)
		}
		coreConfig.ClusterAddr = rendered
		// Force https as we'll always be TLS-secured
		u, err := url.ParseRequestURI(coreConfig.ClusterAddr)
		if err != nil {
			return fmt.Errorf("Error parsing cluster address %s: %v", coreConfig.ClusterAddr, err)
		}
		u.Scheme = "https"
		coreConfig.ClusterAddr = u.String()
	}
	return nil
}

func runUnseal(c *ServerCommand, core *vault.Core, ctx context.Context) {
	for {
		err := core.UnsealWithStoredKeys(ctx)
		if err == nil {
			return
		}

		if vault.IsFatalError(err) {
			c.logger.Error("error unsealing core", "error", err)
			return
		}
		c.logger.Warn("failed to unseal core", "error", err)

		timer := time.NewTimer(5 * time.Second)
		select {
		case <-c.ShutdownCh:
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func createCoreConfig(c *ServerCommand, config *server.Config, backend physical.Backend, configSR sr.ServiceRegistration, barrierSeal, unwrapSeal vault.Seal,
	metricsHelper *metricsutil.MetricsHelper, metricSink *metricsutil.ClusterMetricSink, secureRandomReader io.Reader,
) vault.CoreConfig {
	coreConfig := &vault.CoreConfig{
		RawConfig:                      config,
		Physical:                       backend,
		RedirectAddr:                   config.Storage.RedirectAddr,
		StorageType:                    config.Storage.Type,
		HAPhysical:                     nil,
		ServiceRegistration:            configSR,
		Seal:                           barrierSeal,
		UnwrapSeal:                     unwrapSeal,
		AuditBackends:                  c.AuditBackends,
		CredentialBackends:             c.CredentialBackends,
		LogicalBackends:                c.LogicalBackends,
		LogLevel:                       config.LogLevel,
		Logger:                         c.logger,
		DetectDeadlocks:                config.DetectDeadlocks,
		ImpreciseLeaseRoleTracking:     config.ImpreciseLeaseRoleTracking,
		DisableSentinelTrace:           config.DisableSentinelTrace,
		DisableCache:                   config.DisableCache,
		MaxLeaseTTL:                    config.MaxLeaseTTL,
		DefaultLeaseTTL:                config.DefaultLeaseTTL,
		ClusterName:                    config.ClusterName,
		CacheSize:                      config.CacheSize,
		PluginDirectory:                config.PluginDirectory,
		PluginFileUid:                  config.PluginFileUid,
		PluginFilePermissions:          config.PluginFilePermissions,
		EnableUI:                       config.EnableUI,
		EnableRaw:                      config.EnableRawEndpoint,
		EnableIntrospection:            config.EnableIntrospectionEndpoint,
		DisableSealWrap:                config.DisableSealWrap,
		DisablePerformanceStandby:      config.DisablePerformanceStandby,
		DisableIndexing:                config.DisableIndexing,
		AllLoggers:                     c.allLoggers,
		BuiltinRegistry:                builtinplugins.Registry,
		DisableKeyEncodingChecks:       config.DisablePrintableCheck,
		MetricsHelper:                  metricsHelper,
		MetricSink:                     metricSink,
		SecureRandomReader:             secureRandomReader,
		EnableResponseHeaderHostname:   config.EnableResponseHeaderHostname,
		EnableResponseHeaderRaftNodeID: config.EnableResponseHeaderRaftNodeID,
		AdministrativeNamespacePath:    config.AdministrativeNamespacePath,
		UnsafeCrossNamespaceIdentity:   config.UnsafeCrossNamespaceIdentity,
	}

	if config.DisableSSCTokens != nil {
		coreConfig.DisableSSCTokens = *config.DisableSSCTokens
	} else {
		coreConfig.DisableSSCTokens = true
	}

	if c.flagDev {
		coreConfig.EnableRaw = true
		coreConfig.EnableIntrospection = true
		coreConfig.DevToken = c.flagDevRootTokenID
		if c.flagDevLeasedKV {
			coreConfig.LogicalBackends["kv"] = vault.LeasedPassthroughBackendFactory
		}
		if c.flagDevPluginDir != "" {
			coreConfig.PluginDirectory = c.flagDevPluginDir
		}
		if c.flagDevLatency > 0 {
			injectLatency := time.Duration(c.flagDevLatency) * time.Millisecond
			coreConfig.Physical = physical.NewLatencyInjector(backend, injectLatency, c.flagDevLatencyJitter, c.logger)
		}
	}
	return *coreConfig
}

func runListeners(c *ServerCommand, coreConfig *vault.CoreConfig, config *server.Config, configSR sr.ServiceRegistration) error {
	if sd := coreConfig.GetServiceRegistration(); sd != nil {
		if err := configSR.Run(c.ShutdownCh, c.WaitGroup, coreConfig.RedirectAddr); err != nil {
			return fmt.Errorf("Error running service_registration of type %s: %s", config.ServiceRegistration.Type, err)
		}
	}
	return nil
}

func initDevCore(c *ServerCommand, coreConfig *vault.CoreConfig, config *server.Config, core *vault.Core, certDir string, clusterJSON *testcluster.ClusterJson) error {
	if c.flagDev && !c.flagDevSkipInit {

		init, err := c.enableDev(core, coreConfig)
		if err != nil {
			return fmt.Errorf("Error initializing Dev mode: %s", err)
		}

		if clusterJSON != nil {
			clusterJSON.RootToken = init.RootToken
		}

		var plugins, pluginsNotLoaded []string
		if c.flagDevPluginDir != "" && c.flagDevPluginInit {

			f, err := os.Open(c.flagDevPluginDir)
			if err != nil {
				return fmt.Errorf("Error reading plugin dir: %s", err)
			}

			list, err := f.Readdirnames(0)
			f.Close()
			if err != nil {
				return fmt.Errorf("Error listing plugins: %s", err)
			}

			for _, name := range list {
				path := filepath.Join(f.Name(), name)
				if err := c.addPlugin(path, init.RootToken, core); err != nil {
					if !errwrap.Contains(err, vault.ErrPluginBadType.Error()) {
						return fmt.Errorf("Error enabling plugin %s: %s", name, err)
					}
					pluginsNotLoaded = append(pluginsNotLoaded, name)
					continue
				}
				plugins = append(plugins, name)
			}

			sort.Strings(plugins)
		}

		var qw *quiescenceSink
		var qwo sync.Once
		qw = &quiescenceSink{
			t: time.AfterFunc(100*time.Millisecond, func() {
				qwo.Do(func() {
					c.logger.DeregisterSink(qw)

					// Print the big dev mode warning!
					c.UI.Warn(wrapAtLength(
						"WARNING! dev mode is enabled! In this mode, OpenBao runs entirely " +
							"in-memory and starts unsealed with a single unseal key. The root " +
							"token is already authenticated to the CLI, so you can immediately " +
							"begin using OpenBao."))
					c.UI.Warn("")
					c.UI.Warn("You may need to set the following environment variables:")
					c.UI.Warn("")

					protocol := "http://"
					if c.flagDevTLS {
						protocol = "https://"
					}

					endpointURL := protocol + config.Listeners[0].Address
					if runtime.GOOS == "windows" {
						c.UI.Warn("PowerShell:")
						c.UI.Warn(fmt.Sprintf("    $env:BAO_ADDR=\"%s\"", endpointURL))
						c.UI.Warn("cmd.exe:")
						c.UI.Warn(fmt.Sprintf("    set BAO_ADDR=%s", endpointURL))
					} else {
						c.UI.Warn(fmt.Sprintf("    $ export BAO_ADDR='%s'", endpointURL))
					}

					if c.flagDevTLS {
						if runtime.GOOS == "windows" {
							c.UI.Warn("PowerShell:")
							c.UI.Warn(fmt.Sprintf("    $env:BAO_CACERT=\"%s/vault-ca.pem\"", certDir))
							c.UI.Warn("cmd.exe:")
							c.UI.Warn(fmt.Sprintf("    set BAO_CACERT=%s/vault-ca.pem", certDir))
						} else {
							c.UI.Warn(fmt.Sprintf("    $ export BAO_CACERT='%s/vault-ca.pem'", certDir))
						}
						c.UI.Warn("")
					}

					// Unseal key is not returned if stored shares is supported
					if len(init.SecretShares) > 0 {
						c.UI.Warn("")
						c.UI.Warn(wrapAtLength(
							"The unseal key and root token are displayed below in case you want " +
								"to seal/unseal the Vault or re-authenticate."))
						c.UI.Warn("")
						c.UI.Warn(fmt.Sprintf("Unseal Key: %s", base64.StdEncoding.EncodeToString(init.SecretShares[0])))
					}

					if len(init.RecoveryShares) > 0 {
						c.UI.Warn("")
						c.UI.Warn(wrapAtLength(
							"The recovery key and root token are displayed below in case you want " +
								"to seal/unseal the Vault or re-authenticate."))
						c.UI.Warn("")
						c.UI.Warn(fmt.Sprintf("Recovery Key: %s", base64.StdEncoding.EncodeToString(init.RecoveryShares[0])))
					}

					c.UI.Warn(fmt.Sprintf("Root Token: %s", init.RootToken))

					if len(plugins) > 0 {
						c.UI.Warn("")
						c.UI.Warn(wrapAtLength(
							"The following dev plugins are registered in the catalog:"))
						for _, p := range plugins {
							c.UI.Warn(fmt.Sprintf("    - %s", p))
						}
					}

					if len(pluginsNotLoaded) > 0 {
						c.UI.Warn("")
						c.UI.Warn(wrapAtLength(
							"The following dev plugins FAILED to be registered in the catalog due to unknown type:"))
						for _, p := range pluginsNotLoaded {
							c.UI.Warn(fmt.Sprintf("    - %s", p))
						}
					}

					c.UI.Warn("")
					c.UI.Warn(wrapAtLength(
						"Development mode should NOT be used in production installations!"))
					c.UI.Warn("")
				})
			}),
		}
		c.logger.RegisterSink(qw)
	}
	return nil
}

// Initialize the HTTP servers
func startHttpServers(c *ServerCommand, core *vault.Core, config *server.Config, lns []listenerutil.Listener) error {
	for _, ln := range lns {
		if ln.Config == nil {
			return errors.New("Found nil listener config after parsing")
		}

		if err := config2.IsValidListener(ln.Config); err != nil {
			return err
		}

		handler := vaulthttp.Handler.Handler(&vault.HandlerProperties{
			Core:                  core,
			ListenerConfig:        ln.Config,
			AllListeners:          lns,
			DisablePrintableCheck: config.DisablePrintableCheck,
			RecoveryMode:          c.flagRecovery,
		})

		if len(ln.Config.XForwardedForAuthorizedAddrs) > 0 {
			handler = vaulthttp.WrapForwardedForHandler(handler, ln.Config)
		}

		// server defaults
		server := &http.Server{
			Handler:           handler,
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       30 * time.Second,
			IdleTimeout:       5 * time.Minute,
			ErrorLog:          c.logger.StandardLogger(nil),
		}

		// override server defaults with config values for read/write/idle timeouts if configured
		if ln.Config.HTTPReadHeaderTimeout > 0 {
			server.ReadHeaderTimeout = ln.Config.HTTPReadHeaderTimeout
		}
		if ln.Config.HTTPReadTimeout > 0 {
			server.ReadTimeout = ln.Config.HTTPReadTimeout
		}
		if ln.Config.HTTPWriteTimeout > 0 {
			server.WriteTimeout = ln.Config.HTTPWriteTimeout
		}
		if ln.Config.HTTPIdleTimeout > 0 {
			server.IdleTimeout = ln.Config.HTTPIdleTimeout
		}

		// server config tests can exit now
		if c.flagTestServerConfig {
			continue
		}

		go server.Serve(ln.Listener)
	}
	return nil
}

func SetStorageMigration(b physical.Backend, active bool) error {
	if !active {
		return b.Delete(context.Background(), storageMigrationLock)
	}

	status := StorageMigrationStatus{
		Start: time.Now(),
	}

	enc, err := jsonutil.EncodeJSON(status)
	if err != nil {
		return err
	}

	entry := &physical.Entry{
		Key:   storageMigrationLock,
		Value: enc,
	}

	return b.Put(context.Background(), entry)
}

type grpclogFaker struct {
	logger hclog.Logger
	log    bool
}

func (g *grpclogFaker) Fatal(args ...interface{}) {
	g.logger.Error(fmt.Sprint(args...))
	os.Exit(1)
}

func (g *grpclogFaker) Fatalf(format string, args ...interface{}) {
	g.logger.Error(fmt.Sprintf(format, args...))
	os.Exit(1)
}

func (g *grpclogFaker) Fatalln(args ...interface{}) {
	g.logger.Error(fmt.Sprintln(args...))
	os.Exit(1)
}

func (g *grpclogFaker) Print(args ...interface{}) {
	if g.log && g.logger.IsDebug() {
		g.logger.Debug(fmt.Sprint(args...))
	}
}

func (g *grpclogFaker) Printf(format string, args ...interface{}) {
	if g.log && g.logger.IsDebug() {
		g.logger.Debug(fmt.Sprintf(format, args...))
	}
}

func (g *grpclogFaker) Println(args ...interface{}) {
	if g.log && g.logger.IsDebug() {
		g.logger.Debug(fmt.Sprintln(args...))
	}
}
