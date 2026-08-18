package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/donovan-yohan/airlock/internal/config"
	"github.com/donovan-yohan/airlock/internal/keys"
	"github.com/donovan-yohan/airlock/internal/mcp"
	"github.com/donovan-yohan/airlock/internal/model"
	"github.com/donovan-yohan/airlock/internal/netguard"
	"github.com/donovan-yohan/airlock/internal/requester"
	"github.com/donovan-yohan/airlock/internal/trusted"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "airlock:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return usageError()
	}
	switch args[0] {
	case "requester":
		if len(args) < 2 || args[1] != "serve" {
			return usageError()
		}
		return serveRequester(args[2:])
	case "trusted":
		return trustedCommand(args[1:])
	case "request":
		if len(args) < 2 || args[1] != "create" {
			return usageError()
		}
		return createRequest(args[2:])
	case "keygen":
		return generateKeys(args[1:])
	case "mcp":
		return serveMCP(args[1:])
	default:
		return usageError()
	}
}

func trustedCommand(args []string) error {
	if len(args) == 0 {
		return usageError()
	}
	switch args[0] {
	case "serve":
		return serveTrusted(args[1:])
	case "requests":
		if len(args) < 2 || args[1] != "list" {
			return usageError()
		}
		return trustedRequestsList(args[2:])
	case "request":
		if len(args) < 2 {
			return usageError()
		}
		switch args[1] {
		case "show", "execute", "deny":
			return trustedRequestControl(args[1], args[2:])
		default:
			return usageError()
		}
	default:
		return usageError()
	}
}

func serveRequester(args []string) error {
	flags := flag.NewFlagSet("requester serve", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	configPath := flags.String("config", "", "requester config path")
	unsafeNonLoopback := flags.Bool("unsafe-non-loopback", false, "allow an explicitly configured non-loopback listener")
	if err := flags.Parse(args); err != nil || *configPath == "" || flags.NArg() != 0 {
		return errors.New("usage: airlock requester serve --config PATH [--unsafe-non-loopback]")
	}
	cfg, err := config.LoadRequester(*configPath)
	if err != nil {
		return err
	}
	requestTTL, catalogTTL, receiptTTL, _ := cfg.Durations()
	publicKey, err := keys.LoadPublic(cfg.TrustedPublicKeyFile)
	if err != nil {
		return err
	}
	store, err := requester.NewStore(cfg.StateDir, publicKey, requestTTL, catalogTTL, receiptTTL)
	if err != nil {
		return err
	}
	listener, err := netguard.Listen(cfg.Listen, *unsafeNonLoopback)
	if err != nil {
		return err
	}
	defer listener.Close()
	logger := log.New(os.Stderr, "airlock requester: ", log.LstdFlags|log.LUTC)
	server := hardenedServer(requester.NewServer(store).Handler(), logger)
	logger.Printf("listening on %s", listener.Addr())
	return serveUntilSignal(server, listener, nil, nil)
}

func serveTrusted(args []string) error {
	flags := flag.NewFlagSet("trusted serve", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	configPath := flags.String("config", "", "trusted config path")
	unsafeNonLoopback := flags.Bool("unsafe-non-loopback", false, "allow an explicitly configured non-loopback listener")
	dev := flags.Bool("dev", false, "use the explicit development identity header")
	if err := flags.Parse(args); err != nil || *configPath == "" || flags.NArg() != 0 {
		return errors.New("usage: airlock trusted serve --config PATH [--dev] [--unsafe-non-loopback]")
	}
	cfg, err := config.LoadTrusted(*configPath)
	if err != nil {
		return err
	}
	pollInterval, requestTTL, catalogTTL, receiptTTL, _ := cfg.Durations()
	executionTimeout, _ := cfg.ExecutionDuration()
	privateKey, err := keys.LoadPrivate(cfg.PrivateKeyFile)
	if err != nil {
		return err
	}
	store, err := trusted.NewStore(cfg.StateDir, privateKey, cfg.Capabilities, requestTTL, receiptTTL, trusted.ExecutionConfig{
		GitHubCLIPath: cfg.GitHubCLIPath, GitHubConfigDir: cfg.GitHubConfigDir, SandboxCLIPath: cfg.SandboxCLIPath, Timeout: executionTimeout,
		Profile: cfg.CatalogProfile(), ProfileConfigVersion: cfg.ProfileConfigVersion, ExecutionIdentity: cfg.ExecutionIdentityLabel,
	})
	if err != nil {
		return err
	}
	actions := trusted.NewActionService(store)
	handler, err := trusted.NewServerWithActionService(actions, cfg.AllowedLogins, *dev)
	if err != nil {
		return err
	}
	control, err := trusted.NewControlPlane(cfg.ControlSocket, actions)
	if err != nil {
		return err
	}
	defer control.Close()
	listener, err := netguard.Listen(cfg.Listen, *unsafeNonLoopback)
	if err != nil {
		return err
	}
	defer listener.Close()
	logger := log.New(os.Stderr, "airlock trusted: ", log.LstdFlags|log.LUTC)
	syncer := trusted.NewSyncer(store, privateKey, cfg.Capabilities, cfg.RequesterURL, pollInterval, catalogTTL)
	server := hardenedServer(handler.Handler(), logger)
	// A trusted web execution may run until the validated execution deadline.
	// Keep the connection writable through that bounded operation plus response.
	server.WriteTimeout = executionTimeout + 10*time.Second
	go func() {
		if err := control.Serve(); err != nil {
			logger.Printf("trusted control socket stopped: %v", err)
			_ = server.Close()
		}
	}()
	logger.Printf("listening on %s; local control socket %s; trusted direct execution enabled", listener.Addr(), cfg.ControlSocket)
	return serveUntilSignal(server, listener, func(ctx context.Context) {
		syncer.Run(ctx, logger)
	}, func(ctx context.Context) {
		if err := actions.Shutdown(ctx); err != nil {
			logger.Printf("trusted execution shutdown: %v", err)
		}
		if err := control.Shutdown(ctx); err != nil {
			logger.Printf("trusted control shutdown: %v", err)
		}
	})
}

func trustedRequestsList(args []string) error {
	flags := flag.NewFlagSet("trusted requests list", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	configPath := flags.String("config", "", "trusted config path")
	cursor := flags.String("cursor", "", "opaque next_cursor from a prior list response")
	if err := flags.Parse(args); err != nil || *configPath == "" || flags.NArg() != 0 {
		return errors.New("usage: airlock trusted requests list --config PATH [--cursor CURSOR]")
	}
	client, err := trustedControlClient(*configPath)
	if err != nil {
		return err
	}
	page, err := client.List(context.Background(), *cursor)
	if err != nil {
		return err
	}
	return printTrustedControlJSON(page)
}

func trustedRequestControl(action string, args []string) error {
	flags := flag.NewFlagSet("trusted request "+action, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	configPath := flags.String("config", "", "trusted config path")
	id := flags.String("id", "", "trusted request id")
	planDigest := flags.String("plan-digest", "", "exact resolved plan digest shown by trusted request show")
	confirmFullAuthority := flags.Bool("confirm-full-authority", false, "confirm this exact plan grants full configured GitHub authority")
	if err := flags.Parse(args); err != nil || *configPath == "" || *id == "" || flags.NArg() != 0 {
		return fmt.Errorf("usage: airlock trusted request %s --config PATH --id REQUEST_ID%s", action, func() string {
			if action == "execute" {
				return " --plan-digest SHA256 --confirm-full-authority"
			}
			return ""
		}())
	}
	client, err := trustedControlClient(*configPath)
	if err != nil {
		return err
	}
	switch action {
	case "show":
		record, err := client.Show(context.Background(), *id)
		if err != nil {
			return err
		}
		return printTrustedControlJSON(record)
	case "execute":
		if *planDigest == "" {
			return errors.New("trusted execute requires --plan-digest from a fresh trusted request show")
		}
		if !*confirmFullAuthority {
			return errors.New("trusted execute requires --confirm-full-authority after reviewing the exact plan")
		}
		result, err := client.Execute(context.Background(), *id, *planDigest, true)
		if err != nil {
			return err
		}
		if err := printTrustedControlJSON(result); err != nil {
			return err
		}
		if result.Outcome != "executed" {
			return fmt.Errorf("trusted execution is %s; inspect the persisted attempt before a fresh explicit retry", result.Outcome)
		}
		return nil
	case "deny":
		result, err := client.Deny(context.Background(), *id)
		if err != nil {
			return err
		}
		return printTrustedControlJSON(result)
	default:
		return usageError()
	}
}

func trustedControlClient(configPath string) (*trusted.ControlClient, error) {
	cfg, err := config.LoadTrusted(configPath)
	if err != nil {
		return nil, err
	}
	return trusted.NewControlClient(cfg.ControlSocket)
}

func printTrustedControlJSON(value any) error {
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(encoded))
	return nil
}

func createRequest(args []string) error {
	flags := flag.NewFlagSet("request create", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	configPath := flags.String("config", "", "requester config path")
	profile := flags.String("profile", "", "catalog command profile id")
	profileVersion := flags.String("profile-version", "", "catalog command profile version")
	var argv stringListFlag
	flags.Var(&argv, "arg", "one exact argv element; repeat in order")
	reason := flags.String("reason", "", "human-readable request reason")
	ttl := flags.Duration("ttl", 10*time.Minute, "request lifetime")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *configPath == "" || *profile == "" || *profileVersion == "" || len(argv) == 0 || *reason == "" {
		return errors.New("usage: airlock request create --config PATH --profile github.command --profile-version v1 --arg ARG [--arg ARG...] --reason TEXT [--ttl 10m]")
	}
	cfg, err := config.LoadRequester(*configPath)
	if err != nil {
		return err
	}
	host, port, err := net.SplitHostPort(cfg.Listen)
	if err != nil {
		return errors.New("requester listen address is invalid")
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() || port == "0" {
		return errors.New("request create requires a concrete loopback requester listen address")
	}
	if *ttl < time.Minute {
		return errors.New("request TTL is invalid")
	}
	input := requester.CreateInput{
		ProfileID: *profile, ProfileVersion: *profileVersion, Argv: append([]string(nil), argv...),
		Reason: *reason, TTLSeconds: int64(*ttl / time.Second),
	}
	if err := model.ValidateArgv(input.Argv); err != nil {
		return err
	}
	if err := model.ValidateCommandReason(input.Reason); err != nil {
		return err
	}
	client, err := requester.NewClient("http://" + cfg.Listen)
	if err != nil {
		return err
	}
	record, err := client.Create(context.Background(), input)
	if err != nil {
		return err
	}
	output, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(output))
	return nil
}

func serveMCP(args []string) error {
	flags := flag.NewFlagSet("mcp", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	requesterURL := flags.String("requester-url", "", "explicit local requester URL")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *requesterURL == "" {
		return errors.New("usage: airlock mcp --requester-url http://127.0.0.1:PORT")
	}
	client, err := requester.NewClient(*requesterURL)
	if err != nil {
		return errors.New("mcp requester URL is invalid")
	}
	// Construction makes no network request: MCP initialization and tool
	// registration remain available while the local requester is down.
	return mcp.New(client).Serve(os.Stdin, os.Stdout)
}

func generateKeys(args []string) error {
	flags := flag.NewFlagSet("keygen", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	privatePath := flags.String("private", "", "private key output path")
	publicPath := flags.String("public", "", "public key output path")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *privatePath == "" || *publicPath == "" {
		return errors.New("usage: airlock keygen --private PATH --public PATH")
	}
	if err := keys.GenerateFiles(*privatePath, *publicPath); err != nil {
		return err
	}
	fmt.Printf("generated Ed25519 keypair: private=%s public=%s\n", *privatePath, *publicPath)
	return nil
}

func hardenedServer(handler http.Handler, logger *log.Logger) *http.Server {
	return &http.Server{
		Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second,
		WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 32 << 10,
		ErrorLog: logger,
	}
}

func serveUntilSignal(server *http.Server, listener net.Listener, background, shutdown func(context.Context)) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if background != nil {
		go background(ctx)
	}
	var shutdownOnce sync.Once
	shutdownServer := func() {
		shutdownOnce.Do(func() {
			shutdownContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if shutdown != nil {
				shutdown(shutdownContext)
			}
			_ = server.Shutdown(shutdownContext)
		})
	}
	go func() {
		<-ctx.Done()
		shutdownServer()
	}()
	err := server.Serve(listener)
	// stop also covers an unexpected Serve return: it cancels sync and makes
	// the same ordered shutdown path cancel daemon-owned children before HTTP
	// or local-control shutdown waits can leave one orphaned.
	stop()
	shutdownServer()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func usageError() error {
	return errors.New("usage: airlock {requester serve|trusted serve|trusted requests list|trusted request show|trusted request execute --confirm-full-authority|trusted request deny|request create|keygen|mcp}")
}

type stringListFlag []string

func (values *stringListFlag) String() string { return fmt.Sprintf("%q", []string(*values)) }
func (values *stringListFlag) Set(value string) error {
	*values = append(*values, value)
	return nil
}
