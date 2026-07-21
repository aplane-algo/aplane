// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Command apbounded-admin manages externally held Falcon contract-admin keys.
package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/aplane-algo/aplane/internal/apboundedadminapp"
	boundedauthorization "github.com/aplane-algo/aplane/internal/boundedadmin/authorization"
	"github.com/aplane-algo/aplane/internal/boundedadmin/helpersign"
	boundedprotocol "github.com/aplane-algo/aplane/internal/boundedadmin/protocol"
	apcrypto "github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/witness/artifact"
	"golang.org/x/term"
)

const errorSchema = "aplane.bounded-admin-error.v1"

type application struct {
	ctx            context.Context
	stdin          io.Reader
	stdout         io.Writer
	stderr         io.Writer
	readPassphrase func(string) ([]byte, error)
	confirm        func(string) (bool, error)
	now            func() time.Time
	runOnline      func(context.Context, apboundedadminapp.Options, io.Writer) (*apboundedadminapp.Result, error)
	runPrepare     func(context.Context, apboundedadminapp.Options, io.Writer) (*apboundedadminapp.Prepared, error)
	runComplete    func(context.Context, apboundedadminapp.CompleteOptions, boundedprotocol.Request, boundedprotocol.Response) (*apboundedadminapp.Result, error)
}

type generateResult struct {
	Schema        string                   `json:"schema"`
	ArtifactPath  string                   `json:"artifact_path"`
	ReferencePath string                   `json:"reference_path"`
	Reference     artifact.PublicReference `json:"reference"`
}

type verifyResult struct {
	Schema   string `json:"schema"`
	Verified bool   `json:"verified"`
	artifact.PublicReference
}

type protocolError struct {
	Schema  string `json:"schema"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

type usageError struct{ err error }

func (e *usageError) Error() string { return e.err.Error() }
func (e *usageError) Unwrap() error { return e.err }

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	app := application{
		ctx:            ctx,
		stdin:          os.Stdin,
		stdout:         os.Stdout,
		stderr:         os.Stderr,
		readPassphrase: readControllingTerminal,
		confirm:        confirmControllingTerminal,
		now:            time.Now,
		runOnline:      apboundedadminapp.Run,
		runPrepare:     apboundedadminapp.RunPrepare,
		runComplete:    apboundedadminapp.RunComplete,
	}
	os.Exit(app.run(os.Args[1:]))
}

func (app application) run(args []string) int {
	if len(args) == 0 {
		app.usage()
		return 2
	}
	var err error
	switch args[0] {
	case "generate":
		err = app.generate(args[1:])
	case "inspect":
		err = app.inspect(args[1:])
	case "verify":
		err = app.verify(args[1:])
	case "sign":
		err = app.sign(args[1:])
	case "prepare-rekey":
		err = app.prepare(args[1:], false)
	case "prepare-unrekey":
		err = app.prepare(args[1:], true)
	case "complete":
		err = app.complete(args[1:])
	case "rekey":
		err = app.rekey(args[1:], false)
	case "unrekey":
		err = app.rekey(args[1:], true)
	case "help", "-h", "--help":
		app.usage()
		return 0
	default:
		_, _ = fmt.Fprintf(app.stderr, "unknown command %q\n", args[0])
		app.usage()
		return 2
	}
	if err == nil {
		return 0
	}
	app.writeError(err)
	var commandUsageError *usageError
	if errors.As(err, &commandUsageError) {
		return 2
	}
	return 1
}

func (app application) rekey(args []string, unrekey bool) error {
	command := "rekey"
	operation := apboundedadminapp.OperationRekey
	if unrekey {
		command = "unrekey"
		operation = apboundedadminapp.OperationUnrekey
	}
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(app.stderr)
	var clientData string
	var network string
	var keyPath string
	var fee uint64
	var nowait bool
	flags.StringVar(&clientData, "client-data", "", "client data directory")
	flags.StringVar(&clientData, "d", "", "client data directory")
	flags.StringVar(&network, "network", "", "network context override")
	flags.StringVar(&network, "n", "", "network context override")
	flags.StringVar(&keyPath, "key", "", "external bounded-admin key")
	flags.Uint64Var(&fee, "fee", 0, "flat transaction fee in microAlgos")
	flags.BoolVar(&nowait, "nowait", false, "submit without waiting for confirmation")
	if err := flags.Parse(args); err != nil {
		return &usageError{err: err}
	}
	if keyPath == "" {
		return &usageError{err: fmt.Errorf("%s requires --key <artifact.wit>", command)}
	}
	positional := flags.Args()
	options := apboundedadminapp.Options{
		Operation:  operation,
		ClientData: clientData,
		Network:    network,
		Artifact:   keyPath,
		Fee:        fee,
		Wait:       !nowait,
	}
	flags.Visit(func(flag *flag.Flag) {
		if flag.Name == "fee" {
			options.UseFlatFee = true
		}
	})
	if unrekey {
		if len(positional) != 1 {
			return &usageError{err: fmt.Errorf("usage: apbounded-admin unrekey --key <key.wit> [options] <account>")}
		}
		options.Account = positional[0]
	} else {
		if len(positional) != 3 || !strings.EqualFold(positional[1], "to") {
			return &usageError{err: fmt.Errorf("usage: apbounded-admin rekey --key <key.wit> [options] <account> to <target>")}
		}
		options.Account = positional[0]
		options.Target = positional[2]
	}
	runner := app.runOnline
	if runner == nil {
		runner = apboundedadminapp.Run
	}
	ctx := app.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	result, err := runner(ctx, options, app.stderr)
	if err != nil {
		return err
	}
	if result.Output != "" {
		_, _ = fmt.Fprint(app.stdout, result.Output)
		if !strings.HasSuffix(result.Output, "\n") {
			_, _ = fmt.Fprintln(app.stdout)
		}
	}
	_, _ = fmt.Fprintf(app.stdout, "Governed %s transaction submitted: %s\n", command, result.TxID)
	if result.Confirmed {
		_, _ = fmt.Fprintln(app.stdout, "Transaction confirmed")
	} else if nowait {
		_, _ = fmt.Fprintln(app.stdout, "Transaction submitted without waiting for confirmation")
	}
	if result.RefreshWarning != "" {
		_, _ = fmt.Fprintf(app.stderr, "Warning: authorization cache refresh failed: %s\n", result.RefreshWarning)
	}
	return nil
}

func (app application) generate(args []string) error {
	flags := flag.NewFlagSet("generate", flag.ContinueOnError)
	flags.SetOutput(app.stderr)
	outputDirectory := flags.String("out", "", "existing output directory")
	if err := flags.Parse(args); err != nil {
		return &usageError{err: err}
	}
	if flags.NArg() != 0 {
		return &usageError{err: fmt.Errorf("generate does not accept positional arguments")}
	}
	if *outputDirectory == "" {
		return &usageError{err: fmt.Errorf("--out is required")}
	}
	if err := artifact.ValidateOutputDirectory(*outputDirectory); err != nil {
		return err
	}
	passphrase, err := app.readPassphrase("Bounded-admin key passphrase: ")
	if err != nil {
		return err
	}
	defer apcrypto.ZeroBytes(passphrase)
	if len(passphrase) == 0 {
		return fmt.Errorf("passphrase cannot be empty")
	}
	confirmation, err := app.readPassphrase("Confirm bounded-admin key passphrase: ")
	if err != nil {
		return err
	}
	defer apcrypto.ZeroBytes(confirmation)
	if subtle.ConstantTimeCompare(passphrase, confirmation) != 1 {
		return fmt.Errorf("passphrases do not match")
	}

	files, err := artifact.GenerateFiles(*outputDirectory, passphrase, app.now())
	if err != nil {
		return err
	}
	return writeJSON(app.stdout, generateResult{
		Schema:        "aplane.bounded-admin-generate-result.v1",
		ArtifactPath:  files.BundlePath,
		ReferencePath: files.ReferencePath,
		Reference:     files.Reference,
	})
}

func (app application) inspect(args []string) error {
	path, err := exactlyOnePath("inspect", args)
	if err != nil {
		return err
	}
	data, err := artifact.LoadFile(path)
	if err != nil {
		return err
	}
	reference, err := artifact.Inspect(data)
	if err != nil {
		return err
	}
	return writeJSON(app.stdout, reference)
}

func (app application) verify(args []string) error {
	path, err := exactlyOnePath("verify", args)
	if err != nil {
		return err
	}
	data, err := artifact.LoadFile(path)
	if err != nil {
		return err
	}
	if _, err := artifact.Inspect(data); err != nil {
		return err
	}
	passphrase, err := app.readPassphrase("Bounded-admin key passphrase: ")
	if err != nil {
		return err
	}
	defer apcrypto.ZeroBytes(passphrase)
	reference, err := artifact.Verify(data, passphrase)
	if err != nil {
		return err
	}
	return writeJSON(app.stdout, verifyResult{
		Schema:          "aplane.bounded-admin-verify-result.v1",
		Verified:        true,
		PublicReference: reference,
	})
}

func (app application) sign(args []string) error {
	flags := flag.NewFlagSet("sign", flag.ContinueOnError)
	flags.SetOutput(app.stderr)
	keyPath := flags.String("key", "", "external bounded-admin key")
	requestPath := flags.String("request", "-", "ceremony request path, or - for stdin")
	outputPath := flags.String("out", "-", "ceremony response path, or - for stdout")
	if err := flags.Parse(args); err != nil {
		return &usageError{err: err}
	}
	if flags.NArg() != 0 || *keyPath == "" {
		return &usageError{err: fmt.Errorf("sign requires --key <artifact.wit>")}
	}

	request, err := apboundedadminapp.ReadRequest(*requestPath, app.input())
	if err != nil {
		return err
	}
	validated, err := boundedauthorization.ValidateRequest(request)
	if err != nil {
		return err
	}
	bundle, err := artifact.LoadFile(*keyPath)
	if err != nil {
		return err
	}
	reference, err := artifact.Inspect(bundle)
	if err != nil {
		return err
	}
	metadata := request.Payload.Partial.Authorization
	if reference.WitnessKeyID != metadata.ContractAdminKeyID || reference.PublicKeyHex != metadata.PublicKeyHex {
		return fmt.Errorf("bounded-admin key does not match bounded authorization account")
	}
	txn := validated.Group.Entries[request.Payload.Partial.TargetIndex].Txn
	networkStatus := "verified by canonical genesis hash"
	if !validated.NetworkVerified {
		networkStatus = "custom token; not independently verified offline"
	}
	_, _ = fmt.Fprintf(app.stderr, "Network: %s (%s)\nGenesis hash: %s\nSender: %s\nCurrent authorization: %s\nRekey target: %s\nTransaction ID: %s\nFee: %d microAlgos\nValid rounds: %d-%d\nContract-admin key ID: %s\n",
		request.Payload.Network,
		networkStatus,
		request.Payload.GenesisHashHex,
		txn.Sender.String(),
		request.Payload.CurrentAuthAddress,
		txn.RekeyTo.String(),
		metadata.TransactionID,
		txn.Fee,
		txn.FirstValid,
		txn.LastValid,
		metadata.ContractAdminKeyID,
	)
	confirmed, err := app.confirm("Authorize this rekey with the contract-admin key? [y/N]: ")
	if err != nil {
		return err
	}
	if !confirmed {
		return fmt.Errorf("bounded-admin signing canceled")
	}
	passphrase, err := app.readPassphrase("Bounded-admin key passphrase: ")
	if err != nil {
		return err
	}
	defer apcrypto.ZeroBytes(passphrase)
	credential, err := artifact.Open(bundle, passphrase)
	if err != nil {
		return err
	}
	defer credential.Zero()
	response, _, err := helpersign.Sign(request, credential)
	if err != nil {
		return err
	}
	return apboundedadminapp.WriteResponse(*outputPath, response, app.stdout)
}

func (app application) prepare(args []string, unrekey bool) error {
	command := "prepare-rekey"
	operation := apboundedadminapp.OperationRekey
	if unrekey {
		command = "prepare-unrekey"
		operation = apboundedadminapp.OperationUnrekey
	}
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(app.stderr)
	var clientData, network, outputPath string
	var fee uint64
	flags.StringVar(&clientData, "client-data", "", "client data directory")
	flags.StringVar(&clientData, "d", "", "client data directory")
	flags.StringVar(&network, "network", "", "network context override")
	flags.StringVar(&network, "n", "", "network context override")
	flags.StringVar(&outputPath, "out", "", "ceremony request output")
	flags.Uint64Var(&fee, "fee", 0, "flat transaction fee in microAlgos")
	if err := flags.Parse(args); err != nil {
		return &usageError{err: err}
	}
	if outputPath == "" {
		return &usageError{err: fmt.Errorf("%s requires --out <request.apbounded-admin-request>", command)}
	}
	positional := flags.Args()
	options := apboundedadminapp.Options{Operation: operation, ClientData: clientData, Network: network, Fee: fee}
	flags.Visit(func(flag *flag.Flag) {
		if flag.Name == "fee" {
			options.UseFlatFee = true
		}
	})
	if unrekey {
		if len(positional) != 1 {
			return &usageError{err: fmt.Errorf("usage: apbounded-admin prepare-unrekey --out <request.apbounded-admin-request> [options] <account>")}
		}
		options.Account = positional[0]
	} else {
		if len(positional) != 3 || !strings.EqualFold(positional[1], "to") {
			return &usageError{err: fmt.Errorf("usage: apbounded-admin prepare-rekey --out <request.apbounded-admin-request> [options] <account> to <target>")}
		}
		options.Account, options.Target = positional[0], positional[2]
	}
	runner := app.runPrepare
	if runner == nil {
		runner = apboundedadminapp.RunPrepare
	}
	prepared, err := runner(app.context(), options, app.stderr)
	if err != nil {
		return err
	}
	if err := apboundedadminapp.WriteRequest(outputPath, prepared.Request, app.stdout); err != nil {
		return err
	}
	validated, err := boundedauthorization.ValidateRequest(prepared.Request)
	if err != nil {
		return err
	}
	txn := validated.Group.Entries[prepared.Request.Payload.Partial.TargetIndex].Txn
	_, _ = fmt.Fprintf(app.stderr, "Prepared bounded-admin rekey request for rounds %d-%d: %s\n", txn.FirstValid, txn.LastValid, outputPath)
	return nil
}

func (app application) complete(args []string) error {
	flags := flag.NewFlagSet("complete", flag.ContinueOnError)
	flags.SetOutput(app.stderr)
	var clientData, network string
	var nowait bool
	flags.StringVar(&clientData, "client-data", "", "client data directory")
	flags.StringVar(&clientData, "d", "", "client data directory")
	flags.StringVar(&network, "network", "", "network context override")
	flags.StringVar(&network, "n", "", "network context override")
	flags.BoolVar(&nowait, "nowait", false, "submit without waiting for confirmation")
	if err := flags.Parse(args); err != nil {
		return &usageError{err: err}
	}
	positional := flags.Args()
	if len(positional) != 3 || !strings.EqualFold(positional[1], "with") {
		return &usageError{err: fmt.Errorf("usage: apbounded-admin complete [options] <request.apbounded-admin-request> with <response.apbounded-admin-signature>")}
	}
	if positional[0] == "-" && positional[2] == "-" {
		return &usageError{err: fmt.Errorf("request and response cannot both be read from stdin; pass at least one as a file")}
	}
	request, err := apboundedadminapp.ReadRequest(positional[0], app.input())
	if err != nil {
		return err
	}
	response, err := apboundedadminapp.ReadResponse(positional[2], app.input())
	if err != nil {
		return err
	}
	runner := app.runComplete
	if runner == nil {
		runner = apboundedadminapp.RunComplete
	}
	result, err := runner(app.context(), apboundedadminapp.CompleteOptions{ClientData: clientData, Network: network, Wait: !nowait}, request, response)
	if err != nil {
		return err
	}
	return app.renderSubmission("rekey", result, nowait)
}

func (app application) context() context.Context {
	if app.ctx != nil {
		return app.ctx
	}
	return context.Background()
}

func (app application) input() io.Reader {
	if app.stdin != nil {
		return app.stdin
	}
	return os.Stdin
}

func (app application) renderSubmission(command string, result *apboundedadminapp.Result, nowait bool) error {
	if result.Output != "" {
		_, _ = fmt.Fprint(app.stdout, result.Output)
		if !strings.HasSuffix(result.Output, "\n") {
			_, _ = fmt.Fprintln(app.stdout)
		}
	}
	_, _ = fmt.Fprintf(app.stdout, "Governed %s transaction submitted: %s\n", command, result.TxID)
	if result.Confirmed {
		_, _ = fmt.Fprintln(app.stdout, "Transaction confirmed")
	} else if nowait {
		_, _ = fmt.Fprintln(app.stdout, "Transaction submitted without waiting for confirmation")
	}
	if result.RefreshWarning != "" {
		_, _ = fmt.Fprintf(app.stderr, "Warning: authorization cache refresh failed: %s\n", result.RefreshWarning)
	}
	return nil
}

func (app application) writeError(err error) {
	code := artifact.ErrorCode(err)
	if code == "" {
		code = boundedprotocol.ErrorCode(err)
	}
	if code != "" {
		_ = writeJSON(app.stderr, protocolError{
			Schema:  errorSchema,
			Code:    code,
			Message: err.Error(),
		})
		return
	}
	_, _ = fmt.Fprintf(app.stderr, "apbounded-admin: %v\n", err)
}

func (app application) usage() {
	_, _ = fmt.Fprintln(app.stderr, "Usage:")
	_, _ = fmt.Fprintln(app.stderr, "  apbounded-admin generate --out <directory>")
	_, _ = fmt.Fprintln(app.stderr, "  apbounded-admin inspect <key.wit>")
	_, _ = fmt.Fprintln(app.stderr, "  apbounded-admin verify <key.wit>")
	_, _ = fmt.Fprintln(app.stderr, "  apbounded-admin sign --key <key.wit> < request.json")
	_, _ = fmt.Fprintln(app.stderr, "  apbounded-admin prepare-rekey --out <request.apbounded-admin-request> [--client-data <dir>] [--network <network>] [--fee <microalgos>] <account> to <target>")
	_, _ = fmt.Fprintln(app.stderr, "  apbounded-admin prepare-unrekey --out <request.apbounded-admin-request> [--client-data <dir>] [--network <network>] [--fee <microalgos>] <account>")
	_, _ = fmt.Fprintln(app.stderr, "  apbounded-admin sign --key <key.wit> --request <request.apbounded-admin-request> --out <response.apbounded-admin-signature>")
	_, _ = fmt.Fprintln(app.stderr, "  apbounded-admin complete [--client-data <dir>] [--network <network>] [--nowait] <request.apbounded-admin-request> with <response.apbounded-admin-signature>")
	_, _ = fmt.Fprintln(app.stderr, "  apbounded-admin rekey --key <key.wit> [--client-data <dir>] [--network <network>] [--fee <microalgos>] [--nowait] <account> to <target>")
	_, _ = fmt.Fprintln(app.stderr, "  apbounded-admin unrekey --key <key.wit> [--client-data <dir>] [--network <network>] [--fee <microalgos>] [--nowait] <account>")
}

func readControllingTerminal(prompt string) ([]byte, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("open controlling terminal for passphrase: %w", err)
	}
	defer func() { _ = tty.Close() }()
	if _, err := fmt.Fprint(tty, prompt); err != nil {
		return nil, fmt.Errorf("write passphrase prompt: %w", err)
	}
	passphrase, err := term.ReadPassword(int(tty.Fd()))
	_, _ = fmt.Fprintln(tty)
	if err != nil {
		return nil, fmt.Errorf("read passphrase from controlling terminal: %w", err)
	}
	return passphrase, nil
}

func confirmControllingTerminal(prompt string) (bool, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return false, fmt.Errorf("open controlling terminal for confirmation: %w", err)
	}
	defer func() { _ = tty.Close() }()
	if _, err := fmt.Fprint(tty, prompt); err != nil {
		return false, fmt.Errorf("write confirmation prompt: %w", err)
	}
	var answer string
	if _, err := fmt.Fscanln(tty, &answer); err != nil && !errors.Is(err, io.EOF) {
		return false, fmt.Errorf("read confirmation: %w", err)
	}
	answer = strings.ToLower(strings.TrimSpace(answer))
	return answer == "y" || answer == "yes", nil
}

func exactlyOnePath(command string, args []string) (string, error) {
	if len(args) != 1 {
		return "", &usageError{err: fmt.Errorf("%s requires exactly one .wit path", command)}
	}
	return args[0], nil
}

func writeJSON(writer io.Writer, value any) error {
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		return fmt.Errorf("write JSON result: %w", err)
	}
	return nil
}
