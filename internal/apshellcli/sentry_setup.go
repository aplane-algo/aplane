// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/aplane-algo/aplane/internal/apshellapp"
	"github.com/aplane-algo/aplane/internal/command"
	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/sentry/enrollment"
	"github.com/aplane-algo/aplane/internal/witness"
)

const sentrySetupUsage = "sentry add [public-json] [--alias <alias>] [--endpoint <url>] [--sentry-port <port>] [--replace] [--dry-run]"

type sentrySetupCLIOptions struct {
	request apshellapp.SentrySetupRequest
	path    string
	replace bool
}

type sentrySetupProjection struct {
	Alias        string `json:"alias"`
	WitnessKeyID string `json:"witness_key_id"`
	URL          string `json:"url"`
	Created      bool   `json:"created,omitempty"`
	Updated      bool   `json:"updated,omitempty"`
	TokenIssued  bool   `json:"token_issued,omitempty"`
	Verified     bool   `json:"verified,omitempty"`
	DryRun       bool   `json:"dry_run,omitempty"`
}

func (r *REPLState) cmdSentry(args []string, _ interface{}) (command.Result, error) {
	options, err := parseSentrySetupArgs(args)
	if err != nil {
		return nil, err
	}
	if options.path == "" {
		if r.AutoConfirm || !r.hasInteractiveLineReader() {
			return nil, fmt.Errorf("interactive sentry JSON paste is unavailable; provide a file: %s", sentrySetupUsage)
		}
		options.request.Document, err = r.readSentrySetupPaste()
	} else {
		options.request.Document, err = readBoundedSentrySetupFile(options.path)
	}
	if err != nil {
		return nil, err
	}

	if options.request.Alias == "" {
		if r.AutoConfirm {
			return nil, errors.New("--alias is required in script mode")
		}
		r.println("Choose a name for this sentry connection on this client; it does not need to match the signer reference name.")
		options.request.Alias, err = r.readRequiredSetupValue("Client endpoint alias: ")
		if err != nil {
			return nil, err
		}
	}
	plan, err := r.app().PrepareSentrySetup(options.request)
	if err != nil && errors.Is(err, apshellapp.ErrSentryEndpointURLRequired) && !r.AutoConfirm {
		options.request.URL, err = r.readRequiredSetupValue("Sentry endpoint (ssh://, https://, or loopback http://): ")
		if err != nil {
			return nil, err
		}
		plan, err = r.app().PrepareSentrySetup(options.request)
	}
	if err != nil {
		return nil, err
	}

	if plan.ReplacementRequired && !plan.DryRun {
		if r.AutoConfirm {
			return nil, fmt.Errorf("endpoint alias %q has different settings; review the replacement in interactive apshell", plan.Alias)
		}
		if !options.replace {
			response, promptErr := r.readPromptResponse(fmt.Sprintf("Replace existing sentry endpoint %s? [y/N]: ", plan.Alias))
			if promptErr != nil {
				return nil, promptErr
			}
			if response != "y" && response != "yes" {
				return nil, errors.New("sentry setup cancelled")
			}
			options.replace = true
		}
	}

	if !plan.DryRun && !r.AutoConfirm {
		r.renderSentrySetupReview(plan)
		response, promptErr := r.readPromptResponse("Configure this sentry endpoint and verify it? [y/N]: ")
		if promptErr != nil {
			return nil, promptErr
		}
		if response != "y" && response != "yes" {
			return nil, errors.New("sentry setup cancelled")
		}
	}

	endpoint, err := r.app().ApplySentrySetupEndpoint(plan, options.replace)
	if err != nil {
		return nil, err
	}
	if !plan.DryRun {
		r.Config = r.app().Config
	}
	result, err := r.app().CompleteSentrySetup(r.commandContext(), plan, endpoint, buildHostKeyApproval(r), r.printSentryProvisioningWait)
	if err != nil {
		completed := "endpoint configuration retained"
		if plan.Created {
			completed = "endpoint created"
		} else if plan.Updated {
			completed = "endpoint updated"
		}
		if result != nil && result.TokenIssued {
			completed += " and access token saved"
		}
		return nil, fmt.Errorf("%s; live witness verification did not complete: %w", completed, err)
	}
	return newShellCommandResult(func(w io.Writer) error {
		return r.withOutput(w, func() { r.renderSentrySetupResult(result) })
	}, sentrySetupProjection{
		Alias: result.Alias, WitnessKeyID: result.WitnessKeyID, URL: result.URL,
		Created: result.Created, Updated: result.Updated, TokenIssued: result.TokenIssued,
		Verified: result.Verified, DryRun: result.DryRun,
	})
}

func parseSentrySetupArgs(args []string) (sentrySetupCLIOptions, error) {
	var out sentrySetupCLIOptions
	if len(args) == 0 || args[0] != "add" {
		return out, errors.New("usage: " + sentrySetupUsage)
	}
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--dry-run":
			out.request.DryRun = true
		case "--replace":
			out.replace = true
		case "--alias", "-a":
			i++
			if i >= len(args) {
				return out, errors.New("usage: " + sentrySetupUsage)
			}
			out.request.Alias = args[i]
		case "--endpoint", "--url":
			i++
			if i >= len(args) {
				return out, errors.New("usage: " + sentrySetupUsage)
			}
			out.request.URL = args[i]
		case "--sentryport", "--sentry-port":
			i++
			if i >= len(args) {
				return out, errors.New("usage: " + sentrySetupUsage)
			}
			port, err := parseSetupPort(args[i])
			if err != nil {
				return out, err
			}
			out.request.SignerPort = port
		default:
			if strings.HasPrefix(args[i], "-") || out.path != "" {
				return out, errors.New("usage: " + sentrySetupUsage)
			}
			out.path = args[i]
		}
	}
	return out, nil
}

func parseSetupPort(value string) (int, error) {
	port, err := strconv.Atoi(value)
	if err != nil || port <= 0 || port > 65535 {
		return 0, fmt.Errorf("invalid port %q", value)
	}
	return port, nil
}

func readBoundedSentrySetupFile(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("read sentry JSON %s: %w", path, err)
	}
	defer func() { _ = file.Close() }()
	data, err := io.ReadAll(io.LimitReader(file, enrollment.MaxEnvelopeBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read sentry JSON %s: %w", path, err)
	}
	if len(data) > enrollment.MaxEnvelopeBytes {
		return nil, fmt.Errorf("sentry key JSON exceeds %d bytes", enrollment.MaxEnvelopeBytes)
	}
	return data, nil
}

func (r *REPLState) readSentrySetupPaste() ([]byte, error) {
	r.println("Paste sentry key JSON. The command continues when one complete document is received; Ctrl+C cancels.")
	var document strings.Builder
	var boundary jsonDocumentBoundary
	blankLines := 0
	tooLarge := false
	for {
		line, err := r.readInteractiveLine()
		if err != nil {
			return nil, err
		}
		boundary.feed(line)
		if !tooLarge {
			if document.Len()+len(line)+1 > enrollment.MaxEnvelopeBytes {
				tooLarge = true
			} else {
				document.WriteString(line)
				document.WriteByte('\n')
			}
		}
		if boundary.complete {
			if tooLarge {
				return nil, fmt.Errorf("sentry key JSON exceeds %d bytes", enrollment.MaxEnvelopeBytes)
			}
			data := []byte(document.String())
			if _, parseErr := enrollment.ParseArtifact(data); parseErr != nil {
				return nil, fmt.Errorf("invalid sentry key JSON: %w", parseErr)
			}
			return data, nil
		}
		if strings.TrimSpace(line) == "" {
			blankLines++
		} else {
			blankLines = 0
		}
		if blankLines >= 2 {
			if tooLarge {
				return nil, fmt.Errorf("sentry key JSON exceeds %d bytes", enrollment.MaxEnvelopeBytes)
			}
			return nil, fmt.Errorf("invalid sentry key JSON")
		}
	}
}

// jsonDocumentBoundary tracks the end of the pasted top-level JSON value even
// after the bounded input buffer fills. That lets paste mode drain the rest of
// an oversized multiline document instead of returning its remaining lines to
// normal shell dispatch.
type jsonDocumentBoundary struct {
	depth    int
	started  bool
	inString bool
	escaped  bool
	complete bool
}

func (b *jsonDocumentBoundary) feed(line string) {
	if b.complete {
		return
	}
	for i := 0; i < len(line); i++ {
		ch := line[i]
		if b.inString {
			if b.escaped {
				b.escaped = false
				continue
			}
			switch ch {
			case '\\':
				b.escaped = true
			case '"':
				b.inString = false
			}
			continue
		}
		if ch == '"' {
			b.inString = true
			continue
		}
		switch ch {
		case '{', '[':
			b.started = true
			b.depth++
		case '}', ']':
			if b.started && b.depth > 0 {
				b.depth--
				if b.depth == 0 {
					b.complete = true
					return
				}
			}
		}
	}
}

func (r *REPLState) readRequiredSetupValue(prompt string) (string, error) {
	restorePrompt := r.setTemporaryPrompt(prompt)
	defer restorePrompt()
	if !r.hasInteractiveLineReader() {
		r.print("\n" + prompt)
	}
	value, err := r.readInteractiveLine()
	if err != nil {
		return "", err
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return "", errors.New("value is required")
	}
	return value, nil
}

func (r *REPLState) renderSentrySetupReview(plan apshellapp.SentrySetupPlan) {
	r.println("Sentry setup review:")
	r.printf("  alias: %s\n", plan.Alias)
	r.printf("  endpoint: %s\n", plan.Endpoint.URL)
	if strings.HasPrefix(plan.Endpoint.URL, "ssh://") {
		signerPort := plan.Endpoint.SignerPort
		if signerPort == 0 {
			signerPort = config.DefaultRESTPort
		}
		r.printf("  signer REST port through SSH: %d\n", signerPort)
	}
	r.printf("  Witness Key ID: %s\n", witness.GroupedID(plan.Witness.WitnessKeyID))
	if plan.Created {
		r.println("  endpoint change: create")
	} else if plan.Updated {
		r.println("  endpoint change: replace")
		if plan.ExistingEndpoint != nil {
			r.printf("  previous endpoint: %s\n", plan.ExistingEndpoint.URL)
			if strings.HasPrefix(plan.ExistingEndpoint.URL, "ssh://") {
				previousPort := plan.ExistingEndpoint.SignerPort
				if previousPort == 0 {
					previousPort = config.DefaultRESTPort
				}
				r.printf("  previous signer REST port: %d\n", previousPort)
			}
		}
	} else {
		r.println("  endpoint change: none")
	}
}

func (r *REPLState) printSentryProvisioningWait() {
	r.progressPrintln("Waiting for approval in apadmin on the sentry...")
	r.progressPrintln("Leave this shell open while the sentry operator approves or rejects the request.")
}

func (r *REPLState) renderSentrySetupResult(result *apshellapp.SentrySetupResult) {
	if result.DryRun {
		r.println("Sentry setup dry run:")
		r.printf("  endpoint: %s (%s)\n", result.Alias, result.URL)
		r.printf("  expected Witness Key ID: %s\n", witness.GroupedID(result.WitnessKeyID))
		r.println("  no files changed; no network or trust checks performed")
		return
	}
	r.println("✓ Connected; expected witness found")
	r.printf("  endpoint: %s (%s)\n", result.Alias, result.URL)
	r.printf("  Witness Key ID: %s\n", witness.GroupedID(result.WitnessKeyID))
	if result.TokenIssued {
		r.println("  access token: received and saved")
	}
	r.println("Import the same public JSON in signer-side apadmin before creating a guarded account.")
}
