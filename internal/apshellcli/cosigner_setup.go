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
	"github.com/aplane-algo/aplane/internal/cosigner/enrollment"
)

const cosignerUsage = "cosigner status | cosigner add ... (now: endpoints add)"

const endpointsAddUsage = "endpoints add [public-json] [--alias <alias>] [--endpoint <url>] [--cosigner-port <port>] [--replace] [--dry-run]"

// cosignerAddForwardNotice is printed when the former command name is used.
const cosignerAddForwardNotice = "Note: 'cosigner add' is now 'endpoints add'; continuing."

type cosignerSetupCLIOptions struct {
	request apshellapp.CosignerSetupRequest
	path    string
	replace bool
}

type cosignerSetupProjection struct {
	Alias          string                          `json:"alias"`
	WitnessKeyID   string                          `json:"witness_key_id,omitempty"`
	URL            string                          `json:"url"`
	Created        bool                            `json:"created,omitempty"`
	Updated        bool                            `json:"updated,omitempty"`
	TokenIssued    bool                            `json:"token_issued,omitempty"`
	TokenRetired   bool                            `json:"token_retired,omitempty"`
	Connected      bool                            `json:"connected,omitempty"`
	NodeRole       string                          `json:"node_role,omitempty"`
	KeyCheck       string                          `json:"key_check,omitempty"`
	AdvertisedKeys int                             `json:"advertised_keys,omitempty"`
	Verified       bool                            `json:"verified,omitempty"`
	Routes         *apshellapp.CosignerSetupRoutes `json:"routes,omitempty"`
	DryRun         bool                            `json:"dry_run,omitempty"`
}

func (r *REPLState) cmdCosigner(args []string, _ interface{}) (command.Result, error) {
	if len(args) > 0 && args[0] == "status" {
		if len(args) != 1 {
			return nil, errors.New("usage: cosigner status")
		}
		result, err := r.app().CosignerStatus(r.commandContext(), apshellapp.CosignerStatusRequest{})
		if err != nil {
			return nil, err
		}
		return newShellCommandResult(func(w io.Writer) error {
			return r.withOutput(w, func() {
				for _, line := range result.RenderLines {
					r.println(line)
				}
			})
		}, result.CosignerStatusResult)
	}
	if len(args) > 0 && args[0] == "add" {
		r.println(cosignerAddForwardNotice)
		return r.runEndpointsAdd(args[1:])
	}
	return nil, errors.New("usage: " + cosignerUsage)
}

// runEndpointsAdd is the guided cosigner connection setup. It resolves the
// destination and connection name before asking anything, reuses an existing
// connection without prompts, and reports connection, key, and route results
// separately.
func (r *REPLState) runEndpointsAdd(args []string) (command.Result, error) {
	options, err := parseEndpointsAddArgs(args)
	if err != nil {
		return nil, err
	}
	switch {
	case options.path != "":
		options.request.Document, err = readBoundedCosignerSetupFile(options.path)
	case options.request.URL == "":
		if r.AutoConfirm || !r.hasInteractiveLineReader() {
			return nil, fmt.Errorf("interactive setup JSON paste is unavailable; provide a file or --endpoint: %s", endpointsAddUsage)
		}
		options.request.Document, err = r.readCosignerSetupPaste()
	}
	if err != nil {
		return nil, err
	}

	if options.request.Alias == "" {
		target, resolveErr := r.app().ResolveCosignerSetupTarget(options.request)
		if resolveErr != nil && errors.Is(resolveErr, apshellapp.ErrCosignerEndpointURLRequired) && !r.AutoConfirm {
			options.request.URL, err = r.readRequiredSetupValue("Cosigner endpoint (ssh://, https://, or loopback http://): ")
			if err != nil {
				return nil, err
			}
			target, resolveErr = r.app().ResolveCosignerSetupTarget(options.request)
		}
		if resolveErr != nil {
			return nil, resolveErr
		}
		switch {
		case target.ExistingAlias != "":
			options.request.Alias = target.ExistingAlias
		case r.AutoConfirm:
			return nil, errors.New("--alias is required in script mode")
		default:
			r.printf("Cosigner at %s\n", target.URL)
			options.request.Alias, err = r.readSetupValueWithDefault("Connection name", target.SuggestedAlias)
			if err != nil {
				return nil, err
			}
		}
	}
	plan, err := r.app().PrepareCosignerSetup(options.request)
	if err != nil && errors.Is(err, apshellapp.ErrCosignerEndpointURLRequired) && !r.AutoConfirm {
		options.request.URL, err = r.readRequiredSetupValue("Cosigner endpoint (ssh://, https://, or loopback http://): ")
		if err != nil {
			return nil, err
		}
		plan, err = r.app().PrepareCosignerSetup(options.request)
	}
	if err != nil {
		return nil, err
	}

	if plan.ReplacementRequired && !plan.DryRun {
		if r.AutoConfirm {
			return nil, fmt.Errorf("endpoint alias %q has different settings; review the replacement in interactive apshell", plan.Alias)
		}
		if !options.replace {
			response, promptErr := r.readPromptResponse(fmt.Sprintf("Replace existing cosigner endpoint %s? [y/N]: ", plan.Alias))
			if promptErr != nil {
				return nil, promptErr
			}
			if response != "y" && response != "yes" {
				return nil, errors.New("cosigner setup cancelled")
			}
			options.replace = true
		}
	}

	switch {
	case plan.DryRun:
	case plan.Unchanged():
		// An unchanged connection needs no name, review, or confirmation.
		r.printf("Already configured as %s. Checking access...\n", plan.Alias)
	case !r.AutoConfirm:
		r.renderCosignerSetupReview(plan)
		response, promptErr := r.readPromptResponse("Configure this connection and verify it? [y/N]: ")
		if promptErr != nil {
			return nil, promptErr
		}
		if response != "y" && response != "yes" {
			return nil, errors.New("cosigner setup cancelled")
		}
	}

	endpoint, err := r.app().ApplyCosignerSetupEndpoint(plan, options.replace)
	if err != nil {
		return nil, err
	}
	result, err := r.app().CompleteCosignerSetup(r.commandContext(), plan, endpoint, buildHostKeyApproval(r), r.printCosignerProvisioningWait)
	if err != nil {
		if result != nil {
			for _, line := range result.RenderLines {
				r.println(line)
			}
		}
		completed := cosignerSetupCompletedEffects(plan, result)
		if r.offerCreatedConnectionRemoval(plan, result, err) {
			completed = "the connection created by this run was removed"
		}
		return nil, fmt.Errorf("%s; setup did not complete: %w", completed, err)
	}
	return newShellCommandResult(func(w io.Writer) error {
		return r.withOutput(w, func() {
			for _, line := range result.RenderLines {
				r.println(line)
			}
		})
	}, cosignerSetupProjection{
		Alias: result.Alias, WitnessKeyID: result.WitnessKeyID, URL: result.URL,
		Created: result.Created, Updated: result.Updated, TokenIssued: result.TokenIssued,
		TokenRetired: result.TokenRetired, Connected: result.Connected, NodeRole: result.NodeRole,
		KeyCheck: result.KeyCheck, AdvertisedKeys: result.AdvertisedKeys, Verified: result.Verified,
		Routes: result.Routes, DryRun: result.DryRun,
	})
}

// cosignerSetupCompletedEffects names what a failed setup run left in place,
// so a partial setup is never described as complete or as nothing.
func cosignerSetupCompletedEffects(plan apshellapp.CosignerSetupPlan, result *apshellapp.CosignerSetupResult) string {
	completed := "connection configuration retained"
	if plan.Created {
		completed = "connection created"
	} else if plan.Updated {
		completed = "connection updated"
	}
	if result != nil && result.TokenRetired {
		completed += ", previous destination's token removed"
	}
	if result != nil && result.TokenIssued {
		completed += " and access token saved"
	}
	return completed
}

// offerCreatedConnectionRemoval offers to remove a connection only when this
// run created it and it cannot be used as it stands: the node is not a
// cosigner, or it duplicates another connection's route. Existing connections
// are never offered for removal here.
func (r *REPLState) offerCreatedConnectionRemoval(plan apshellapp.CosignerSetupPlan, result *apshellapp.CosignerSetupResult, setupErr error) bool {
	if !plan.Created || r.AutoConfirm || !r.hasInteractiveLineReader() {
		return false
	}
	if !errors.Is(setupErr, apshellapp.ErrCosignerSetupNotCosigner) && !errors.Is(setupErr, apshellapp.ErrCosignerSetupDuplicateRoute) {
		return false
	}
	r.println(setupErr.Error())
	response, err := r.readPromptResponse(fmt.Sprintf("Remove the connection %s that this run created? [y/N]: ", plan.Alias))
	if err != nil || (response != "y" && response != "yes") {
		return false
	}
	if err := r.app().RemoveCreatedCosignerConnection(plan, result); err != nil {
		r.printf("Could not remove connection %s: %v\n", plan.Alias, err)
		return false
	}
	return true
}

func parseEndpointsAddArgs(args []string) (cosignerSetupCLIOptions, error) {
	var out cosignerSetupCLIOptions
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--dry-run":
			out.request.DryRun = true
		case "--replace":
			out.replace = true
		case "--alias", "-a":
			i++
			if i >= len(args) {
				return out, errors.New("usage: " + endpointsAddUsage)
			}
			out.request.Alias = args[i]
		case "--endpoint", "--url":
			i++
			if i >= len(args) {
				return out, errors.New("usage: " + endpointsAddUsage)
			}
			out.request.URL = args[i]
		case "--cosignerport", "--cosigner-port":
			i++
			if i >= len(args) {
				return out, errors.New("usage: " + endpointsAddUsage)
			}
			port, err := parseSetupPort(args[i])
			if err != nil {
				return out, err
			}
			out.request.SignerPort = port
		default:
			if strings.HasPrefix(args[i], "-") || out.path != "" {
				return out, errors.New("usage: " + endpointsAddUsage)
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

func readBoundedCosignerSetupFile(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("read cosigner JSON %s: %w", path, err)
	}
	defer func() { _ = file.Close() }()
	data, err := io.ReadAll(io.LimitReader(file, enrollment.MaxEnvelopeBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read cosigner JSON %s: %w", path, err)
	}
	if len(data) > enrollment.MaxEnvelopeBytes {
		return nil, fmt.Errorf("cosigner key JSON exceeds %d bytes", enrollment.MaxEnvelopeBytes)
	}
	return data, nil
}

func (r *REPLState) readCosignerSetupPaste() ([]byte, error) {
	r.println("Paste the cosigner setup JSON. The command continues when one complete document is received; Ctrl+C cancels.")
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
				return nil, fmt.Errorf("cosigner key JSON exceeds %d bytes", enrollment.MaxEnvelopeBytes)
			}
			data := []byte(document.String())
			if parseErr := apshellapp.ValidateCosignerSetupDocument(data); parseErr != nil {
				return nil, fmt.Errorf("invalid cosigner key JSON: %w", parseErr)
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
				return nil, fmt.Errorf("cosigner key JSON exceeds %d bytes", enrollment.MaxEnvelopeBytes)
			}
			return nil, fmt.Errorf("invalid cosigner key JSON")
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

// readSetupValueWithDefault prompts for a value and accepts an empty answer as
// the offered default.
func (r *REPLState) readSetupValueWithDefault(label, fallback string) (string, error) {
	prompt := fmt.Sprintf("%s [%s]: ", label, fallback)
	restorePrompt := r.setTemporaryPrompt(prompt)
	defer restorePrompt()
	if !r.hasInteractiveLineReader() {
		r.print("\n" + prompt)
	}
	value, err := r.readInteractiveLine()
	if err != nil {
		return "", err
	}
	if value = strings.TrimSpace(value); value == "" {
		return fallback, nil
	}
	return value, nil
}

func (r *REPLState) renderCosignerSetupReview(plan apshellapp.CosignerSetupPlan) {
	r.println("Cosigner connection review:")
	r.printf("  connection name: %s\n", plan.Alias)
	r.printf("  endpoint: %s\n", plan.Endpoint.URL)
	if strings.HasPrefix(plan.Endpoint.URL, "ssh://") {
		signerPort := plan.Endpoint.SignerPort
		if signerPort == 0 {
			signerPort = config.DefaultRESTPort
		}
		r.printf("  Cosigner API port through SSH: %d\n", signerPort)
	}
	if !plan.HasWitness {
		r.println("  key: none in the input; the connection is set up without a key comparison")
	}
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
				r.printf("  previous Cosigner API port: %d\n", previousPort)
			}
		}
		if plan.RetiresToken {
			r.println("  access token: the stored token was issued by the previous destination and will be removed")
		}
	} else {
		r.println("  endpoint change: none")
	}
}

func (r *REPLState) printCosignerProvisioningWait(clientFingerprint string) {
	r.progressPrintln("Waiting for approval. In apadmin on the cosigner, open the Client Access Request")
	r.progressPrintln("and compare its full fingerprint with this one before approving:")
	r.progressPrintln("  " + clientFingerprint)
	r.progressPrintln("Leave this shell open while the cosigner operator approves or rejects the request.")
}
