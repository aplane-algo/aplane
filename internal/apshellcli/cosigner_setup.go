// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/aplane-algo/aplane/internal/apshellapp"
	"github.com/aplane-algo/aplane/internal/command"
)

const cosignerUsage = "cosigner status | cosigner add ... (now: endpoints add)"

const endpointsAddUsage = "endpoints add [<cosigner-url>] [--alias <alias>] [--replace] [--dry-run]"

// endpointsAddFileHint answers an operator who hands the client the cosigner's
// key file, which belongs on the signer.
const endpointsAddFileHint = "endpoints add takes the cosigner's URL (for example ssh://cosigner.example:1127), not a file; the cosigner's key file is imported on the signer with apadmin"

// cosignerAddForwardNotice is printed when the former command name is used.
const cosignerAddForwardNotice = "Note: 'cosigner add' is now 'endpoints add'; continuing."

type cosignerSetupCLIOptions struct {
	request apshellapp.CosignerSetupRequest
	replace bool
}

type cosignerSetupProjection struct {
	Alias             string                          `json:"alias"`
	URL               string                          `json:"url"`
	Created           bool                            `json:"created,omitempty"`
	Updated           bool                            `json:"updated,omitempty"`
	Enrolled          bool                            `json:"enrolled,omitempty"`
	EnrollmentPending bool                            `json:"enrollment_pending,omitempty"`
	Connected         bool                            `json:"connected,omitempty"`
	NodeRole          string                          `json:"node_role,omitempty"`
	AdvertisedKeys    int                             `json:"advertised_keys,omitempty"`
	Routes            *apshellapp.CosignerSetupRoutes `json:"routes,omitempty"`
	DryRun            bool                            `json:"dry_run,omitempty"`
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
// connection without prompts, and reports connection and route results
// separately.
func (r *REPLState) runEndpointsAdd(args []string) (command.Result, error) {
	options, err := parseEndpointsAddArgs(args)
	if err != nil {
		return nil, err
	}
	if options.request.URL == "" && (r.AutoConfirm || !r.hasInteractiveLineReader()) {
		return nil, fmt.Errorf("the cosigner URL is required: %s", endpointsAddUsage)
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
	result, err := r.app().CompleteCosignerSetup(r.commandContext(), plan, endpoint, buildHostKeyApproval(r), r.printCosignerEnrollmentWait)
	if err != nil {
		if result != nil {
			for _, line := range result.RenderLines {
				r.println(line)
			}
		}
		completed := cosignerSetupCompletedEffects(plan, result)
		if r.offerCreatedConnectionRemoval(plan, err) {
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
		Alias: result.Alias, URL: result.URL,
		Created: result.Created, Updated: result.Updated, Enrolled: result.Enrolled, EnrollmentPending: result.EnrollmentPending,
		Connected: result.Connected, NodeRole: result.NodeRole,
		AdvertisedKeys: result.AdvertisedKeys, Routes: result.Routes, DryRun: result.DryRun,
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
	if result != nil && result.Enrolled {
		completed += " and this client's key was enrolled at the cosigner"
	}
	if result != nil && result.EnrollmentPending {
		completed += " and an enrollment request for this client's key is waiting for the cosigner's operator"
	}
	return completed
}

// offerCreatedConnectionRemoval offers to remove a connection only when this
// run created it and it cannot be used as it stands: the node is not a
// cosigner, or it duplicates another connection's route. Existing connections
// are never offered for removal here.
func (r *REPLState) offerCreatedConnectionRemoval(plan apshellapp.CosignerSetupPlan, setupErr error) bool {
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
	if err := r.app().RemoveCreatedCosignerConnection(plan); err != nil {
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
		default:
			if strings.HasPrefix(args[i], "-") || out.request.URL != "" {
				return out, errors.New("usage: " + endpointsAddUsage)
			}
			if !strings.Contains(args[i], "://") {
				return out, errors.New(endpointsAddFileHint)
			}
			out.request.URL = args[i]
		}
	}
	return out, nil
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
	if plan.Created {
		r.println("  endpoint change: create")
	} else if plan.Updated {
		r.println("  endpoint change: replace")
		if plan.ExistingEndpoint != nil {
			r.printf("  previous endpoint: %s\n", plan.ExistingEndpoint.URL)
		}
	} else {
		r.println("  endpoint change: none")
	}
}

func (r *REPLState) printCosignerEnrollmentWait(clientFingerprint string) {
	r.progressPrintln("Waiting for approval. In apadmin on the cosigner, open the Client Enrollment Request")
	r.progressPrintln("and compare its full fingerprint with this one before approving:")
	r.progressPrintln("  " + clientFingerprint)
	r.progressPrintln("Leave this shell open while the cosigner operator approves or rejects the request.")
}
