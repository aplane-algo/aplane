// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apadminapp

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/aplane-algo/aplane/internal/endpointrefs"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/sentry/enrollment"
	"github.com/aplane-algo/aplane/internal/witness"
)

const (
	SentryEnrollmentImportResultSchema = "aplane.sentry-enrollment-import-result.v1"

	sentryEnrollmentExportUsage = "usage: apadmin sentry enrollment export <witness-key-id> [--include-endpoint] [--host <host> | --url <url>] [--signer-port <port>] --out <file>"
	sentryEnrollmentImportUsage = "usage: apadmin sentry enrollment import <file|-> --name <reference-name> [--dry-run]"
)

type sentryEnrollmentExportOptions struct {
	WitnessKeyID    string
	IncludeEndpoint bool
	Host            string
	URL             string
	SignerPort      int
	OutPath         string
}

type sentryEnrollmentImportOptions struct {
	Path   string
	Name   string
	DryRun bool
}

// SentryEnrollmentImportStep is one independently owned effect in a combined
// enrollment import result.
type SentryEnrollmentImportStep struct {
	Status string `json:"status"`
	Name   string `json:"name,omitempty"`
	Alias  string `json:"alias,omitempty"`
	URL    string `json:"url,omitempty"`
	Error  string `json:"error,omitempty"`
}

// SentryEnrollmentImportResult reports signer-reference and client-endpoint
// effects separately so partial completion is machine-visible and retryable.
type SentryEnrollmentImportResult struct {
	Schema          string                     `json:"schema"`
	DryRun          bool                       `json:"dry_run"`
	WitnessKeyID    string                     `json:"witness_key_id"`
	ReferenceImport SentryEnrollmentImportStep `json:"reference_import"`
	EndpointImport  SentryEnrollmentImportStep `json:"endpoint_import"`
}

func sentryEnrollmentAuthMode(args []string) (AuthMode, error) {
	if len(args) == 0 {
		return AuthUnlock, fmt.Errorf("usage: apadmin sentry enrollment <export|import>")
	}
	switch args[0] {
	case "export":
		if _, err := parseSentryEnrollmentExportOptions(args[1:]); err != nil {
			return AuthReadOnly, err
		}
		return AuthReadOnly, nil
	case "import":
		if _, err := parseSentryEnrollmentImportOptions(args[1:]); err != nil {
			return AuthUnlock, err
		}
		return AuthUnlock, nil
	default:
		return AuthUnlock, fmt.Errorf("usage: apadmin sentry enrollment <export|import>")
	}
}

func (c Catalog) runSentryEnrollment(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: apadmin sentry enrollment <export|import>")
	}
	switch args[0] {
	case "export":
		options, err := parseSentryEnrollmentExportOptions(args[1:])
		if err != nil {
			return err
		}
		return c.exportSentryEnrollment(options)
	case "import":
		options, err := parseSentryEnrollmentImportOptions(args[1:])
		if err != nil {
			return err
		}
		return c.importSentryEnrollment(options)
	default:
		return fmt.Errorf("usage: apadmin sentry enrollment <export|import>")
	}
}

func parseSentryEnrollmentExportOptions(args []string) (sentryEnrollmentExportOptions, error) {
	if len(args) == 0 || (args[0] != "-" && strings.HasPrefix(args[0], "-")) {
		return sentryEnrollmentExportOptions{}, errors.New(sentryEnrollmentExportUsage)
	}
	options := sentryEnrollmentExportOptions{WitnessKeyID: args[0]}
	fs := flag.NewFlagSet("apadmin sentry enrollment export", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.BoolVar(&options.IncludeEndpoint, "include-endpoint", false, "include configured portable endpoint metadata")
	fs.StringVar(&options.Host, "host", "", "client-reachable SSH host or IP")
	fs.StringVar(&options.URL, "url", "", "endpoint URL")
	fs.IntVar(&options.SignerPort, "signer-port", 0, "remote apsigner REST port")
	fs.StringVar(&options.OutPath, "out", "", "output JSON path")
	if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 0 || strings.TrimSpace(options.OutPath) == "" {
		return sentryEnrollmentExportOptions{}, errors.New(sentryEnrollmentExportUsage)
	}
	if options.Host != "" && options.URL != "" {
		return sentryEnrollmentExportOptions{}, fmt.Errorf("--host and --url are mutually exclusive")
	}
	keyID, err := witness.NormalizeID(options.WitnessKeyID)
	if err != nil {
		return sentryEnrollmentExportOptions{}, fmt.Errorf("invalid Witness Key ID: %w", err)
	}
	options.WitnessKeyID = keyID
	return options, nil
}

func parseSentryEnrollmentImportOptions(args []string) (sentryEnrollmentImportOptions, error) {
	if len(args) == 0 || (args[0] != "-" && strings.HasPrefix(args[0], "-")) {
		return sentryEnrollmentImportOptions{}, errors.New(sentryEnrollmentImportUsage)
	}
	options := sentryEnrollmentImportOptions{Path: args[0]}
	fs := flag.NewFlagSet("apadmin sentry enrollment import", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&options.Name, "name", "", "signer-local sentry reference name")
	fs.BoolVar(&options.DryRun, "dry-run", false, "validate and preview without mutation")
	if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 0 || strings.TrimSpace(options.Name) == "" {
		return sentryEnrollmentImportOptions{}, errors.New(sentryEnrollmentImportUsage)
	}
	return options, nil
}

func (c Catalog) exportSentryEnrollment(options sentryEnrollmentExportOptions) error {
	result, err := requestInspectionWithRetry(c, func() any {
		return protocol.ExportSentryPublicMessage{
			BaseMessage:  protocol.BaseMessage{Type: protocol.MsgTypeExportSentryPublic, ID: c.requestID("sentry-enrollment-export")},
			WitnessKeyID: options.WitnessKeyID,
		}
	}, func(result *protocol.ExportSentryPublicResultMessage) string { return result.Code })
	if err != nil {
		return err
	}
	if !result.Success {
		return resultError("sentry enrollment export failed", result.Code, result.Error)
	}
	reference, err := witness.ParsePublicReference([]byte(result.EnvelopeJSON))
	if err != nil {
		return fmt.Errorf("sentry returned an invalid public witness reference: %w", err)
	}
	if reference.WitnessKeyID != options.WitnessKeyID {
		return fmt.Errorf("sentry returned Witness Key ID %s for requested ID %s", reference.WitnessKeyID, options.WitnessKeyID)
	}

	settings, err := c.loadEndpointSettings()
	if err != nil {
		return err
	}
	bundle := enrollment.Envelope{Schema: enrollment.Schema, Witness: reference}
	includeEndpoint := options.IncludeEndpoint || options.Host != "" || options.URL != "" || options.SignerPort != 0
	if includeEndpoint {
		endpoint, err := buildEndpointExportEnvelope(
			options.Host, options.URL, options.SignerPort, 0, settings,
		)
		if err != nil {
			return err
		}
		bundle.Endpoint = &endpoint
	}

	data, err := enrollment.Marshal(bundle)
	if err != nil {
		return err
	}
	if err := WriteSentryPublicEnvelope(options.OutPath, data); err != nil {
		return err
	}
	c.info("sentry enrollment envelope written: %s", options.OutPath)
	return nil
}

func (c Catalog) importSentryEnrollment(options sentryEnrollmentImportOptions) error {
	data, err := ReadSentryPublicEnvelope(options.Path, c.Streams.Stdin)
	if err != nil {
		return err
	}
	artifact, err := enrollment.ParseArtifact(data)
	if err != nil {
		return err
	}
	witnessJSON, err := enrollment.MarshalWitness(artifact.Witness)
	if err != nil {
		return err
	}

	result := SentryEnrollmentImportResult{
		Schema:       SentryEnrollmentImportResultSchema,
		DryRun:       options.DryRun,
		WitnessKeyID: artifact.Witness.WitnessKeyID,
		ReferenceImport: SentryEnrollmentImportStep{
			Status: "planned", Name: options.Name,
		},
		EndpointImport: SentryEnrollmentImportStep{Status: "not_requested"},
	}

	if options.DryRun {
		return c.writeSentryEnrollmentImportResult(result)
	}

	var importResult protocol.ImportSentryReferenceResultMessage
	if err := c.Client.Request(protocol.ImportSentryReferenceMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeImportSentryReference, ID: c.requestID("sentry-enrollment-import")},
		Name:        options.Name, EnvelopeJSON: string(witnessJSON),
	}, &importResult); err != nil {
		return err
	}
	if !importResult.Success {
		return resultError("sentry enrollment reference import failed", importResult.Code, importResult.Error)
	}
	result.ReferenceImport.Status = "imported"
	if importResult.Reference.Name != "" {
		result.ReferenceImport.Name = importResult.Reference.Name
	}

	if err := c.writeSentryEnrollmentImportResult(result); err != nil {
		return err
	}
	return nil
}

func (c Catalog) writeSentryEnrollmentImportResult(result SentryEnrollmentImportResult) error {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("encode sentry enrollment import result: %w", err)
	}
	_, err = c.Streams.Stdout.Write(append(data, '\n'))
	return err
}

func buildEndpointExportEnvelope(
	host, explicitURL string,
	signerPort, localPort int,
	settings endpointExportSettings,
) (endpointrefs.Envelope, error) {
	urlValue, err := endpointExportURL(host, explicitURL, settings.AdvertiseURL, endpointExportSSHPort(settings))
	if err != nil {
		return endpointrefs.Envelope{}, err
	}
	if signerPort == 0 && endpointExportUsesSSH(urlValue) {
		signerPort = endpointExportSignerPort(settings)
	}
	return endpointrefs.Normalize(endpointrefs.Envelope{
		Schema: endpointrefs.Schema, URL: urlValue, SignerPort: signerPort, LocalPort: localPort,
	})
}

// BuildAdvertisedEndpointEnvelope constructs the portable endpoint portion of
// an enrollment bundle from signer-advertised settings. Batch and TUI export
// share this helper so URL and port precedence cannot drift.
func BuildAdvertisedEndpointEnvelope(advertiseURL string, sshPort, signerPort int) (endpointrefs.Envelope, error) {
	return buildEndpointExportEnvelope("", "", 0, 0, endpointExportSettings{
		AdvertiseURL: advertiseURL,
		SSHPort:      sshPort,
		SignerPort:   signerPort,
	})
}
