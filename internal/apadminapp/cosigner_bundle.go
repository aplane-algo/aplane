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

	"github.com/aplane-algo/aplane/internal/cosigner/enrollment"
	"github.com/aplane-algo/aplane/internal/endpointrefs"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/witness"
)

const (
	CosignerEnrollmentImportResultSchema = "aplane.cosigner-enrollment-import-result.v1"

	cosignerEnrollmentExportUsage = "usage: apadmin cosigner enrollment export <witness-key-id> [--include-endpoint] [--host <host> | --url <url>] [--signer-port <port>] --out <file>"
	cosignerEnrollmentImportUsage = "usage: apadmin cosigner enrollment import <file|-> --name <reference-name> [--dry-run]"
)

type cosignerEnrollmentExportOptions struct {
	WitnessKeyID    string
	IncludeEndpoint bool
	Host            string
	URL             string
	SignerPort      int
	OutPath         string
}

type cosignerEnrollmentImportOptions struct {
	Path   string
	Name   string
	DryRun bool
}

// CosignerEnrollmentImportStep is one independently owned effect in a combined
// enrollment import result.
type CosignerEnrollmentImportStep struct {
	Status string `json:"status"`
	Name   string `json:"name,omitempty"`
	Alias  string `json:"alias,omitempty"`
	URL    string `json:"url,omitempty"`
	Error  string `json:"error,omitempty"`
}

// CosignerEnrollmentImportResult reports signer-reference and client-endpoint
// effects separately so partial completion is machine-visible and retryable.
type CosignerEnrollmentImportResult struct {
	Schema          string                       `json:"schema"`
	DryRun          bool                         `json:"dry_run"`
	WitnessKeyID    string                       `json:"witness_key_id"`
	ReferenceImport CosignerEnrollmentImportStep `json:"reference_import"`
	EndpointImport  CosignerEnrollmentImportStep `json:"endpoint_import"`
}

func cosignerEnrollmentAuthMode(args []string) (AuthMode, error) {
	if len(args) == 0 {
		return AuthUnlock, fmt.Errorf("usage: apadmin cosigner enrollment <export|import>")
	}
	switch args[0] {
	case "export":
		if _, err := parseCosignerEnrollmentExportOptions(args[1:]); err != nil {
			return AuthReadOnly, err
		}
		return AuthReadOnly, nil
	case "import":
		if _, err := parseCosignerEnrollmentImportOptions(args[1:]); err != nil {
			return AuthUnlock, err
		}
		return AuthUnlock, nil
	default:
		return AuthUnlock, fmt.Errorf("usage: apadmin cosigner enrollment <export|import>")
	}
}

func (c Catalog) runCosignerEnrollment(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: apadmin cosigner enrollment <export|import>")
	}
	switch args[0] {
	case "export":
		options, err := parseCosignerEnrollmentExportOptions(args[1:])
		if err != nil {
			return err
		}
		return c.exportCosignerEnrollment(options)
	case "import":
		options, err := parseCosignerEnrollmentImportOptions(args[1:])
		if err != nil {
			return err
		}
		return c.importCosignerEnrollment(options)
	default:
		return fmt.Errorf("usage: apadmin cosigner enrollment <export|import>")
	}
}

func parseCosignerEnrollmentExportOptions(args []string) (cosignerEnrollmentExportOptions, error) {
	if len(args) == 0 || (args[0] != "-" && strings.HasPrefix(args[0], "-")) {
		return cosignerEnrollmentExportOptions{}, errors.New(cosignerEnrollmentExportUsage)
	}
	options := cosignerEnrollmentExportOptions{WitnessKeyID: args[0]}
	fs := flag.NewFlagSet("apadmin cosigner enrollment export", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.BoolVar(&options.IncludeEndpoint, "include-endpoint", false, "include configured portable endpoint metadata")
	fs.StringVar(&options.Host, "host", "", "client-reachable SSH host or IP")
	fs.StringVar(&options.URL, "url", "", "endpoint URL")
	fs.IntVar(&options.SignerPort, "signer-port", 0, "remote apsigner REST port")
	fs.StringVar(&options.OutPath, "out", "", "output JSON path")
	if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 0 || strings.TrimSpace(options.OutPath) == "" {
		return cosignerEnrollmentExportOptions{}, errors.New(cosignerEnrollmentExportUsage)
	}
	if options.Host != "" && options.URL != "" {
		return cosignerEnrollmentExportOptions{}, fmt.Errorf("--host and --url are mutually exclusive")
	}
	keyID, err := witness.NormalizeID(options.WitnessKeyID)
	if err != nil {
		return cosignerEnrollmentExportOptions{}, fmt.Errorf("invalid Witness Key ID: %w", err)
	}
	options.WitnessKeyID = keyID
	return options, nil
}

func parseCosignerEnrollmentImportOptions(args []string) (cosignerEnrollmentImportOptions, error) {
	if len(args) == 0 || (args[0] != "-" && strings.HasPrefix(args[0], "-")) {
		return cosignerEnrollmentImportOptions{}, errors.New(cosignerEnrollmentImportUsage)
	}
	options := cosignerEnrollmentImportOptions{Path: args[0]}
	fs := flag.NewFlagSet("apadmin cosigner enrollment import", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&options.Name, "name", "", "signer-local cosigner reference name")
	fs.BoolVar(&options.DryRun, "dry-run", false, "validate and preview without mutation")
	if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 0 || strings.TrimSpace(options.Name) == "" {
		return cosignerEnrollmentImportOptions{}, errors.New(cosignerEnrollmentImportUsage)
	}
	return options, nil
}

func (c Catalog) exportCosignerEnrollment(options cosignerEnrollmentExportOptions) error {
	result, err := requestInspectionWithRetry(c, func() any {
		return protocol.ExportCosignerPublicMessage{
			BaseMessage:  protocol.BaseMessage{Type: protocol.MsgTypeExportCosignerPublic, ID: c.requestID("cosigner-enrollment-export")},
			WitnessKeyID: options.WitnessKeyID,
		}
	}, func(result *protocol.ExportCosignerPublicResultMessage) string { return result.Code })
	if err != nil {
		return err
	}
	if !result.Success {
		return resultError("cosigner key export failed", result.Code, result.Error)
	}
	reference, err := witness.ParsePublicReference([]byte(result.EnvelopeJSON))
	if err != nil {
		return fmt.Errorf("cosigner returned an invalid public witness reference: %w", err)
	}
	if reference.WitnessKeyID != options.WitnessKeyID {
		return fmt.Errorf("cosigner returned Witness Key ID %s for requested ID %s", reference.WitnessKeyID, options.WitnessKeyID)
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
	if err := WriteCosignerPublicEnvelope(options.OutPath, data); err != nil {
		return err
	}
	c.info("cosigner key written: %s", options.OutPath)
	return nil
}

func (c Catalog) importCosignerEnrollment(options cosignerEnrollmentImportOptions) error {
	data, err := ReadCosignerPublicEnvelope(options.Path, c.Streams.Stdin)
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

	result := CosignerEnrollmentImportResult{
		Schema:       CosignerEnrollmentImportResultSchema,
		DryRun:       options.DryRun,
		WitnessKeyID: artifact.Witness.WitnessKeyID,
		ReferenceImport: CosignerEnrollmentImportStep{
			Status: "planned", Name: options.Name,
		},
		EndpointImport: CosignerEnrollmentImportStep{Status: "not_requested"},
	}

	if options.DryRun {
		return c.writeCosignerEnrollmentImportResult(result)
	}

	var importResult protocol.ImportCosignerReferenceResultMessage
	if err := c.Client.Request(protocol.ImportCosignerReferenceMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeImportCosignerReference, ID: c.requestID("cosigner-enrollment-import")},
		Name:        options.Name, EnvelopeJSON: string(witnessJSON),
	}, &importResult); err != nil {
		return err
	}
	if !importResult.Success {
		return resultError("cosigner key import failed", importResult.Code, importResult.Error)
	}
	result.ReferenceImport.Status = "imported"
	if importResult.Reference.Name != "" {
		result.ReferenceImport.Name = importResult.Reference.Name
	}

	if err := c.writeCosignerEnrollmentImportResult(result); err != nil {
		return err
	}
	return nil
}

func (c Catalog) writeCosignerEnrollmentImportResult(result CosignerEnrollmentImportResult) error {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("encode cosigner enrollment import result: %w", err)
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

// BuildCosignerEndpointEnvelope constructs the portable endpoint portion of
// an enrollment bundle from an operator-supplied host or, when host is empty,
// the signer-advertised URL. Batch and TUI export share this helper so URL and
// port precedence cannot drift.
func BuildCosignerEndpointEnvelope(host, advertiseURL string, sshPort, signerPort int) (endpointrefs.Envelope, error) {
	return buildEndpointExportEnvelope(host, "", 0, 0, endpointExportSettings{
		AdvertiseURL: advertiseURL,
		SSHPort:      sshPort,
		SignerPort:   signerPort,
	})
}
