// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package config

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

// These types are the bounded read adapter for endpoints.yaml v1. Retired
// published_sentries data is decoded only here and is deliberately absent
// from the production endpoint types returned to callers.
type clientEndpointRegistryV1 struct {
	SchemaVersion int                               `yaml:"schema_version"`
	Default       string                            `yaml:"default,omitempty"`
	Endpoints     map[string]clientEndpointConfigV1 `yaml:"endpoints,omitempty"`
}

type clientEndpointConfigV1 struct {
	Role              string                                     `yaml:"role"`
	URL               string                                     `yaml:"url"`
	SignerPort        int                                        `yaml:"signer_port,omitempty"`
	LocalPort         int                                        `yaml:"local_port,omitempty"`
	IdentityFile      string                                     `yaml:"identity_file,omitempty"`
	KnownHostsPath    string                                     `yaml:"known_hosts_path,omitempty"`
	TokenFile         string                                     `yaml:"token_file,omitempty"`
	PublishedSentries map[string]clientEndpointPublishedSentryV1 `yaml:"published_sentries,omitempty"`
}

type clientEndpointPublishedSentryV1 struct {
	ComponentKey string `yaml:"component_key"`
	KeyType      string `yaml:"key_type"`
	LastSeenAt   string `yaml:"last_seen_at,omitempty"`
}

func decodeClientEndpointRegistry(data []byte) (ClientEndpointRegistry, error) {
	var header struct {
		SchemaVersion int `yaml:"schema_version"`
	}
	if err := yaml.Unmarshal(data, &header); err != nil {
		return ClientEndpointRegistry{}, err
	}
	if header.SchemaVersion == 0 {
		header.SchemaVersion = 1
	}
	switch header.SchemaVersion {
	case 1:
		var legacy clientEndpointRegistryV1
		if err := UnmarshalKnownFields(data, &legacy); err != nil {
			return ClientEndpointRegistry{}, err
		}
		registry := ClientEndpointRegistry{
			SchemaVersion: ClientEndpointSchemaVersion,
			Default:       legacy.Default,
			Endpoints:     make(map[string]ClientEndpointConfig, len(legacy.Endpoints)),
		}
		for alias, endpoint := range legacy.Endpoints {
			registry.Endpoints[alias] = ClientEndpointConfig{
				Role:           endpoint.Role,
				URL:            endpoint.URL,
				SignerPort:     endpoint.SignerPort,
				LocalPort:      endpoint.LocalPort,
				IdentityFile:   endpoint.IdentityFile,
				KnownHostsPath: endpoint.KnownHostsPath,
				TokenFile:      endpoint.TokenFile,
			}
		}
		return registry, nil
	case ClientEndpointSchemaVersion:
		var registry ClientEndpointRegistry
		if err := UnmarshalKnownFields(data, &registry); err != nil {
			return ClientEndpointRegistry{}, err
		}
		return registry, nil
	default:
		return ClientEndpointRegistry{}, fmt.Errorf("%s schema_version = %d, want 1 or %d", ClientEndpointsFile, header.SchemaVersion, ClientEndpointSchemaVersion)
	}
}
