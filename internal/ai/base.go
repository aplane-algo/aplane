// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package ai

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const defaultMaxTokens = 4096

// baseProvider contains fields common to all AI providers.
type baseProvider struct {
	apiKey     string
	model      string
	httpClient *http.Client
	plugins    []PluginInfo
	functions  []FunctionInfo
}

// newBaseProvider creates a base provider with common initialization.
func newBaseProvider(apiKey, model, defaultModel string) baseProvider {
	if model == "" {
		model = defaultModel
	}
	return baseProvider{
		apiKey: apiKey,
		model:  model,
		httpClient: &http.Client{
			Timeout: 60 * time.Second,
		},
	}
}

// SetPlugins sets the plugin information for dynamic prompt generation.
func (p *baseProvider) SetPlugins(plugins []PluginInfo) {
	p.plugins = plugins
}

// SetFunctions sets the typed function information for dynamic prompt generation.
func (p *baseProvider) SetFunctions(functions []FunctionInfo) {
	p.functions = functions
}

// doJSONRequest performs an HTTP POST with JSON body and returns the response body.
// headers is a map of additional headers to set (beyond Content-Type).
func (p *baseProvider) doJSONRequest(url string, reqBody interface{}, headers map[string]string) ([]byte, error) {
	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequest("POST", url, bytes.NewReader(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("API request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	return body, nil
}
