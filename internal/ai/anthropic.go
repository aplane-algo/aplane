// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package ai

import (
	"encoding/json"
	"fmt"
)

const (
	anthropicAPIURL       = "https://api.anthropic.com/v1/messages"
	anthropicAPIVersion   = "2023-06-01"
	anthropicDefaultModel = "claude-sonnet-4-5-20250929"
)

// AnthropicProvider implements Provider for Claude API.
type AnthropicProvider struct {
	baseProvider
}

// anthropicMessage represents a conversation message.
type anthropicMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// anthropicRequest is the API request body.
type anthropicRequest struct {
	Model     string             `json:"model"`
	MaxTokens int                `json:"max_tokens"`
	System    string             `json:"system,omitempty"`
	Messages  []anthropicMessage `json:"messages"`
}

// anthropicResponse is the API response body.
type anthropicResponse struct {
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
	Error *struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	} `json:"error"`
}

// NewAnthropicProvider creates a new Anthropic provider.
func NewAnthropicProvider(apiKey, model string) (*AnthropicProvider, error) {
	return &AnthropicProvider{
		baseProvider: newBaseProvider(apiKey, model, anthropicDefaultModel),
	}, nil
}

// Name returns the provider name.
func (p *AnthropicProvider) Name() string {
	return "Anthropic"
}

// GenerateCode generates JavaScript code from a natural language prompt.
func (p *AnthropicProvider) GenerateCode(prompt string) (string, error) {
	reqBody := anthropicRequest{
		Model:     p.model,
		MaxTokens: defaultMaxTokens,
		System:    BuildSystemPromptWithFunctions(p.plugins, p.functions),
		Messages: []anthropicMessage{
			{Role: "user", Content: prompt},
		},
	}

	body, err := p.doJSONRequest(anthropicAPIURL, reqBody, map[string]string{
		"x-api-key":         p.apiKey,
		"anthropic-version": anthropicAPIVersion,
	})
	if err != nil {
		return "", err
	}

	var apiResp anthropicResponse
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return "", fmt.Errorf("failed to parse response: %w", err)
	}

	if apiResp.Error != nil {
		return "", fmt.Errorf("API error: %s", apiResp.Error.Message)
	}

	if len(apiResp.Content) == 0 {
		return "", fmt.Errorf("empty response from API")
	}

	return extractCode(apiResp.Content[0].Text), nil
}

// Compile-time interface check
var _ Provider = (*AnthropicProvider)(nil)
