// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package ai

import (
	"encoding/json"
	"fmt"
)

const (
	openaiAPIURL       = "https://api.openai.com/v1/chat/completions"
	openaiDefaultModel = "gpt-5.2"
)

// OpenAIProvider implements Provider for OpenAI API.
type OpenAIProvider struct {
	baseProvider
}

// openaiMessage represents a conversation message.
type openaiMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// openaiRequest is the API request body.
type openaiRequest struct {
	Model               string          `json:"model"`
	MaxCompletionTokens int             `json:"max_completion_tokens,omitempty"`
	Messages            []openaiMessage `json:"messages"`
}

// openaiResponse is the API response body.
type openaiResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
}

// NewOpenAIProvider creates a new OpenAI provider.
func NewOpenAIProvider(apiKey, model string) (*OpenAIProvider, error) {
	return &OpenAIProvider{
		baseProvider: newBaseProvider(apiKey, model, openaiDefaultModel),
	}, nil
}

// Name returns the provider name.
func (p *OpenAIProvider) Name() string {
	return "OpenAI"
}

// GenerateCode generates JavaScript code from a natural language prompt.
func (p *OpenAIProvider) GenerateCode(prompt string) (string, error) {
	reqBody := openaiRequest{
		Model:               p.model,
		MaxCompletionTokens: defaultMaxTokens,
		Messages: []openaiMessage{
			{Role: "system", Content: BuildSystemPromptWithFunctions(p.plugins, p.functions)},
			{Role: "user", Content: prompt},
		},
	}

	body, err := p.doJSONRequest(openaiAPIURL, reqBody, map[string]string{
		"Authorization": "Bearer " + p.apiKey,
	})
	if err != nil {
		return "", err
	}

	var apiResp openaiResponse
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return "", fmt.Errorf("failed to parse response: %w", err)
	}

	if apiResp.Error != nil {
		return "", fmt.Errorf("API error: %s", apiResp.Error.Message)
	}

	if len(apiResp.Choices) == 0 {
		return "", fmt.Errorf("empty response from API")
	}

	return extractCode(apiResp.Choices[0].Message.Content), nil
}

// Compile-time interface check
var _ Provider = (*OpenAIProvider)(nil)
