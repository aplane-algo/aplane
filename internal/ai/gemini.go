// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package ai

import (
	"encoding/json"
	"fmt"
)

const (
	geminiAPIURLBase   = "https://generativelanguage.googleapis.com/v1beta/models/"
	geminiDefaultModel = "gemini-2.0-flash"
)

// GeminiProvider implements Provider for Google Gemini API.
type GeminiProvider struct {
	baseProvider
}

// geminiPart represents a content part.
type geminiPart struct {
	Text string `json:"text"`
}

// geminiContent represents a conversation message.
type geminiContent struct {
	Role  string       `json:"role,omitempty"`
	Parts []geminiPart `json:"parts"`
}

// geminiGenerationConfig holds generation parameters.
type geminiGenerationConfig struct {
	MaxOutputTokens int `json:"maxOutputTokens,omitempty"`
}

// geminiRequest is the API request body.
type geminiRequest struct {
	Contents          []geminiContent        `json:"contents"`
	SystemInstruction *geminiContent         `json:"systemInstruction,omitempty"`
	GenerationConfig  geminiGenerationConfig `json:"generationConfig,omitempty"`
}

// geminiResponse is the API response body.
type geminiResponse struct {
	Candidates []struct {
		Content struct {
			Parts []geminiPart `json:"parts"`
			Role  string       `json:"role"`
		} `json:"content"`
	} `json:"candidates"`
	Error *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Status  string `json:"status"`
	} `json:"error"`
}

// NewGeminiProvider creates a new Gemini provider.
func NewGeminiProvider(apiKey, model string) (*GeminiProvider, error) {
	return &GeminiProvider{
		baseProvider: newBaseProvider(apiKey, model, geminiDefaultModel),
	}, nil
}

// Name returns the provider name.
func (p *GeminiProvider) Name() string {
	return "Gemini"
}

// GenerateCode generates JavaScript code from a natural language prompt.
func (p *GeminiProvider) GenerateCode(prompt string) (string, error) {
	reqBody := geminiRequest{
		Contents: []geminiContent{
			{
				Role:  "user",
				Parts: []geminiPart{{Text: prompt}},
			},
		},
		SystemInstruction: &geminiContent{
			Parts: []geminiPart{{Text: BuildSystemPromptWithFunctions(p.plugins, p.functions)}},
		},
		GenerationConfig: geminiGenerationConfig{
			MaxOutputTokens: defaultMaxTokens,
		},
	}

	// Gemini uses the API key as a query parameter
	url := geminiAPIURLBase + p.model + ":generateContent?key=" + p.apiKey

	body, err := p.doJSONRequest(url, reqBody, nil)
	if err != nil {
		return "", err
	}

	var apiResp geminiResponse
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return "", fmt.Errorf("failed to parse response: %w", err)
	}

	if apiResp.Error != nil {
		return "", fmt.Errorf("API error: %s", apiResp.Error.Message)
	}

	if len(apiResp.Candidates) == 0 {
		return "", fmt.Errorf("empty response from API")
	}

	if len(apiResp.Candidates[0].Content.Parts) == 0 {
		return "", fmt.Errorf("empty content in response")
	}

	return extractCode(apiResp.Candidates[0].Content.Parts[0].Text), nil
}

// Compile-time interface check
var _ Provider = (*GeminiProvider)(nil)
