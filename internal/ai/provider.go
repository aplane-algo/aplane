// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

// Package ai provides integration with LLM APIs for generating JavaScript code.
package ai

import (
	"fmt"
	"os"
	"strings"
)

// Provider is the interface for AI code generation providers.
type Provider interface {
	// GenerateCode generates JavaScript code from a natural language prompt.
	GenerateCode(prompt string) (string, error)

	// Name returns the provider name for display.
	Name() string

	// SetPlugins sets the plugin information for dynamic prompt generation.
	SetPlugins(plugins []PluginInfo)

	// SetFunctions sets the typed function information for dynamic prompt generation.
	SetFunctions(functions []FunctionInfo)
}

// Config holds configuration for creating a provider.
type Config struct {
	// Model name (required). Provider is detected from model prefix:
	// claude-* -> Anthropic, gpt-*/o1*/o3* -> OpenAI, gemini-* -> Gemini
	Model string
}

// NewProvider creates a provider based on configuration.
// Requires config.Model to be set explicitly.
func NewProvider(config Config) (Provider, error) {
	if config.Model == "" {
		return nil, fmt.Errorf("ai disabled: ai_model not set")
	}

	apiKey := os.Getenv("AI_API_KEY")
	if apiKey == "" {
		return nil, fmt.Errorf("ai disabled: AI_API_KEY not set")
	}

	// Detect provider from model name
	provider := detectProviderFromModel(config.Model)
	if provider == "" {
		return nil, fmt.Errorf("ai disabled: unknown model %q (expected claude-*, gpt-*, o1-*, o3-*, or gemini-*)", config.Model)
	}

	switch provider {
	case "anthropic":
		return NewAnthropicProvider(apiKey, config.Model)
	case "openai":
		return NewOpenAIProvider(apiKey, config.Model)
	case "gemini":
		return NewGeminiProvider(apiKey, config.Model)
	default:
		return nil, fmt.Errorf("ai disabled: unknown provider %q", provider)
	}
}

// detectProviderFromModel determines the provider based on model name prefix.
func detectProviderFromModel(model string) string {
	model = strings.ToLower(model)
	switch {
	case strings.HasPrefix(model, "claude-"):
		return "anthropic"
	case strings.HasPrefix(model, "gpt-"), strings.HasPrefix(model, "o1-"), strings.HasPrefix(model, "o3-"), strings.HasPrefix(model, "o1"), strings.HasPrefix(model, "o3"):
		return "openai"
	case strings.HasPrefix(model, "gemini-"):
		return "gemini"
	default:
		return ""
	}
}

// aiGeneratedHeader is prepended to all AI-generated code.
const aiGeneratedHeader = "// AI Generated Code. This is experimental. Please check carefully before running.\n\n"

// extractCode extracts JavaScript code from markdown code blocks if present.
func extractCode(text string) string {
	text = strings.TrimSpace(text)

	var code string
	markers := []string{"```javascript", "```js", "```"}
	for _, marker := range markers {
		if idx := strings.Index(text, marker); idx != -1 {
			start := idx + len(marker)
			if end := strings.Index(text[start:], "```"); end != -1 {
				code = strings.TrimSpace(text[start : start+end])
				break
			}
		}
	}

	if code == "" {
		code = text
	}

	return aiGeneratedHeader + code
}
