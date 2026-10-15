// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package main implements a static analyzer that detects potential key material in logs or errors.
//
// This analyzer scans for logging statements or error messages that might
// accidentally include private key material via format specifiers.
package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// A formatted line is dangerous when a string literal on it holds a verb that
// renders a value's contents and an identifier outside the string literals
// names key material. Matching identifiers, not raw text, keeps the words in a
// message ("private key: %x") from vouching for the argument that follows it.
var (
	contentFormatVerb = regexp.MustCompile(`%[-+# 0-9.]*[xXvsq]`)
	identifierToken   = regexp.MustCompile(`[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*`)
	sensitiveName     = regexp.MustCompile(`(?i)(privatekey|privkey|secretkey|mnemonic|entropy|seed)`)
	camelWord         = regexp.MustCompile(`[A-Z]?[a-z0-9]+|[A-Z]+(?:[A-Z][a-z]|$|[0-9])?`)
)

// benignWords mark an identifier that names something about key material
// rather than the material itself (publicKey, mnemonicType, seedLen).
var benignWords = map[string]bool{
	"public": true, "pub": true, "type": true, "types": true, "count": true,
	"size": true, "len": true, "length": true, "handler": true, "handlers": true,
	"provider": true, "providers": true, "mnemonics": true, "words": true,
	"word": true, "path": true, "file": true, "dir": true, "name": true,
	"label": true, "param": true, "params": true, "version": true,
	"fingerprint": true, "id": true, "ids": true,
}

// Very dangerous: directly printing key variables
var directKeyPrintPatterns = []*regexp.Regexp{
	// fmt.Println(privateKey) or similar
	regexp.MustCompile(`fmt\.(Print|Println)\((?i)(privatekey|privkey|secretkey|mnemonic)\)`),
	// log.Print(privateKey)
	regexp.MustCompile(`log\.(Print|Println)\((?i)(privatekey|privkey|secretkey|mnemonic)\)`),
}

// Lines that are safe whatever identifiers they mention.
var safeLinePatterns = []*regexp.Regexp{
	// Struct field assignments (for encrypted storage, not logging)
	regexp.MustCompile(`^\s*\w+:\s+fmt\.Sprintf`),
}

// Files that intentionally output key material to the user (not logging).
// These are CLI commands where the user explicitly requests to see the key/mnemonic.
var exemptFiles = map[string]string{
	"cmd/apadmin/batch.go": "generate-mnemonic command intentionally outputs mnemonic to user",
}

// Specific line patterns that are known safe despite matching dangerous patterns.
// Key: file path suffix, Value: patterns that are exempt in that file
var exemptPatterns = map[string][]*regexp.Regexp{
	"internal/keygen/": {
		// Struct field assignment for encrypted storage
		regexp.MustCompile(`PrivateKeyHex:\s+fmt\.Sprintf`),
	},
}

type finding struct {
	file    string
	line    int
	content string
	reason  string
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: keylog <repo-root>")
		os.Exit(1)
	}

	root := os.Args[1]
	var findings []finding
	var filesChecked int

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			base := filepath.Base(path)
			if base == "vendor" || base == ".git" || base == "node_modules" || base == "analysis" {
				return filepath.SkipDir
			}
			return nil
		}

		if !strings.HasSuffix(path, ".go") {
			return nil
		}

		if strings.Contains(path, "_test.go") {
			return nil
		}

		// Check if file is exempt (intentionally outputs key material)
		for exemptPath := range exemptFiles {
			if strings.HasSuffix(path, exemptPath) {
				return nil
			}
		}

		filesChecked++
		fileFindings := checkFile(path)
		findings = append(findings, fileFindings...)
		return nil
	})

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error walking directory: %v\n", err)
		os.Exit(2)
	}

	// Report results
	fmt.Printf("Key Logging Analysis\n")
	fmt.Printf("====================\n")
	fmt.Printf("Files checked: %d\n\n", filesChecked)

	if len(findings) == 0 {
		fmt.Println("No issues found.")
		os.Exit(0)
	}

	fmt.Printf("Potential issues: %d\n\n", len(findings))
	for _, f := range findings {
		fmt.Printf("%s:%d\n", f.file, f.line)
		fmt.Printf("  Line: %s\n", strings.TrimSpace(f.content))
		fmt.Printf("  Issue: %s\n\n", f.reason)
	}

	os.Exit(1)
}

func checkFile(path string) []finding {
	var findings []finding

	file, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer func() { _ = file.Close() }()

	// Collect applicable exempt patterns for this file
	var fileExemptPatterns []*regexp.Regexp
	for pathPrefix, patterns := range exemptPatterns {
		if strings.Contains(path, pathPrefix) {
			fileExemptPatterns = append(fileExemptPatterns, patterns...)
		}
	}

	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		// Skip comments
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") {
			continue
		}

		// Check if line matches any exempt pattern for this file
		isExempt := false
		for _, pat := range fileExemptPatterns {
			if pat.MatchString(line) {
				isExempt = true
				break
			}
		}
		if isExempt {
			continue
		}

		// Check for direct key printing (most dangerous)
		for _, pat := range directKeyPrintPatterns {
			if pat.MatchString(line) {
				findings = append(findings, finding{
					file:    path,
					line:    lineNum,
					content: line,
					reason:  "Direct printing of key material variable",
				})
				continue
			}
		}

		if name := sensitiveFormattedName(line); name != "" {
			findings = append(findings, finding{
				file:    path,
				line:    lineNum,
				content: line,
				reason:  "Potential key material in formatted output: " + name,
			})
		}
	}

	return findings
}

// sensitiveFormattedName returns the first identifier on a formatting line
// that names key material, or "" when the line formats nothing or names none.
func sensitiveFormattedName(line string) string {
	for _, pat := range safeLinePatterns {
		if pat.MatchString(line) {
			return ""
		}
	}
	literals, code := splitStringLiterals(line)
	if !contentFormatVerb.MatchString(literals) {
		return ""
	}
	for _, name := range identifierToken.FindAllString(code, -1) {
		last := name[strings.LastIndex(name, ".")+1:]
		if sensitiveName.MatchString(last) && !namesAboutKeyMaterial(last) {
			return name
		}
	}
	return ""
}

// namesAboutKeyMaterial reports whether an identifier's words include one that
// names metadata (a type, count, path...) rather than the material itself.
func namesAboutKeyMaterial(identifier string) bool {
	for _, part := range strings.Split(identifier, "_") {
		for _, word := range camelWord.FindAllString(part, -1) {
			if benignWords[strings.ToLower(word)] {
				return true
			}
		}
	}
	return false
}

// splitStringLiterals separates a line into the contents of its string
// literals (interpreted and raw) and the code outside them, dropping a
// trailing // comment. Code keeps a space where each literal was.
func splitStringLiterals(line string) (literals, code string) {
	var lit, out strings.Builder
	var quote rune
	escaped := false
	runes := []rune(line)
	for i := 0; i < len(runes); i++ {
		ch := runes[i]
		switch {
		case quote != 0:
			if escaped {
				escaped = false
				lit.WriteRune(ch)
				continue
			}
			if ch == '\\' && quote == '"' {
				escaped = true
				continue
			}
			if ch == quote {
				quote = 0
				lit.WriteRune(' ')
				out.WriteRune(' ')
				continue
			}
			lit.WriteRune(ch)
		case ch == '"' || ch == '`':
			quote = ch
		case ch == '\'':
			// A rune literal: skip to its closing quote.
			for i++; i < len(runes) && runes[i] != '\''; i++ {
				if runes[i] == '\\' {
					i++
				}
			}
		case ch == '/' && i+1 < len(runes) && runes[i+1] == '/':
			return lit.String(), out.String()
		default:
			out.WriteRune(ch)
		}
	}
	return lit.String(), out.String()
}
