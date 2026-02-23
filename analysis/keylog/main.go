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

// Dangerous: format specifiers that could print key bytes
// %x, %v, %+v, %#v with key-related variable names
var dangerousFormatPatterns = []*regexp.Regexp{
	// Printing hex of something with "key" or "priv" in name
	regexp.MustCompile(`%x.*(?i)(private|priv|secret)key`),
	regexp.MustCompile(`(?i)(private|priv|secret)key.*%x`),
	// Printing %v of key material
	regexp.MustCompile(`%v.*(?i)(privatekey|privkey|secretkey)`),
	regexp.MustCompile(`(?i)(privatekey|privkey|secretkey).*%v`),
	// Printing mnemonic content (not just the word)
	regexp.MustCompile(`%[sv].*(?i)mnemonic[^s]`), // mnemonic but not mnemonics (list of handlers)
	regexp.MustCompile(`(?i)mnemonic[^s].*%[sv]`),
	// Printing entropy or seed bytes
	regexp.MustCompile(`%x.*(?i)\bentropy\b`),
	regexp.MustCompile(`(?i)\bentropy\b.*%x`),
}

// Very dangerous: directly printing key variables
var directKeyPrintPatterns = []*regexp.Regexp{
	// fmt.Println(privateKey) or similar
	regexp.MustCompile(`fmt\.(Print|Println)\((?i)(privatekey|privkey|secretkey|mnemonic)\)`),
	// log.Print(privateKey)
	regexp.MustCompile(`log\.(Print|Println)\((?i)(privatekey|privkey|secretkey|mnemonic)\)`),
}

// Patterns that look dangerous but are actually safe
var safePatterns = []*regexp.Regexp{
	// String literals with security terms (help text, error messages)
	regexp.MustCompile(`"[^"]*(?i)(mnemonic|seed|private|secret)[^"]*"`),
	// Talking about handlers, types, or counts
	regexp.MustCompile(`(?i)(handlers|providers|types|count|size|length)`),
	// Public key operations are fine
	regexp.MustCompile(`(?i)public`),
	// KeyType is metadata, not key material
	regexp.MustCompile(`(?i)keytype`),
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

		// Check for format specifier patterns
		for _, pat := range dangerousFormatPatterns {
			if pat.MatchString(line) {
				// Verify it's not a safe pattern
				isSafe := false

				// If the line is primarily a string literal (help text), skip it
				// Count quotes - if there are more string chars than code, likely safe
				stringContent := extractStringLiterals(line)
				if containsSecurityTerm(stringContent) && !containsFormatSpecInString(line) {
					isSafe = true
				}

				for _, safePat := range safePatterns {
					if safePat.MatchString(line) {
						// Check if the safe pattern explains the dangerous match
						isSafe = true
						break
					}
				}

				if !isSafe {
					findings = append(findings, finding{
						file:    path,
						line:    lineNum,
						content: line,
						reason:  "Potential key material in formatted output",
					})
				}
				break
			}
		}
	}

	return findings
}

// extractStringLiterals extracts all string literal content from a line
func extractStringLiterals(line string) string {
	var result strings.Builder
	inString := false
	escaped := false

	for _, ch := range line {
		if escaped {
			escaped = false
			if inString {
				result.WriteRune(ch)
			}
			continue
		}
		if ch == '\\' {
			escaped = true
			continue
		}
		if ch == '"' {
			inString = !inString
			continue
		}
		if inString {
			result.WriteRune(ch)
		}
	}

	return result.String()
}

// containsSecurityTerm checks if text contains security-related terms
func containsSecurityTerm(text string) bool {
	terms := []string{"mnemonic", "seed", "private", "secret", "key", "entropy"}
	lower := strings.ToLower(text)
	for _, term := range terms {
		if strings.Contains(lower, term) {
			return true
		}
	}
	return false
}

// containsFormatSpecInString checks if format specifiers appear to be formatting key material
func containsFormatSpecInString(line string) bool {
	// Look for patterns like: fmt.Printf("key: %x", privateKey)
	// where %x is inside a string but privateKey is outside
	return strings.Contains(line, "%x") || strings.Contains(line, "%v")
}
