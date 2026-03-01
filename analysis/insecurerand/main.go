// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

// Package main implements a static analyzer that detects insecure random number usage.
//
// This analyzer ensures that crypto/rand is used instead of math/rand
// in security-sensitive code paths.
package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Directories that should never use math/rand
var criticalDirs = []string{
	"internal/signing",
	"internal/crypto",
	"internal/keygen",
	"internal/mnemonic",
	"lsig",
}

// Patterns indicating math/rand import (the actual problem)
var mathRandImportPatterns = []*regexp.Regexp{
	regexp.MustCompile(`"math/rand"`),
	regexp.MustCompile(`"math/rand/v2"`),
}

// Patterns indicating crypto/rand import (correct usage)
var cryptoRandImportPattern = regexp.MustCompile(`"crypto/rand"`)

// Patterns that are only problematic with math/rand (not crypto/rand)
var mathRandOnlyPatterns = []*regexp.Regexp{
	regexp.MustCompile(`rand\.Seed`),
	regexp.MustCompile(`rand\.Intn\(`),
	regexp.MustCompile(`rand\.Int31`),
	regexp.MustCompile(`rand\.Int63`),
	regexp.MustCompile(`rand\.Float`),
	regexp.MustCompile(`rand\.Perm`),
	regexp.MustCompile(`rand\.Shuffle`),
	regexp.MustCompile(`rand\.New\(rand\.NewSource`),
	regexp.MustCompile(`rand\.NewSource`),
}

type finding struct {
	file    string
	line    int
	content string
	reason  string
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: insecurerand <repo-root>")
		os.Exit(1)
	}

	root := os.Args[1]
	var findings []finding
	var filesChecked int

	for _, dir := range criticalDirs {
		dirPath := filepath.Join(root, dir)
		if _, err := os.Stat(dirPath); os.IsNotExist(err) {
			continue
		}

		err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}

			if info.IsDir() {
				return nil
			}

			if !strings.HasSuffix(path, ".go") {
				return nil
			}

			if strings.Contains(path, "_test.go") {
				return nil
			}

			filesChecked++
			fileFindings := checkFile(path)
			findings = append(findings, fileFindings...)
			return nil
		})

		if err != nil {
			fmt.Fprintf(os.Stderr, "Error walking %s: %v\n", dir, err)
		}
	}

	// Report results
	fmt.Printf("Insecure Random Analysis\n")
	fmt.Printf("========================\n")
	fmt.Printf("Files checked: %d\n", filesChecked)
	fmt.Printf("Critical directories: %v\n\n", criticalDirs)

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

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	// First pass: check imports
	hasMathRandImport := false
	hasCryptoRandImport := false
	mathRandImportLine := 0
	mathRandImportContent := ""

	for i, line := range lines {
		lineNum := i + 1

		for _, pat := range mathRandImportPatterns {
			if pat.MatchString(line) {
				hasMathRandImport = true
				mathRandImportLine = lineNum
				mathRandImportContent = line
				break
			}
		}

		if cryptoRandImportPattern.MatchString(line) {
			hasCryptoRandImport = true
		}
	}

	// If file imports math/rand in a critical directory, flag the import
	if hasMathRandImport {
		findings = append(findings, finding{
			file:    path,
			line:    mathRandImportLine,
			content: mathRandImportContent,
			reason:  "math/rand import in security-critical directory - use crypto/rand instead",
		})
	}

	// Second pass: check for math/rand-only function calls (even if import was aliased)
	// Only flag these if we don't have crypto/rand imported
	if !hasCryptoRandImport {
		for i, line := range lines {
			lineNum := i + 1

			// Skip comments
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "//") {
				continue
			}

			for _, pat := range mathRandOnlyPatterns {
				if pat.MatchString(line) {
					findings = append(findings, finding{
						file:    path,
						line:    lineNum,
						content: line,
						reason:  "math/rand function in security-critical code without crypto/rand import",
					})
					break
				}
			}
		}
	}

	return findings
}
