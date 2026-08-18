// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

// Scripting, AI, and plugin execution commands

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/aplane-algo/aplane/internal/command"
	"github.com/aplane-algo/aplane/internal/docassets"

	"github.com/chzyer/readline"
)

// cmdJS executes JavaScript code in the REPL.
// Supports:
//   - js -help: print the JavaScript API reference
//   - js <file.js>, js { code }, js <inline>, and multi-line mode
func (r *REPLState) cmdJS(args []string, ctxRaw interface{}) (command.Result, error) {
	return newTerminalCommandResult(nil), r.runJS(args, ctxRaw)
}

func (r *REPLState) runJS(args []string, ctxRaw interface{}) error {
	var code string

	// Get raw args from context (preserves quotes that ParseCommand strips)
	ctx, _ := ctxRaw.(*command.Context)
	rawArgs := ""
	if ctx != nil {
		rawArgs = ctx.RawArgs
	}

	if len(args) > 0 && args[0] == "-help" {
		r.println(strings.TrimRight(docassets.UserJSAPI, "\n"))
		return nil
	}

	if len(args) == 0 {
		// Multi-line mode: read lines until blank line
		r.println("Enter JavaScript code (blank line to execute, Ctrl+C to cancel):")

		var lines []string
		if r.LineReader != nil {
			r.clearInputPrompt()
			for {
				line, err := r.readInteractiveLine()
				if err != nil {
					if errors.Is(err, readline.ErrInterrupt) {
						r.println("\nCancelled.")
						return nil
					}
					return err
				}
				if line == "" {
					break
				}
				lines = append(lines, line)
			}
		} else {
			scanner := bufio.NewScanner(os.Stdin)
			for scanner.Scan() {
				line := scanner.Text()
				if line == "" {
					break
				}
				lines = append(lines, line)
			}
			if err := scanner.Err(); err != nil {
				return err
			}
		}
		if len(lines) == 0 {
			return nil
		}
		code = strings.Join(lines, "\n")
	} else if strings.HasPrefix(rawArgs, "{") {
		// Brace-delimited mode: js { code here }
		// Use rawArgs to preserve quotes inside the braces
		inner := strings.TrimPrefix(rawArgs, "{")
		inner = strings.TrimSpace(inner)

		if strings.HasSuffix(inner, "}") {
			code = strings.TrimSuffix(inner, "}")
			code = strings.TrimSpace(code)
		} else {
			// Read more lines until we find closing brace
			lines := []string{inner}
			if r.LineReader != nil {
				r.clearInputPrompt()
				for {
					line, err := r.readInteractiveLine()
					if err != nil {
						if errors.Is(err, readline.ErrInterrupt) {
							r.println("\nCancelled.")
							return nil
						}
						return err
					}
					if strings.TrimSpace(line) == "}" {
						break
					}
					lines = append(lines, line)
				}
			} else {
				scanner := bufio.NewScanner(os.Stdin)
				for scanner.Scan() {
					line := scanner.Text()
					if strings.TrimSpace(line) == "}" {
						break
					}
					lines = append(lines, line)
				}
				if err := scanner.Err(); err != nil {
					return err
				}
			}
			code = strings.Join(lines, "\n")
		}
	} else if strings.HasSuffix(args[0], ".js") {
		// File mode: js script.js
		// Absolute paths are used as-is; bare filenames resolve to the scripts directory.
		scriptPath := args[0]
		if !filepath.IsAbs(scriptPath) {
			scriptPath = filepath.Join(r.DataDir, "scripts", scriptPath)
		}
		content, err := os.ReadFile(scriptPath)
		if err != nil {
			return fmt.Errorf("failed to read script: %w", err)
		}
		code = string(content)
	} else {
		// Inline mode: js <code>
		// Use rawArgs to preserve quotes
		if rawArgs != "" {
			code = rawArgs
		} else {
			code = strings.Join(args, " ")
		}
	}

	r.ensureJSRunner()

	// Run the code
	result, err := r.Scripts.Runner.RunWithContext(r.commandContext(), code)
	if err != nil {
		return err
	}

	r.Scripts.LastCode = code

	// Print result if not empty
	if !result.IsEmpty {
		switch v := result.Value.(type) {
		case map[string]interface{}, []interface{}:
			r.printf("%v\n", v)
		default:
			r.println(result.Value)
		}
	}

	return nil
}

// cmdJSSave saves JavaScript code to a file in the data directory's scripts/ folder.
// Usage: jssave [-f] <path> [-last | <javascript code>]
func (r *REPLState) cmdJSSave(args []string, ctxRaw interface{}) (command.Result, error) {
	return newTerminalCommandResult(nil), r.runJSSave(args, ctxRaw)
}

func (r *REPLState) runJSSave(_ []string, ctxRaw interface{}) error {
	ctx, _ := ctxRaw.(*command.Context)
	if ctx == nil || strings.TrimSpace(ctx.RawArgs) == "" {
		return fmt.Errorf("usage: jssave [-f] <path> [-last | <javascript code>]")
	}

	raw := strings.TrimSpace(ctx.RawArgs)

	overwrite := false
	if strings.HasPrefix(raw, "-f ") {
		overwrite = true
		raw = strings.TrimSpace(raw[3:])
	}

	parts := strings.SplitN(raw, " ", 2)
	if len(parts) < 2 || strings.TrimSpace(parts[1]) == "" {
		return fmt.Errorf("usage: jssave [-f] <path> [-last | <javascript code>]")
	}

	scriptPath := parts[0]
	code := parts[1]

	if strings.TrimSpace(code) == "-last" {
		if r.Scripts.LastCode == "" {
			return fmt.Errorf("no previously executed JavaScript code")
		}
		code = r.Scripts.LastCode
	}

	dest, err := saveJSScript(r.DataDir, scriptPath, code, overwrite)
	if err != nil {
		return err
	}

	r.printf("Saved to %s\n", dest)
	return nil
}

// cmdJSList lists saved JavaScript scripts in the data directory's scripts/ folder.
func (r *REPLState) cmdJSList(args []string, ctx interface{}) (command.Result, error) {
	return newTerminalCommandResult(nil), r.runJSList(args, ctx)
}

func (r *REPLState) runJSList(_ []string, _ interface{}) error {
	entries, err := listJSScripts(r.DataDir)
	if err != nil {
		return err
	}

	dir, err := jsScriptsDir(r.DataDir)
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		r.printf("No saved scripts in %s\n", dir)
		return nil
	}
	r.printf("Scripts in %s:\n", dir)
	for _, e := range entries {
		r.printf("  %s  %6d B  %s\n", e.Name, e.Size, time.Unix(e.MTime, 0).Format("2006-01-02 15:04"))
	}
	return nil
}

// jsScriptEntry describes a saved script file surfaced by jslist.
type jsScriptEntry struct {
	Name  string `json:"name"`
	Size  int64  `json:"size"`
	MTime int64  `json:"mtime"`
}

func jsScriptsDir(dataDir string) (string, error) {
	return filepath.Abs(filepath.Join(dataDir, "scripts"))
}

func normalizeJSScriptPath(dataDir, scriptPath string) (string, error) {
	scriptsDir, err := jsScriptsDir(dataDir)
	if err != nil {
		return "", err
	}

	scriptPath = strings.TrimSpace(scriptPath)
	if scriptPath == "" {
		return "", fmt.Errorf("path is required")
	}

	var dest string
	if strings.Contains(scriptPath, "/") {
		if !strings.HasPrefix(scriptPath, "/") {
			return "", fmt.Errorf("path with '/' must be absolute (must start with '/')")
		}
		dest = filepath.Clean(scriptPath)
	} else {
		dest = filepath.Join(scriptsDir, scriptPath)
	}
	if !strings.HasSuffix(dest, ".js") {
		dest += ".js"
	}
	return dest, nil
}

// saveJSScript writes code to an absolute path under dataDir/scripts/.
// Returns the final absolute path written.
func saveJSScript(dataDir, scriptPath, code string, overwrite bool) (string, error) {
	dest, err := normalizeJSScriptPath(dataDir, scriptPath)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0755); err != nil {
		return "", fmt.Errorf("failed to create scripts directory: %w", err)
	}
	if !overwrite {
		if _, err := os.Stat(dest); err == nil {
			return "", fmt.Errorf("%s already exists (use -f to overwrite)", dest)
		}
	}
	if err := os.WriteFile(dest, []byte(code+"\n"), 0644); err != nil {
		return "", fmt.Errorf("failed to write %s: %w", dest, err)
	}
	return dest, nil
}

// listJSScripts returns saved scripts in dataDir/scripts/ sorted by path.
func listJSScripts(dataDir string) ([]jsScriptEntry, error) {
	dir, err := jsScriptsDir(dataDir)
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []jsScriptEntry
	for _, e := range raw {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".js") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, jsScriptEntry{
			Name:  e.Name(),
			Size:  info.Size(),
			MTime: info.ModTime().Unix(),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// runShellCommand executes a shell command (used by ! prefix).
func (r *REPLState) runShellCommand(cmdStr string) error {
	if cmdStr == "" {
		return nil
	}

	// Execute via sh -c to support pipes, redirects, etc.
	cmd := exec.Command("sh", "-c", cmdStr)
	cmd.Stdout = r.Out
	cmd.Stderr = r.Out
	cmd.Stdin = os.Stdin

	err := cmd.Run()
	if err != nil {
		// Don't treat non-zero exit as error, just show it happened
		if exitErr, ok := err.(*exec.ExitError); ok {
			r.printf("(exit %d)\n", exitErr.ExitCode())
			return nil
		}
		return fmt.Errorf("failed to execute command: %w", err)
	}

	return nil
}
