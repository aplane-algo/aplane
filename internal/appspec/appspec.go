// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package appspec

import (
	"crypto/sha512"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	abi "github.com/algorand/avm-abi/abi"

	"github.com/aplane-algo/aplane/internal/appinput"
)

type Contract struct {
	Name    string   `json:"name"`
	Desc    string   `json:"desc,omitempty"`
	Methods []Method `json:"methods"`
}

type Method struct {
	Name    string       `json:"name"`
	Args    []MethodArg  `json:"args"`
	Returns MethodReturn `json:"returns"`
	Desc    string       `json:"desc,omitempty"`
}

type MethodArg struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

type MethodReturn struct {
	Type string `json:"type"`
}

func Load(path string) (*Contract, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read ABI file: %w", err)
	}

	var contract Contract
	if err := json.Unmarshal(data, &contract); err != nil {
		return nil, fmt.Errorf("failed to decode ABI file: %w", err)
	}

	if len(contract.Methods) == 0 {
		return nil, fmt.Errorf("ABI file contains no methods")
	}

	for _, method := range contract.Methods {
		for _, arg := range method.Args {
			if err := validateABIType(arg.Type); err != nil {
				return nil, err
			}
		}
		if err := validateABIType(method.Returns.Type); err != nil {
			return nil, err
		}
		if err := abi.VerifyMethodSignature(method.Signature()); err != nil {
			return nil, fmt.Errorf("invalid ABI method %q: %w", method.Signature(), err)
		}
	}

	return &contract, nil
}

func (m Method) Signature() string {
	argTypes := make([]string, 0, len(m.Args))
	for _, arg := range m.Args {
		argTypes = append(argTypes, arg.Type)
	}
	return fmt.Sprintf("%s(%s)%s", m.Name, strings.Join(argTypes, ","), m.Returns.Type)
}

func (m Method) Selector() []byte {
	sum := sha512.Sum512_256([]byte(m.Signature()))
	return sum[:4]
}

// SignatureSelector returns the ARC-4 selector for a full method signature
// after verifying the signature is well-formed.
func SignatureSelector(signature string) ([]byte, error) {
	if err := abi.VerifyMethodSignature(signature); err != nil {
		return nil, err
	}
	sum := sha512.Sum512_256([]byte(signature))
	return sum[:4], nil
}

func (c *Contract) ResolveMethod(ref string) (*Method, error) {
	if ref == "" {
		return nil, fmt.Errorf("method name is required")
	}

	if strings.Contains(ref, "(") {
		for i := range c.Methods {
			if c.Methods[i].Signature() == ref {
				return &c.Methods[i], nil
			}
		}
		return nil, fmt.Errorf("method %q not found in ABI", ref)
	}

	var matches []*Method
	for i := range c.Methods {
		if c.Methods[i].Name == ref {
			matches = append(matches, &c.Methods[i])
		}
	}

	switch len(matches) {
	case 0:
		return nil, fmt.Errorf("method %q not found in ABI", ref)
	case 1:
		return matches[0], nil
	default:
		signatures := make([]string, 0, len(matches))
		for _, method := range matches {
			signatures = append(signatures, method.Signature())
		}
		return nil, fmt.Errorf("method %q is overloaded; use full signature: %s", ref, strings.Join(signatures, ", "))
	}
}

func (m Method) EncodeArgs(rawArgs []string) ([][]byte, error) {
	if len(rawArgs) != len(m.Args) {
		return nil, fmt.Errorf("method %s expects %d args, got %d", m.Signature(), len(m.Args), len(rawArgs))
	}

	encoded := make([][]byte, 0, len(rawArgs)+1)
	encoded = append(encoded, m.Selector())

	for i, arg := range m.Args {
		abiType, err := abi.TypeOf(arg.Type)
		if err != nil {
			return nil, fmt.Errorf("invalid ABI type %q for arg %q: %w", arg.Type, arg.Name, err)
		}

		value, err := parseArgValue(arg.Type, rawArgs[i])
		if err != nil {
			return nil, fmt.Errorf("invalid arg %q (%s): %w", arg.Name, arg.Type, err)
		}

		argBytes, err := abiType.Encode(value)
		if err != nil {
			return nil, fmt.Errorf("failed to encode arg %q (%s): %w", arg.Name, arg.Type, err)
		}
		encoded = append(encoded, argBytes)
	}

	return encoded, nil
}

var staticByteArrayRE = regexp.MustCompile(`^byte\[(\d+)]$`)

func validateABIType(typeName string) error {
	match := staticByteArrayRE.FindStringSubmatch(typeName)
	if len(match) != 2 {
		return nil
	}
	if _, err := strconv.ParseUint(match[1], 10, 16); err != nil {
		return fmt.Errorf("invalid static byte array type %q: size must be between 0 and 65535", typeName)
	}
	return nil
}

func parseArgValue(typeName, raw string) (interface{}, error) {
	if err := validateABIType(typeName); err != nil {
		return nil, err
	}
	if isByteArrayType(typeName) {
		return parseByteValue(raw)
	}

	if typeName == "string" {
		if strings.HasPrefix(raw, "json:") {
			abiType, _ := abi.TypeOf(typeName)
			return abiType.UnmarshalFromJSON([]byte(strings.TrimPrefix(raw, "json:")))
		}
		return raw, nil
	}

	payload := strings.TrimPrefix(raw, "json:")

	switch {
	case typeName == "address":
		if strings.HasPrefix(payload, `"`) {
			break
		}
		payload = strconv.Quote(payload)
	case strings.HasPrefix(typeName, "uint"), strings.HasPrefix(typeName, "ufixed"), typeName == "bool":
		// Raw scalar JSON is already fine.
	default:
		if !strings.HasPrefix(payload, "[") && !strings.HasPrefix(payload, "{") && !strings.HasPrefix(payload, `"`) {
			return nil, fmt.Errorf("use json:<value> for ABI type %s", typeName)
		}
	}

	abiType, err := abi.TypeOf(typeName)
	if err != nil {
		return nil, err
	}

	value, err := abiType.UnmarshalFromJSON([]byte(payload))
	if err != nil {
		return nil, err
	}
	return value, nil
}

func isByteArrayType(typeName string) bool {
	if typeName == "byte[]" {
		return true
	}
	return staticByteArrayRE.MatchString(typeName)
}

func parseByteValue(raw string) ([]byte, error) {
	return appinput.ParseByteValue(raw)
}
