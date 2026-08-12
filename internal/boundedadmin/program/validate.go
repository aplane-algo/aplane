// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package program structurally validates frozen bounded1 LogicSig bytecode.
package program

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	boundedmessage "github.com/aplane-algo/aplane/internal/boundedadmin/message"
	"github.com/aplane-algo/aplane/internal/boundedmeta"
	sentrymessage "github.com/aplane-algo/aplane/internal/sentry/message"
	"github.com/aplane-algo/aplane/internal/txeffects"
)

var bounded1ContractManifest = txeffects.Bounded1Manifest()

const invalidOpcodeSize = 255

// avmOpcodeSizes is generated from go-algorand's langspec_v12.json. Zero
// identifies variable-width opcodes handled explicitly. TEAL v13 retains
// these fixed sizes except that b/bz/bnz/callsub use signed varint offsets;
// decodeProgram selects that encoding from the program version.
var avmOpcodeSizes = [256]uint8{
	1, 1, 1, 1, 1, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	0, 2, 1, 1, 1, 1, 0, 2, 1, 1, 1, 1, 2, 1, 1, 1,
	1, 2, 2, 3, 2, 2, 3, 4, 2, 3, 3, 2, 2, 1, 1, 1,
	3, 3, 3, 1, 1, 2, 2, 2, 1, 1, 1, 2, 1, 1, 2, 2,
	1, 3, 1, 1, 1, 1, 1, 3, 1, 1, 1, 1, 2, 1, 2, 2,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 255, 255, 255, 255, 255, 255,
	2, 2, 2, 2, 2, 1, 255, 255, 1, 255, 255, 255, 255, 255, 255, 255,
	0, 0, 0, 0, 1, 1, 255, 255, 3, 1, 3, 2, 2, 0, 0, 255,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 255, 255, 255, 255, 255, 255, 255,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 2, 1, 2, 3, 1, 3, 4, 1, 1, 1, 1, 1, 1, 1,
	2, 3, 2, 1, 1, 2, 3, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	2, 2, 1, 1, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	2, 2, 2, 2, 2, 2, 2, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
}

var fixedOpcodeNames = map[byte]string{
	0x00: "err", 0x03: "sha512_256", 0x0d: ">", 0x0e: "<=", 0x10: "&&", 0x11: "||", 0x12: "==", 0x13: "!=", 0x15: "len",
	0x31: "txn", 0x32: "global", 0x40: "bnz", 0x41: "bz", 0x42: "b", 0x43: "return", 0x44: "assert",
	0x48: "pop", 0x50: "concat", 0x85: "falcon_verify", 0x88: "callsub", 0x89: "retsub",
	0x8d: "switch", 0x8e: "match",
}

var txnFields = map[byte]string{
	0: "Sender", 1: "Fee", 7: "Receiver", 8: "Amount", 9: "CloseRemainderTo",
	16: "TypeEnum", 17: "XferAsset", 18: "AssetAmount", 19: "AssetSender", 20: "AssetReceiver", 21: "AssetCloseTo", 23: "TxID", 32: "RekeyTo",
}

var globalFields = map[byte]string{3: "ZeroAddress"}

// Expected is the composer-owned structure and operands required at the
// authentication and contract-admin verification sites.
type Expected struct {
	SpendingPublicKey []byte
	SentryPublicKey   []byte
	AdminPublicKey    []byte
	ProgramBinding    []byte
	BaseArgCount      int
	SentryArgIndex    int
	AdminArgIndex     int
	MaxFee            uint64
	SpendEffects      []string
}

// Validate disassembles AVM bytecode and proves the frozen composer-owned
// control-flow regions. Layer 3 remains opaque but must lead to the same final
// accept block and cannot contain its own return.
func Validate(bytecode []byte, expected Expected) error {
	if err := validateExpected(expected); err != nil {
		return err
	}
	version, used := binary.Uvarint(bytecode)
	if used <= 0 {
		return fmt.Errorf("invalid AVM version prefix")
	}
	parsed, err := decodeProgramUnambiguously(bytecode, version)
	if err != nil {
		return fmt.Errorf("bounded1 program validation failed: %w", err)
	}
	if err := validateDecoded(parsed, expected); err != nil {
		return fmt.Errorf("bounded1 program validation failed: %w", err)
	}
	return nil
}

func validateDecoded(parsed disassembly, expected Expected) error {
	if parsed.version != bounded1ContractManifest.TEALVersion {
		return fmt.Errorf("bounded1 program version %d invalid (expected %d)", parsed.version, bounded1ContractManifest.TEALVersion)
	}

	auth := []pattern{
		exact("txn", "TxID"), exact("arg", "0"), bytesValue(expected.SpendingPublicKey),
		exact("falcon_verify"), exact("assert"),
	}
	authAt, count := findUnique(parsed.instructions, auth)
	if count != 1 {
		return fmt.Errorf("bounded1 spending authentication site count %d invalid", count)
	}
	for _, instruction := range parsed.instructions[:authAt] {
		if instruction.name != "pushbytes" && instruction.name != "pop" {
			return fmt.Errorf("unexpected executable instruction %q before bounded1 authentication", instruction.name)
		}
	}

	feeAt := authAt + len(auth)
	fee := []pattern{exact("txn", "Fee"), intValue(expected.MaxFee), exact("<="), exact("assert")}
	if !matchesAt(parsed.instructions, feeAt, fee) {
		return fmt.Errorf("bounded1 fee gate is not immediately after authentication")
	}

	rekeyDispatch := []pattern{
		exact("txn", "RekeyTo"), exact("global", "ZeroAddress"), exact("!="), branch("bnz"),
	}
	dispatchAt, count := findUnique(parsed.instructions, rekeyDispatch)
	if count != 1 || dispatchAt != feeAt+len(fee) {
		return fmt.Errorf("bounded1 rekey dispatch is missing or misplaced")
	}
	rekeyTarget, ok := parsed.labels[parsed.instructions[dispatchAt+3].args[0]]
	if !ok {
		return fmt.Errorf("bounded1 rekey branch target is invalid")
	}

	prefix, err := boundedmessage.Prefix(boundedmessage.OperationRekey, expected.ProgramBinding)
	if err != nil {
		return err
	}
	rekeyBody := []pattern{
		exact("txn", "TypeEnum"), intValue(1), exact("=="), exact("assert"),
		exact("txn", "Amount"), intValue(0), exact("=="), exact("assert"),
		exact("txn", "Receiver"), exact("txn", "Sender"), exact("=="), exact("assert"),
		exact("txn", "RekeyTo"), exact("global", "ZeroAddress"), exact("!="), exact("assert"),
	}
	rekeyBody = append(rekeyBody, dangerAssertions()...)
	rekeyBody = append(rekeyBody,
		exact("arg", strconv.Itoa(expected.AdminArgIndex)), exact("len"), intValue(0), exact(">"), exact("assert"),
		exact("arg", strconv.Itoa(expected.AdminArgIndex)), exact("len"), intValue(uint64(boundedmeta.FalconAdminSignatureSize)), exact("<="), exact("assert"),
		bytesValue(prefix), exact("txn", "TxID"), exact("concat"), exact("sha512_256"),
		exact("arg", strconv.Itoa(expected.AdminArgIndex)), bytesValue(expected.AdminPublicKey),
		exact("falcon_verify"), exact("assert"), branch("b"),
	)
	if !matchesAt(parsed.instructions, rekeyTarget, rekeyBody) {
		return fmt.Errorf("bounded1 pure-rekey or contract-admin verification region does not match the frozen structure")
	}
	acceptLabel := parsed.instructions[rekeyTarget+len(rekeyBody)-1].args[0]
	acceptAt, ok := parsed.labels[acceptLabel]
	if !ok || !matchesAt(parsed.instructions, acceptAt, []pattern{intValue(1), exact("return")}) {
		return fmt.Errorf("bounded1 rekey path does not reach the frozen accept block")
	}

	spendGate := dangerAssertions()
	payBranch := len(spendGate) + 3
	spendGate = append(spendGate,
		exact("txn", "TypeEnum"), intValue(1), exact("=="), branch("bnz"),
	)
	axferBranch := len(spendGate) + 3
	spendGate = append(spendGate,
		exact("txn", "TypeEnum"), intValue(4), exact("=="), branch("bnz"), exact("err"),
	)
	payAt := len(spendGate)
	spendGate = append(spendGate, spendEffectDecision(expectedAllowsSpendEffect(expected, boundedmeta.SpendEffectPay))...)
	axferAt := len(spendGate)
	spendGate = append(spendGate,
		exact("txn", "AssetAmount"), intValue(0), exact("=="),
		exact("txn", "AssetReceiver"), exact("txn", "Sender"), exact("=="), exact("&&"), branch("bnz"),
	)
	optInBranch := len(spendGate) - 1
	spendGate = append(spendGate, spendEffectDecision(expectedAllowsSpendEffect(expected, boundedmeta.SpendEffectAxfer))...)
	optInAt := len(spendGate)
	spendGate = append(spendGate, spendEffectDecision(expectedAllowsSpendEffect(expected, boundedmeta.SpendEffectAssetOptIn))...)
	spendBranchAt := dispatchAt + len(rekeyDispatch)
	if !matchesAt(parsed.instructions, spendBranchAt, spendGate) || spendBranchAt+len(spendGate) != rekeyTarget {
		return fmt.Errorf("bounded1 pure-spend effect/type gate does not match the frozen structure")
	}
	payTarget, payTargetOK := branchTarget(parsed, spendBranchAt+payBranch)
	axferTarget, axferTargetOK := branchTarget(parsed, spendBranchAt+axferBranch)
	optInTarget, optInTargetOK := branchTarget(parsed, spendBranchAt+optInBranch)
	if !payTargetOK || !axferTargetOK || !optInTargetOK ||
		payTarget != spendBranchAt+payAt || axferTarget != spendBranchAt+axferAt || optInTarget != spendBranchAt+optInAt {
		return fmt.Errorf("bounded1 spend-effect dispatch target is invalid")
	}
	spendAt := -1
	for _, decisionAt := range []int{payAt, axferAt + 8, optInAt} {
		instruction := parsed.instructions[spendBranchAt+decisionAt]
		if instruction.name != "b" {
			continue
		}
		target, targetOK := branchTarget(parsed, spendBranchAt+decisionAt)
		if !targetOK {
			return fmt.Errorf("bounded1 spend-effect branch target is invalid")
		}
		if spendAt >= 0 && target != spendAt {
			return fmt.Errorf("bounded1 spend effects do not share one Layer-3 boundary")
		}
		spendAt = target
	}
	ok = spendAt >= 0
	if !ok || spendAt <= rekeyTarget || spendAt >= acceptAt {
		return fmt.Errorf("bounded1 pure-spend boundary is invalid")
	}
	layer3At := spendAt
	if len(expected.SentryPublicKey) != 0 {
		sentryGate := []pattern{
			exact("arg", strconv.Itoa(expected.SentryArgIndex)), exact("len"), intValue(0), exact(">"), exact("assert"),
			exact("arg", strconv.Itoa(expected.SentryArgIndex)), exact("len"), intValue(uint64(boundedmeta.SentrySignatureMaxSizeV1)), exact("<="), exact("assert"),
			bytesValue([]byte(sentrymessage.DomainTagV1)), bytesValue([]byte{byte(sentrymessage.RoleSentry)}), exact("concat"),
			exact("txn", "TxID"), exact("concat"), exact("sha512_256"),
			exact("arg", strconv.Itoa(expected.SentryArgIndex)), bytesValue(expected.SentryPublicKey),
			exact("falcon_verify"), exact("assert"), branch("b"),
		}
		if !matchesAt(parsed.instructions, spendAt, sentryGate) {
			return fmt.Errorf("bounded1 sentry verification region does not match the frozen structure")
		}
		var targetOK bool
		layer3At, targetOK = branchTarget(parsed, spendAt+len(sentryGate)-1)
		if !targetOK || layer3At != spendAt+len(sentryGate) || layer3At >= acceptAt {
			return fmt.Errorf("bounded1 sentry verification does not reach the Layer-3 boundary")
		}
	} else if matchesFrameworkSentryGateAt(parsed.instructions, spendAt) {
		return fmt.Errorf("bounded1 sentry verification region is present without sentry metadata")
	}
	if err := validateLayer3ControlFlow(parsed, layer3At, acceptAt); err != nil {
		return fmt.Errorf("bounded1 Layer-3 control flow is invalid: %w", err)
	}
	return nil
}

func validateExpected(expected Expected) error {
	if len(expected.SpendingPublicKey) != boundedmeta.FalconAdminPublicKeySize {
		return fmt.Errorf("falcon spending public key length %d invalid", len(expected.SpendingPublicKey))
	}
	if len(expected.AdminPublicKey) != boundedmeta.FalconAdminPublicKeySize {
		return fmt.Errorf("contract admin public key length %d invalid", len(expected.AdminPublicKey))
	}
	if len(expected.ProgramBinding) != boundedmeta.ProgramBindingSize {
		return fmt.Errorf("program binding length %d invalid", len(expected.ProgramBinding))
	}
	if expected.BaseArgCount != 1 {
		return fmt.Errorf("bounded1 Falcon base argument count %d invalid", expected.BaseArgCount)
	}
	if expected.AdminArgIndex < expected.BaseArgCount || expected.AdminArgIndex > 255 {
		return fmt.Errorf("bounded1 contract-admin argument index %d invalid", expected.AdminArgIndex)
	}
	if len(expected.SentryPublicKey) == 0 {
		if expected.SentryArgIndex != 0 {
			return fmt.Errorf("bounded1 sentry argument index is present without a sentry public key")
		}
	} else {
		if len(expected.SentryPublicKey) != boundedmeta.SentryPublicKeySizeV1 {
			return fmt.Errorf("bounded1 sentry public key length %d invalid", len(expected.SentryPublicKey))
		}
		if expected.SentryArgIndex < expected.BaseArgCount || expected.SentryArgIndex >= expected.AdminArgIndex {
			return fmt.Errorf("bounded1 sentry argument index %d invalid", expected.SentryArgIndex)
		}
		if bytes.Equal(expected.SentryPublicKey, expected.SpendingPublicKey) || bytes.Equal(expected.SentryPublicKey, expected.AdminPublicKey) {
			return fmt.Errorf("bounded1 sentry public key collides with another authority")
		}
	}
	if expected.MaxFee > boundedmeta.MaximumProfileFee {
		return fmt.Errorf("bounded1 maximum fee %d invalid", expected.MaxFee)
	}
	if err := boundedmeta.ValidateSpendEffects(expected.SpendEffects); err != nil {
		return fmt.Errorf("bounded1 spend effects invalid: %w", err)
	}
	order := make(map[string]int, len(bounded1ContractManifest.SpendEffects))
	for i, effect := range bounded1ContractManifest.SpendEffects {
		order[string(effect)] = i
	}
	for i := 1; i < len(expected.SpendEffects); i++ {
		if order[expected.SpendEffects[i-1]] >= order[expected.SpendEffects[i]] {
			return fmt.Errorf("bounded1 spend effects are not canonical")
		}
	}
	return nil
}

func dangerAssertions() []pattern {
	patterns := make([]pattern, 0, 4*(len(bounded1ContractManifest.Predicates)-1))
	for _, predicate := range bounded1ContractManifest.Predicates {
		if predicate.Effect == txeffects.EffectRekey {
			continue
		}
		patterns = append(patterns,
			exact("txn", string(predicate.Field)), exact("global", "ZeroAddress"), exact("=="), exact("assert"),
		)
	}
	return patterns
}

func expectedAllowsSpendEffect(expected Expected, effect string) bool {
	for _, allowed := range expected.SpendEffects {
		if allowed == effect {
			return true
		}
	}
	return false
}

func spendEffectDecision(allowed bool) []pattern {
	if allowed {
		return []pattern{branch("b")}
	}
	return []pattern{exact("err")}
}

func branchTarget(parsed disassembly, instructionAt int) (int, bool) {
	if instructionAt < 0 || instructionAt >= len(parsed.instructions) || len(parsed.instructions[instructionAt].args) != 1 {
		return 0, false
	}
	target, ok := parsed.labels[parsed.instructions[instructionAt].args[0]]
	return target, ok
}

type instruction struct {
	pc   int
	name string
	args []string
}

type disassembly struct {
	version      int
	instructions []instruction
	labels       map[string]int
}

type branchEncoding uint8

const (
	branchEncodingFixed branchEncoding = iota
	branchEncodingVarint
)

func (encoding branchEncoding) String() string {
	if encoding == branchEncodingVarint {
		return "varint branches"
	}
	return "fixed-width branches"
}

// decodeProgramUnambiguously recognizes both branch encodings that have been
// deployed for AVM v13 without accepting a program merely because one of two
// divergent interpretations satisfies the bounded contract. The sole
// syntactically valid interpretation is safe to inspect: selecting the other
// encoding on-chain can only make the program invalid. When both parse, their
// complete instruction boundaries, operations, operands, and control-flow
// targets must agree.
func decodeProgramUnambiguously(program []byte, version uint64) (disassembly, error) {
	if version < 13 {
		return decodeProgram(program, branchEncodingFixed)
	}

	varintProgram, varintErr := decodeProgram(program, branchEncodingVarint)
	fixedProgram, fixedErr := decodeProgram(program, branchEncodingFixed)
	switch {
	case varintErr == nil && fixedErr == nil:
		if !equivalentDisassembly(varintProgram, fixedProgram) {
			return disassembly{}, fmt.Errorf(
				"ambiguous AVM v%d branch encoding: varint and fixed-width decodings differ",
				version,
			)
		}
		return varintProgram, nil
	case varintErr == nil:
		return varintProgram, nil
	case fixedErr == nil:
		return fixedProgram, nil
	default:
		return disassembly{}, fmt.Errorf(
			"cannot decode AVM v%d program (%s: %v; %s: %v)",
			version,
			branchEncodingVarint,
			varintErr,
			branchEncodingFixed,
			fixedErr,
		)
	}
}

func equivalentDisassembly(left, right disassembly) bool {
	if left.version != right.version || len(left.instructions) != len(right.instructions) {
		return false
	}
	for i := range left.instructions {
		leftInstruction := left.instructions[i]
		rightInstruction := right.instructions[i]
		if leftInstruction.pc != rightInstruction.pc ||
			leftInstruction.name != rightInstruction.name ||
			len(leftInstruction.args) != len(rightInstruction.args) {
			return false
		}
		for argIndex := range leftInstruction.args {
			leftArg := leftInstruction.args[argIndex]
			rightArg := rightInstruction.args[argIndex]
			if isBranchInstruction(leftInstruction.name) {
				leftTarget, leftOK := left.labels[leftArg]
				rightTarget, rightOK := right.labels[rightArg]
				if !leftOK || !rightOK || leftTarget != rightTarget {
					return false
				}
				continue
			}
			if leftArg != rightArg {
				return false
			}
		}
	}
	return true
}

func decodeProgram(program []byte, branchEncoding branchEncoding) (disassembly, error) {
	version, versionBytes := binary.Uvarint(program)
	if versionBytes <= 0 {
		return disassembly{}, fmt.Errorf("invalid AVM version prefix")
	}
	result := disassembly{version: int(version), labels: make(map[string]int)}
	var intConstants []uint64
	var byteConstants [][]byte
	pcToIndex := make(map[int]int)
	for pc := versionBytes; pc < len(program); {
		opcode := program[pc]
		size := int(avmOpcodeSizes[opcode])
		if size == invalidOpcodeSize {
			previous := "program start"
			if count := len(result.instructions); count != 0 {
				last := result.instructions[count-1]
				previous = fmt.Sprintf("%s at pc %d", last.name, last.pc)
			}
			from, to := max(0, pc-8), min(len(program), pc+9)
			return disassembly{}, fmt.Errorf(
				"invalid AVM v%d opcode 0x%02x at pc %d after %s (bytes %d:%d = %x)",
				result.version, opcode, pc, previous, from, to, program[from:to],
			)
		}
		inst := instruction{pc: pc, name: fmt.Sprintf("op_%02x", opcode)}
		var err error
		switch opcode {
		case 0x20:
			size, intConstants, err = decodeIntBlock(program, pc)
		case 0x26:
			size, byteConstants, err = decodeByteBlock(program, pc)
		case 0x80:
			var value []byte
			size, value, err = decodePushBytes(program, pc)
			inst.name, inst.args = "pushbytes", []string{"0x" + hex.EncodeToString(value)}
		case 0x81:
			var value uint64
			size, value, err = decodePushInt(program, pc)
			inst.name, inst.args = "pushint", []string{strconv.FormatUint(value, 10)}
		case 0x82, 0x83:
			size, err = decodeVariableVector(program, pc, opcode)
		case 0x8d, 0x8e:
			size, inst.args, err = decodeBranchVector(program, pc)
			inst.name = fixedOpcodeNames[opcode]
		case 0x40, 0x41, 0x42, 0x88:
			if result.version >= 13 && branchEncoding == branchEncodingVarint {
				size, inst.args, err = decodeVarintBranch(program, pc)
				inst.name = fixedOpcodeNames[opcode]
			} else if pc+size > len(program) {
				err = fmt.Errorf("instruction at pc %d exceeds program", pc)
			} else {
				inst, err = decodeFixedInstruction(program, pc, size, intConstants, byteConstants)
			}
		default:
			if pc+size > len(program) {
				err = fmt.Errorf("instruction at pc %d exceeds program", pc)
			} else {
				inst, err = decodeFixedInstruction(program, pc, size, intConstants, byteConstants)
			}
		}
		if err != nil {
			return disassembly{}, err
		}
		if size <= 0 || pc+size > len(program) {
			return disassembly{}, fmt.Errorf("invalid instruction size %d at pc %d", size, pc)
		}
		if opcode != 0x20 && opcode != 0x26 {
			pcToIndex[pc] = len(result.instructions)
			result.instructions = append(result.instructions, inst)
		}
		pc += size
	}
	pcToIndex[len(program)] = len(result.instructions)
	for _, inst := range result.instructions {
		if isBranchInstruction(inst.name) {
			for _, rawTarget := range inst.args {
				target, err := strconv.Atoi(rawTarget)
				if err != nil {
					return disassembly{}, fmt.Errorf("invalid branch target at pc %d", inst.pc)
				}
				index, ok := pcToIndex[target]
				if !ok {
					return disassembly{}, fmt.Errorf("branch at pc %d targets non-instruction pc %d", inst.pc, target)
				}
				result.labels[rawTarget] = index
			}
		}
	}
	return result, nil
}

func decodeVarintBranch(program []byte, pc int) (int, []string, error) {
	if pc < 0 || pc+1 >= len(program) {
		return 0, nil, fmt.Errorf("invalid varint branch at pc %d", pc)
	}
	offset, used := binary.Varint(program[pc+1:])
	if used <= 0 {
		return 0, nil, fmt.Errorf("invalid varint branch at pc %d", pc)
	}
	size := 1 + used
	var target int64
	if offset < 0 {
		target = int64(pc) + offset
	} else {
		target = int64(pc+size) + offset
	}
	if target < 0 || target > int64(len(program)) {
		return 0, nil, fmt.Errorf("varint branch at pc %d targets outside program", pc)
	}
	return size, []string{strconv.FormatInt(target, 10)}, nil
}

func decodeFixedInstruction(program []byte, pc, size int, ints []uint64, byteArrays [][]byte) (instruction, error) {
	opcode := program[pc]
	inst := instruction{pc: pc, name: fixedOpcodeNames[opcode]}
	if inst.name == "" {
		inst.name = fmt.Sprintf("op_%02x", opcode)
	}
	switch opcode {
	case 0x21:
		return integerConstantInstruction(inst, int(program[pc+1]), ints)
	case 0x22, 0x23, 0x24, 0x25:
		return integerConstantInstruction(inst, int(opcode-0x22), ints)
	case 0x27:
		return byteConstantInstruction(inst, int(program[pc+1]), byteArrays)
	case 0x28, 0x29, 0x2a, 0x2b:
		return byteConstantInstruction(inst, int(opcode-0x28), byteArrays)
	case 0x2c:
		inst.name, inst.args = "arg", []string{strconv.Itoa(int(program[pc+1]))}
	case 0x2d, 0x2e, 0x2f, 0x30:
		inst.name, inst.args = "arg", []string{strconv.Itoa(int(opcode - 0x2d))}
	case 0x31:
		field, ok := txnFields[program[pc+1]]
		if !ok {
			return instruction{}, fmt.Errorf("unsupported txn field %d at pc %d", program[pc+1], pc)
		}
		inst.args = []string{field}
	case 0x32:
		field, ok := globalFields[program[pc+1]]
		if !ok {
			return instruction{}, fmt.Errorf("unsupported global field %d at pc %d", program[pc+1], pc)
		}
		inst.args = []string{field}
	case 0x40, 0x41, 0x42, 0x88:
		offset := int(int16(binary.BigEndian.Uint16(program[pc+1 : pc+3])))
		inst.args = []string{strconv.Itoa(pc + size + offset)}
	}
	return inst, nil
}

func integerConstantInstruction(inst instruction, index int, constants []uint64) (instruction, error) {
	if index < 0 || index >= len(constants) {
		return instruction{}, fmt.Errorf("invalid int constant %d at pc %d", index, inst.pc)
	}
	inst.name, inst.args = "pushint", []string{strconv.FormatUint(constants[index], 10)}
	return inst, nil
}

func byteConstantInstruction(inst instruction, index int, constants [][]byte) (instruction, error) {
	if index < 0 || index >= len(constants) {
		return instruction{}, fmt.Errorf("invalid byte constant %d at pc %d", index, inst.pc)
	}
	inst.name, inst.args = "pushbytes", []string{"0x" + hex.EncodeToString(constants[index])}
	return inst, nil
}

func decodeIntBlock(program []byte, pc int) (int, []uint64, error) {
	count, used, err := readUvarint(program, pc+1)
	if err != nil {
		return 0, nil, err
	}
	offset := pc + 1 + used
	values := make([]uint64, 0, count)
	for range count {
		value, n, err := readUvarint(program, offset)
		if err != nil {
			return 0, nil, err
		}
		values = append(values, value)
		offset += n
	}
	return offset - pc, values, nil
}

func decodeByteBlock(program []byte, pc int) (int, [][]byte, error) {
	count, used, err := readUvarint(program, pc+1)
	if err != nil {
		return 0, nil, err
	}
	offset := pc + 1 + used
	values := make([][]byte, 0, count)
	for range count {
		length, n, err := readUvarint(program, offset)
		if err != nil || length > uint64(len(program)-offset-n) {
			return 0, nil, fmt.Errorf("invalid byte constant block at pc %d", pc)
		}
		offset += n
		values = append(values, bytes.Clone(program[offset:offset+int(length)]))
		offset += int(length)
	}
	return offset - pc, values, nil
}

func decodePushBytes(program []byte, pc int) (int, []byte, error) {
	length, used, err := readUvarint(program, pc+1)
	if err != nil || length > uint64(len(program)-pc-1-used) {
		return 0, nil, fmt.Errorf("invalid pushbytes at pc %d", pc)
	}
	start := pc + 1 + used
	return 1 + used + int(length), program[start : start+int(length)], nil
}

func decodePushInt(program []byte, pc int) (int, uint64, error) {
	value, used, err := readUvarint(program, pc+1)
	return 1 + used, value, err
}

func decodeVariableVector(program []byte, pc int, opcode byte) (int, error) {
	if opcode != 0x82 && opcode != 0x83 {
		return 0, fmt.Errorf("unsupported variable-vector opcode 0x%02x at pc %d", opcode, pc)
	}
	count, used, err := readUvarint(program, pc+1)
	if err != nil {
		return 0, err
	}
	offset := pc + 1 + used
	for range count {
		switch opcode {
		case 0x82:
			length, n, err := readUvarint(program, offset)
			if err != nil || length > uint64(len(program)-offset-n) {
				return 0, fmt.Errorf("invalid pushbytess at pc %d", pc)
			}
			offset += n + int(length)
		case 0x83:
			_, n, err := readUvarint(program, offset)
			if err != nil {
				return 0, err
			}
			offset += n
		}
	}
	return offset - pc, nil
}

func decodeBranchVector(program []byte, pc int) (int, []string, error) {
	if pc+2 > len(program) {
		return 0, nil, fmt.Errorf("invalid branch vector at pc %d", pc)
	}
	count := int(program[pc+1])
	size := 2 + 2*count
	if pc+size > len(program) {
		return 0, nil, fmt.Errorf("invalid branch vector at pc %d", pc)
	}
	targets := make([]string, count)
	for i := range count {
		offsetAt := pc + 2 + 2*i
		offset := int(int16(binary.BigEndian.Uint16(program[offsetAt : offsetAt+2])))
		targets[i] = strconv.Itoa(pc + size + offset)
	}
	return size, targets, nil
}

func readUvarint(program []byte, offset int) (uint64, int, error) {
	if offset < 0 || offset >= len(program) {
		return 0, 0, fmt.Errorf("varuint at offset %d exceeds program", offset)
	}
	value, used := binary.Uvarint(program[offset:])
	if used <= 0 {
		return 0, 0, fmt.Errorf("invalid varuint at offset %d", offset)
	}
	return value, used, nil
}

type pattern func(instruction) bool

func exact(name string, args ...string) pattern {
	return func(inst instruction) bool {
		if inst.name != name || len(inst.args) != len(args) {
			return false
		}
		for i := range args {
			if inst.args[i] != args[i] {
				return false
			}
		}
		return true
	}
}

func branch(name string) pattern {
	return func(inst instruction) bool { return inst.name == name && len(inst.args) == 1 }
}

func intValue(value uint64) pattern {
	return func(inst instruction) bool {
		if inst.name != "pushint" || len(inst.args) != 1 {
			return false
		}
		got, err := strconv.ParseUint(inst.args[0], 0, 64)
		return err == nil && got == value
	}
}

func bytesValue(value []byte) pattern {
	want := strings.ToLower(hex.EncodeToString(value))
	return func(inst instruction) bool {
		if inst.name != "pushbytes" || len(inst.args) != 1 {
			return false
		}
		got := strings.TrimPrefix(strings.ToLower(inst.args[0]), "0x")
		decoded, err := hex.DecodeString(got)
		return err == nil && bytes.Equal(decoded, value) && got == want
	}
}

func matchesFrameworkSentryGateAt(instructions []instruction, at int) bool {
	anyArg := func(inst instruction) bool {
		return inst.name == "arg" && len(inst.args) == 1
	}
	anyBytes := func(inst instruction) bool {
		return inst.name == "pushbytes" && len(inst.args) == 1
	}
	gate := []pattern{
		anyArg, exact("len"), intValue(0), exact(">"), exact("assert"),
		anyArg, exact("len"), intValue(uint64(boundedmeta.SentrySignatureMaxSizeV1)), exact("<="), exact("assert"),
		bytesValue([]byte(sentrymessage.DomainTagV1)), bytesValue([]byte{byte(sentrymessage.RoleSentry)}), exact("concat"),
		exact("txn", "TxID"), exact("concat"), exact("sha512_256"),
		anyArg, anyBytes, exact("falcon_verify"), exact("assert"), branch("b"),
	}
	if !matchesAt(instructions, at, gate) {
		return false
	}
	firstArg := instructions[at].args[0]
	if instructions[at+5].args[0] != firstArg || instructions[at+16].args[0] != firstArg {
		return false
	}
	rawKey := strings.TrimPrefix(strings.ToLower(instructions[at+17].args[0]), "0x")
	key, err := hex.DecodeString(rawKey)
	return err == nil && len(key) == boundedmeta.SentryPublicKeySizeV1
}

func matchesAt(instructions []instruction, at int, patterns []pattern) bool {
	if at < 0 || at+len(patterns) > len(instructions) {
		return false
	}
	for i, matches := range patterns {
		if !matches(instructions[at+i]) {
			return false
		}
	}
	return true
}

func findUnique(instructions []instruction, patterns []pattern) (first, count int) {
	first = -1
	for i := range instructions {
		if matchesAt(instructions, i, patterns) {
			if first < 0 {
				first = i
			}
			count++
		}
	}
	return first, count
}

func isBranchInstruction(name string) bool {
	switch name {
	case "b", "bnz", "bz", "callsub", "switch", "match":
		return true
	default:
		return false
	}
}

type controlFlowState struct {
	at      int
	returns string
}

func validateLayer3ControlFlow(parsed disassembly, start, acceptAt int) error {
	if start < 0 || start >= acceptAt || acceptAt+1 >= len(parsed.instructions) {
		return fmt.Errorf("boundary is invalid")
	}
	type pendingState struct {
		at      int
		returns []int
	}
	pending := []pendingState{{at: start}}
	seen := make(map[controlFlowState]struct{})
	for len(pending) > 0 {
		state := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		if state.at == acceptAt {
			if len(state.returns) != 0 {
				return fmt.Errorf("accept block entered from a subroutine")
			}
			continue
		}
		if state.at < start || state.at >= acceptAt {
			return fmt.Errorf("control transfer escapes Layer 3")
		}
		key := controlFlowState{at: state.at, returns: encodeReturnStack(state.returns)}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		if len(seen) > len(parsed.instructions)*16 {
			return fmt.Errorf("control-flow state count exceeds validation limit")
		}
		inst := parsed.instructions[state.at]
		next := state.at + 1
		enqueue := func(target int, returns []int) {
			pending = append(pending, pendingState{at: target, returns: returns})
		}
		targets := func() ([]int, error) {
			resolved := make([]int, len(inst.args))
			for i, raw := range inst.args {
				target, ok := parsed.labels[raw]
				if !ok {
					return nil, fmt.Errorf("%s at pc %d has an unresolved target", inst.name, inst.pc)
				}
				resolved[i] = target
			}
			return resolved, nil
		}

		switch inst.name {
		case "err":
			continue
		case "return":
			return fmt.Errorf("return at pc %d bypasses the frozen accept block", inst.pc)
		case "retsub":
			if len(state.returns) == 0 {
				return fmt.Errorf("retsub at pc %d has no matching callsub", inst.pc)
			}
			returnAt := state.returns[len(state.returns)-1]
			enqueue(returnAt, append([]int(nil), state.returns[:len(state.returns)-1]...))
		case "callsub":
			resolved, err := targets()
			if err != nil || len(resolved) != 1 {
				if err != nil {
					return err
				}
				return fmt.Errorf("callsub at pc %d has invalid targets", inst.pc)
			}
			if len(state.returns) >= len(parsed.instructions) {
				return fmt.Errorf("callsub depth exceeds program size")
			}
			stack := append(append([]int(nil), state.returns...), next)
			enqueue(resolved[0], stack)
		case "b":
			resolved, err := targets()
			if err != nil || len(resolved) != 1 {
				if err != nil {
					return err
				}
				return fmt.Errorf("branch at pc %d has invalid targets", inst.pc)
			}
			enqueue(resolved[0], append([]int(nil), state.returns...))
		case "bnz", "bz":
			resolved, err := targets()
			if err != nil || len(resolved) != 1 {
				if err != nil {
					return err
				}
				return fmt.Errorf("conditional branch at pc %d has invalid targets", inst.pc)
			}
			enqueue(resolved[0], append([]int(nil), state.returns...))
			enqueue(next, append([]int(nil), state.returns...))
		case "switch", "match":
			resolved, err := targets()
			if err != nil {
				return err
			}
			for _, target := range resolved {
				enqueue(target, append([]int(nil), state.returns...))
			}
			enqueue(next, append([]int(nil), state.returns...))
		default:
			enqueue(next, append([]int(nil), state.returns...))
		}
	}
	return nil
}

func encodeReturnStack(values []int) string {
	var encoded strings.Builder
	for _, value := range values {
		encoded.WriteString(strconv.Itoa(value))
		encoded.WriteByte(',')
	}
	return encoded.String()
}
