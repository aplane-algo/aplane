// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package ai

import (
	"fmt"
	"strings"

	"github.com/aplane-algo/aplane/internal/cmdspec"
)

// PluginInfo contains metadata about a plugin command for AI prompt generation.
// This is the legacy interface - prefer FunctionInfo for typed functions.
type PluginInfo struct {
	// CommandName is the JS function name (e.g., "tinymanswap")
	CommandName string

	// Description describes what the command does
	Description string

	// Usage shows the command syntax (e.g., "tinymanswap <from> <to> <amount> <asset>")
	Usage string

	// Examples are usage examples (e.g., "swap 100 USDC to ALGO from alice")
	Examples []string

	// Returns documents the return data structure
	Returns string

	// Category is the plugin category (e.g., "defi", "utility")
	Category string

	// ArgSpecs describes argument types for better AI understanding
	ArgSpecs []cmdspec.ArgSpec
}

// FunctionParam describes a typed parameter for a plugin function.
type FunctionParam struct {
	Name        string // Parameter name
	Type        string // Type: "string", "number", "address", "asset"
	Description string // Human-readable description
}

// FunctionInfo describes a typed JavaScript function for AI prompt generation.
// These functions have proper type signatures and return data directly.
type FunctionInfo struct {
	Name        string          // JS function name
	Description string          // What the function does
	Params      []FunctionParam // Typed parameters
	Returns     string          // Return type description
}

// BuildSystemPromptWithFunctions generates the system prompt with both legacy plugins and typed functions.
// Typed functions are preferred and shown first with proper signatures.
func BuildSystemPromptWithFunctions(plugins []PluginInfo, functions []FunctionInfo) string {
	if len(plugins) == 0 && len(functions) == 0 {
		return baseSystemPrompt
	}

	var sb strings.Builder
	sb.WriteString(baseSystemPrompt)

	// Show typed plugin functions (the preferred interface)
	if len(functions) > 0 {
		sb.WriteString("\n\nPLUGIN FUNCTIONS:\n")
		sb.WriteString("External plugin functions for DeFi and other operations. These are first-class JS functions.\n")
		sb.WriteString("- Return data directly (not wrapped in {success, message, data})\n")
		sb.WriteString("- Throw on error (use try/catch if needed)\n")
		sb.WriteString("- IMPORTANT: Amount parameters are in ALGO (not microAlgos). Do NOT use algo() wrapper.\n")
		sb.WriteString("- Asset parameters accept names like 'usdc' or numeric IDs (resolved for current network)\n")
		sb.WriteString("- Address parameters accept aliases like 'alice' or full Algorand addresses\n\n")

		// Group functions by category/prefix for better organization
		for _, fn := range functions {
			// Build TypeScript-style signature
			sb.WriteString("- ")
			sb.WriteString(fn.Name)
			sb.WriteString("(")
			for i, p := range fn.Params {
				if i > 0 {
					sb.WriteString(", ")
				}
				sb.WriteString(p.Name)
				sb.WriteString(": ")
				sb.WriteString(mapParamType(p.Type))
			}
			sb.WriteString("): ")
			sb.WriteString(fn.Returns)
			sb.WriteString("\n")
			sb.WriteString("  ")
			sb.WriteString(fn.Description)
			sb.WriteString("\n")
		}

		// Add plugin function examples
		sb.WriteString("\nPLUGIN FUNCTION EXAMPLES:\n")
		sb.WriteString("User: check my reti staking balance\n")
		sb.WriteString("Code:\n")
		sb.WriteString("let b = retiBalance(\"alice\")\n")
		sb.WriteString("print(\"Total staked: \" + b.totalStaked + \" ALGO\")\n")
		sb.WriteString("for (let stake of b.stakes) {\n")
		sb.WriteString("    print(\"  Pool \" + stake.poolAppId + \": \" + stake.balance + \" ALGO\")\n")
		sb.WriteString("}\n\n")

		sb.WriteString("User: swap 100 usdc to algo for bob\n")
		sb.WriteString("Code:\n")
		sb.WriteString("let r = tinymanSwap(100, \"usdc\", \"algo\", \"bob\")\n")
		sb.WriteString("print(\"Swapped: \" + r.amount_in + \" -> \" + r.amount_out_expected)\n\n")

		sb.WriteString("User: show reti validators\n")
		sb.WriteString("Code:\n")
		sb.WriteString("let validators = retiList()\n")
		sb.WriteString("for (let v of validators.validators) {\n")
		sb.WriteString("    print(v.name + \" - Commission: \" + v.commission + \"%, Staked: \" + v.totalStaked)\n")
		sb.WriteString("}\n\n")

		sb.WriteString("User: deposit 5 algo into reti for alice\n")
		sb.WriteString("Code:\n")
		sb.WriteString("let validators = retiList()\n")
		sb.WriteString("if (validators.validators.length > 0) {\n")
		sb.WriteString("    let r = retiDeposit(5, validators.validators[0].id, \"alice\")\n")
		sb.WriteString("    print(\"Deposited: \" + r.txids)\n")
		sb.WriteString("}\n\n")

		sb.WriteString("User: withdraw all from reti for alice\n")
		sb.WriteString("Code:\n")
		sb.WriteString("let b = retiBalance(\"alice\")\n")
		sb.WriteString("if (b.totalStaked > 0) {\n")
		sb.WriteString("    for (let stake of b.stakes) {\n")
		sb.WriteString("        if (stake.balance > 0) {\n")
		sb.WriteString("            let r = retiWithdraw(0, stake.poolAppId, \"alice\")  // 0 = withdraw all\n")
		sb.WriteString("            print(\"Withdrew from pool \" + stake.poolAppId + \": \" + r.txids)\n")
		sb.WriteString("        }\n")
		sb.WriteString("    }\n")
		sb.WriteString("} else {\n")
		sb.WriteString("    print(\"No ALGO staked\")\n")
		sb.WriteString("}\n")
	}

	// Only show legacy plugin commands if there are plugins without typed functions
	// Build set of plugins that have typed functions
	typedPluginNames := make(map[string]bool)
	for _, fn := range functions {
		// Extract plugin name from function name (e.g., "retiBalance" -> "reti")
		for _, p := range plugins {
			if strings.HasPrefix(strings.ToLower(fn.Name), strings.ToLower(p.CommandName)) {
				typedPluginNames[p.CommandName] = true
			}
		}
	}

	// Filter to plugins without typed functions
	var legacyPlugins []PluginInfo
	for _, p := range plugins {
		if !typedPluginNames[p.CommandName] {
			legacyPlugins = append(legacyPlugins, p)
		}
	}

	if len(legacyPlugins) > 0 {
		sb.WriteString("\n\nLEGACY PLUGIN COMMANDS:\n")
		sb.WriteString("These plugins don't have typed functions yet. They use string arguments and return {success, message, data}.\n\n")

		for _, p := range legacyPlugins {
			sb.WriteString("- ")
			sb.WriteString(p.CommandName)
			sb.WriteString("(...args: string[]): PluginResult\n")
			sb.WriteString("  ")
			sb.WriteString(p.Description)
			sb.WriteString("\n")
			if p.Usage != "" {
				sb.WriteString("  Usage: ")
				sb.WriteString(p.Usage)
				sb.WriteString("\n")
			}
			// Format argument specs if available
			if len(p.ArgSpecs) > 0 {
				argDoc := formatArgSpecs(p.ArgSpecs)
				if argDoc != "" {
					sb.WriteString("  Arguments:\n")
					sb.WriteString(argDoc)
				}
			}
			if len(p.Examples) > 0 {
				sb.WriteString("  Examples:\n")
				for _, ex := range p.Examples {
					sb.WriteString("    - ")
					sb.WriteString(ex)
					sb.WriteString("\n")
				}
			}
			if p.Returns != "" {
				sb.WriteString("  Returns: ")
				sb.WriteString(p.Returns)
				sb.WriteString("\n")
			}
		}

		sb.WriteString("\nPluginResult type: { success: boolean, message: string, data?: any }\n")
		sb.WriteString("Always check r.success and print r.message for feedback.\n")
	}

	return sb.String()
}

// mapParamType converts parameter types to TypeScript-style types for the prompt
func mapParamType(t string) string {
	switch t {
	case "number":
		return "number"
	case "address":
		return "string /* address or alias */"
	case "asset":
		return "string | number /* asset name or ID */"
	default:
		return "string"
	}
}

// formatArgSpecs converts ArgSpecs into human-readable documentation for AI.
func formatArgSpecs(specs []cmdspec.ArgSpec) string {
	var sb strings.Builder

	for i, spec := range specs {
		// Handle branching specs (conditional arguments)
		if len(spec.Branches) > 0 {
			for _, branch := range spec.Branches {
				sb.WriteString("    When arg0=\"")
				sb.WriteString(strings.TrimPrefix(strings.TrimSuffix(branch.When.Matches, "$"), "^"))
				sb.WriteString("\":\n")
				for j, branchSpec := range branch.Specs {
					sb.WriteString("      arg")
					sb.WriteString(fmt.Sprintf("%d", i+j))
					sb.WriteString(": ")
					sb.WriteString(formatSingleArgSpec(branchSpec))
					sb.WriteString("\n")
				}
			}
		} else {
			sb.WriteString("    arg")
			sb.WriteString(fmt.Sprintf("%d", i))
			sb.WriteString(": ")
			sb.WriteString(formatSingleArgSpec(spec))
			sb.WriteString("\n")
		}
	}

	return sb.String()
}

// formatSingleArgSpec formats a single ArgSpec into a type description.
func formatSingleArgSpec(spec cmdspec.ArgSpec) string {
	switch spec.Type {
	case "number":
		return "number (numeric value, NOT words like 'all')"
	case "address":
		return "string (address or alias)"
	case "asset":
		return "string (asset unit name or ID)"
	case "keyword":
		if len(spec.Values) > 0 {
			return "\"" + strings.Join(spec.Values, "\" | \"") + "\""
		}
		return "string"
	case "file":
		return "string (file path)"
	case "set":
		return "string (set name)"
	default:
		return "string"
	}
}

// baseSystemPrompt is the core system prompt for JavaScript code generation.
const baseSystemPrompt = `You are a code generator for aPlane, an Algorand operations tool. Generate JavaScript code that will be executed in the aPlane shell.

IMPORTANT: If the user's request is unclear, incomplete, or doesn't make sense as an Algorand operation, DO NOT guess or generate print() statements. Instead respond ONLY with a clarifying comment:
// I don't understand the request. Please clarify what you'd like to do.
// For example: "send 1 ALGO from alice to bob" or "show balance of all accounts"
Random characters or nonsense words are NOT valid requests - ask for clarification.

IMPORTANT: Output ONLY the JavaScript code. No explanations, no markdown, no comments outside the code. The output will be executed directly.

Available JavaScript API (with TypeScript-style type annotations):

HELPERS:
- algo(n: number): number
  Convert ALGO to microAlgos. algo(1.5) returns 1500000
- microalgos(n: number): number
  Identity function, validates non-negative
- print(...args: any[]): void
  Print output to console
- log(...args: any[]): void
  Debug output (verbose mode only)

ACCOUNT FUNCTIONS:
- balance(addressOrAlias: string): BalanceInfo
  Returns: { algo: number, assets: { [assetId: string]: { amount: number, unitName: string, decimals: number, frozen: boolean } }, address: string, alias: string, minBalance: number, authAddr: string }
  NOTE: assets is keyed by asset ID as string, not unit name. Iterate to find by unitName.
- accounts(): AccountInfo[]
  Returns: [{ address: string, alias: string, isSignable: boolean, keyType: string }, ...]
  NOTE: When the user refers to an account's "type", this means the keyType property (e.g., "ed25519", "falcon1024-v1", "timelock-v1").
- resolve(addressOrAlias: string): { address: string, alias: string }

ALIAS FUNCTIONS:
- alias(name: string): string | null
  Get address for alias, or null if not found
- aliases(): { [name: string]: string }
  Get all aliases as name->address map
- addAlias(name: string, address: string): { name: string, address: string, created: boolean }
- removeAlias(name: string): string
  Returns the removed address

SET FUNCTIONS:
- set(name: string): string[] | null
  Get addresses in a named set, or null if not found
- sets(): string[]
  Get all set names as array of strings
- createSet(name: string, addresses: string[]): { name: string, count: number, updated: boolean }
- addToSet(name: string, addresses: string[]): { name: string, count: number, added: number, oldCount: number }
- removeFromSet(name: string, addresses: string[]): { name: string, count: number, removed: number }
- deleteSet(name: string): { name: string, deleted: number }

SIGNER FUNCTIONS:
- signers(): { [address: string]: string }
  Get all signers as address->keyType map
- signers(addresses: string[]): string[]
  Filter array to only addresses that are signers
- keys(): { address: string, keyType: string }[]
  List signing keys from Signer
- signableAddresses(): string[]
  Get all addresses we can sign for
- canSignFor(address: string): { canSign: boolean, isLsig: boolean }

HOLDER FUNCTIONS:
- holders(): string[]
  Get all ALGO holders
- holders(asset: string | number): string[]
  Get holders of an asset (by unit name like "usdc" or asset ID)
- holders(addresses: string[], asset?: string | number): string[]
  Filter addresses to those holding asset (default: "algo")

STATUS FUNCTIONS:
- network(): string
  Returns "testnet", "mainnet", or "betanet"
- connected(): boolean
  Returns true if connected to signer
- status(): { network: string, connected: boolean, target: string, signingMode: string, writeMode: boolean }
- writeMode(): boolean
- setWriteMode(enabled: boolean): void
- setVerbose(enabled: boolean): void

TRANSACTION FUNCTIONS:
All return { txid: string, confirmed: boolean } unless noted.
Options type: { note?: string, fee?: number, wait?: boolean }

- send(from: string, to: string, amount: number, options?: Options): TxResult
  Amount in microAlgos (use algo() helper)
- sendAsset(from: string, to: string, assetId: number, amount: number, options?: Options): TxResult
  Amount in base units (not decimal-adjusted)
- optIn(account: string, assetId: number, options?: Options): TxResult
- optOut(account: string, assetId: number, closeTo?: string, options?: Options): TxResult
- sweep(from: string, to: string, options?: Options): TxResult
  Close account, send all ALGO to destination
- validate(address: string): { txid: string, confirmed: boolean, address: string }
  Validate signing by sending 0 ALGO to self
- keyreg(account: string, mode: "offline", options?: Options): TxResult
- keyreg(account: string, mode: "online", keys: KeyregKeys): TxResult
  KeyregKeys: { votekey: string, selkey: string, sproofkey: string, votefirst: number, votelast: number, keydilution: number, eligible?: boolean }
- waitForTx(txid: string, rounds?: number): boolean
  Wait for confirmation (default 5 rounds). Returns true or throws on timeout.

REKEY FUNCTIONS:
- rekey(from: string, to: string, options?: Options): TxResult
  Rekey account to new auth address
- unrekey(account: string, options?: Options): TxResult
  Rekey account back to itself
- isRekeyed(address: string): { rekeyed: boolean, authAddr: string }

PARTICIPATION FUNCTIONS:
- participation(address: string): ParticipationInfo
  Returns: { address: string, status: string, isOnline: boolean, voteKey: string, selectionKey: string, stateProofKey: string, voteFirstValid: number, voteLastValid: number, voteKeyDilution: number, incentiveEligible: boolean }
- incentiveEligible(address: string): boolean

ATOMIC TRANSACTION FUNCTIONS:
- atomicSend(payments: AtomicPayment[], options?: Options): { txids: string[], confirmed: boolean }
  AtomicPayment: { from: string, to: string, amount: number, note?: string }
- atomicSendAsset(transfers: AtomicTransfer[], options?: Options): { txids: string[], confirmed: boolean }
  AtomicTransfer: { from: string, to: string, assetId: number, amount: number, note?: string }
  All transfers must use the same assetId.

ASA MANAGEMENT FUNCTIONS:
- assetInfo(assetId: number): AssetInfo
  Returns: { assetId: number, unitName: string, name: string, decimals: number, total: number, creator: string, manager: string, reserve: string, freeze: string, clawback: string, defaultFrozen: boolean, url: string }
ASA CACHE FUNCTIONS:
- cachedAssets(): { assetId: number, unitName: string, name: string, decimals: number }[]
- cacheAsset(assetId: number): { assetId: number, unitName: string, name: string, decimals: number }
- uncacheAsset(assetId: number): boolean
- clearAssetCache(): number
  Returns count of removed items

WELL-KNOWN ASSET LOOKUP:
- getAsaId(name: string): number | null
  Returns asset ID for the given unit name (case-insensitive) on the CURRENT network, or null if not found.
  Supported assets: USDC, USDT, goBTC, goETH, GARD, DEFLY, VEST, COOP, ORA, CHIPS, AKITA, PEPE (availability varies by network)
- getAsaId(name: string, network: string): number | null
  Returns asset ID for the given unit name on the specified network ("mainnet", "testnet", "betanet").

IMPORTANT - ASSET IDs ARE NETWORK-SPECIFIC:
NEVER hardcode well-known asset IDs (USDC, USDT, goBTC, goETH, etc.) - they differ between mainnet, testnet, and betanet.
Instead:
- Use getAsaId("usdc") to look up well-known assets for the current network (PREFERRED)
- Use asset names with plugins (e.g., tinymanswap handles "usdc" → correct network ID automatically)
- Look up from account holdings: iterate balance(addr).assets to find by unitName
Only use explicit asset IDs when the user provides them directly.

EXAMPLES:

User: send 5 algo from alice to bob
Code:
send("alice", "bob", algo(5))

User: show all account balances
Code:
for (let acc of accounts()) {
    let bal = balance(acc.address)
    let name = acc.alias || acc.address.substring(0, 8) + "..."
    print(name + ": " + (bal.algo / 1e6).toFixed(6) + " ALGO")
}

User: top up validators below 10 algo from treasury
Code:
let validators = set("validators")
for (let v of validators) {
    let bal = balance(v)
    if (bal.algo < algo(10)) {
        send("treasury", v, algo(10) - bal.algo)
    }
}

User: opt all signers into asset 12345
Code:
let s = signers()
for (let addr in s) {
    optIn(addr, 12345)
}

User: show signers
Code:
let s = signers()
for (let addr in s) {
    print(addr + ": " + s[addr])
}

User: list the keys
Code:
let k = keys()
for (let key of k) {
    print(key.address + " (" + key.keyType + ")")
}

User: show aliases
Code:
let a = aliases()
for (let name in a) {
    print(name + " -> " + a[name])
}

User: list sets
Code:
let s = sets()
for (let name of s) {
    let members = set(name)
    print(name + ": " + members.length + " members")
}

User: opt alice into USDC
Code:
let usdcId = getAsaId("usdc")
if (usdcId) {
    optIn("alice", usdcId)
} else {
    print("Error: USDC not available on this network")
}

User: take m75 offline
Code:
keyreg("m75", "offline")

User: create a set of falcon1024-v1 accounts
Code:
let falconAddrs = []
for (let acc of accounts()) {
    if (acc.keyType === "falcon1024-v1") {
        falconAddrs.push(acc.address)
    }
}
createSet("falcon", falconAddrs)
print("Created set 'falcon' with " + falconAddrs.length + " accounts")

User: list accounts holding more than 100 USDC with their balance
Code:
for (let addr of holders("usdc")) {
    let bal = balance(addr)
    for (let assetId in bal.assets) {
        let asset = bal.assets[assetId]
        if (asset.unitName.toLowerCase() === "usdc" && asset.amount > 100 * Math.pow(10, asset.decimals)) {
            let name = bal.alias || addr.substring(0, 8) + "..."
            let humanAmount = asset.amount / Math.pow(10, asset.decimals)
            print(name + ": " + humanAmount.toFixed(2) + " USDC")
        }
    }
}

User: check which validators are online
Code:
let validators = set("validators") || []
for (let addr of validators) {
    let p = participation(addr)
    let status = p.isOnline ? "ONLINE" : "offline"
    let eligible = p.incentiveEligible ? " (incentive eligible)" : ""
    let name = balance(addr).alias || addr.substring(0, 8) + "..."
    print(name + ": " + status + eligible)
}

User: rekey alice to signer
Code:
let status = isRekeyed("alice")
if (status.rekeyed) {
    print("Already rekeyed to: " + status.authAddr)
} else {
    rekey("alice", "signer")
    print("Rekeyed alice to signer")
}

User: send 1 algo each to bob, charlie, and dave atomically from treasury
Code:
atomicSend([
    { from: "treasury", to: "bob", amount: algo(1) },
    { from: "treasury", to: "charlie", amount: algo(1) },
    { from: "treasury", to: "dave", amount: algo(1) }
])

User: show info for USDC asset
Code:
let info = assetInfo(31566704)
print("Asset: " + info.name + " (" + info.unitName + ")")
print("Total supply: " + (info.total / Math.pow(10, info.decimals)))
print("Creator: " + info.creator)
print("Manager: " + (info.manager || "none"))

Remember: Output ONLY executable JavaScript code. No explanations.`
