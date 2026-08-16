// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/algorand/go-algorand-sdk/v2/client/kmd"
	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

const (
	pluginName    = "algokit-localnet"
	pluginVersion = "0.1.0"
	// pluginProtocol is declared independently during initialization. It is
	// distinct from the JSON-RPC envelope and this plugin's release version.
	pluginProtocol    = "aplane-plugin/2"
	defaultAlgodURL   = "http://localhost:4001"
	defaultKMDURL     = "http://localhost:4002"
	defaultToken      = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	defaultWalletName = "unencrypted-default-wallet"
	microAlgosPerAlgo = uint64(1_000_000)
	defaultFundAmount = 100 * microAlgosPerAlgo
)

type Request struct {
	Jsonrpc string          `json:"jsonrpc"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
	ID      interface{}     `json:"id"`
}

type Response struct {
	Jsonrpc string      `json:"jsonrpc"`
	Result  interface{} `json:"result,omitempty"`
	Error   *Error      `json:"error,omitempty"`
	ID      interface{} `json:"id"`
}

type Error struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

type InitializeParams struct {
	Network    string `json:"network"`
	AlgodURL   string `json:"algodUrl"`
	AlgodToken string `json:"algodToken"`
}

type InitializeResult struct {
	Success  bool   `json:"success"`
	Message  string `json:"message,omitempty"`
	Protocol string `json:"protocol"`
}

type ExecuteParams struct {
	Command string   `json:"command"`
	Args    []string `json:"args"`
	Context Context  `json:"context"`
}

type Context struct {
	AddressMap  map[string]string `json:"addressMap,omitempty"`
	Network     string            `json:"network"`
	Round       uint64            `json:"round"`
	GenesisID   string            `json:"genesisId"`
	GenesisHash string            `json:"genesisHash"`
}

type ExecuteResult struct {
	Success      bool          `json:"success"`
	Message      string        `json:"message,omitempty"`
	Data         interface{}   `json:"data,omitempty"`
	Presentation *Presentation `json:"presentation,omitempty"`
}

type Presentation struct {
	Title    string                `json:"title,omitempty"`
	Summary  string                `json:"summary,omitempty"`
	Sections []PresentationSection `json:"sections,omitempty"`
}

type PresentationSection struct {
	Kind    string                 `json:"kind"`
	Title   string                 `json:"title,omitempty"`
	Text    string                 `json:"text,omitempty"`
	Items   []PresentationItem     `json:"items,omitempty"`
	Columns []string               `json:"columns,omitempty"`
	Rows    []PresentationTableRow `json:"rows,omitempty"`
}

type PresentationItem struct {
	Label string `json:"label"`
	Value string `json:"value"`
}

type PresentationTableRow struct {
	Cells []string `json:"cells"`
}

type GetInfoResult struct {
	Name        string   `json:"name"`
	Version     string   `json:"version"`
	Description string   `json:"description"`
	Commands    []string `json:"commands"`
	Networks    []string `json:"networks"`
	Status      string   `json:"status"`
}

type ShutdownResult struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
}

type pluginConfig struct {
	network        string
	algodURL       string
	kmdURL         string
	token          string
	walletName     string
	walletPassword string
}

type walletSession struct {
	client    kmd.Client
	handle    string
	addresses []string
}

type accountRow struct {
	address    string
	balance    uint64
	minBalance uint64
	spendable  uint64
}

var cfg = pluginConfig{
	network:        "localnet",
	algodURL:       defaultAlgodURL,
	kmdURL:         defaultKMDURL,
	token:          defaultToken,
	walletName:     defaultWalletName,
	walletPassword: "",
}

func main() {
	logInfo("%s starting", pluginName)

	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	writer := bufio.NewWriter(os.Stdout)

	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}

		var req Request
		if err := json.Unmarshal([]byte(line), &req); err != nil {
			logError("failed to parse request: %v", err)
			continue
		}

		resp := handleRequest(&req)
		respBytes, err := json.Marshal(resp)
		if err != nil {
			logError("failed to marshal response: %v", err)
			continue
		}

		_, _ = writer.Write(respBytes)
		_ = writer.WriteByte('\n')
		_ = writer.Flush()
	}

	if err := scanner.Err(); err != nil && err != io.EOF {
		logError("scanner error: %v", err)
	}
}

func handleRequest(req *Request) *Response {
	switch req.Method {
	case "initialize":
		return handleInitialize(req)
	case "execute":
		return handleExecute(req)
	case "getInfo":
		return handleGetInfo(req)
	case "shutdown":
		return handleShutdown(req)
	default:
		return errorResponse(req.ID, -32601, "Method not found", nil)
	}
}

func handleInitialize(req *Request) *Response {
	var params InitializeParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return errorResponse(req.ID, -32602, "Invalid params", err.Error())
	}

	cfg.network = firstNonEmpty(params.Network, "localnet")
	cfg.algodURL = cleanURL(envDefault("APLANE_LOCALNET_ALGOD_URL", firstNonEmpty(params.AlgodURL, defaultAlgodURL)))
	cfg.kmdURL = cleanURL(envDefault("APLANE_LOCALNET_KMD_URL", defaultKMDURL))
	cfg.token = envDefault("APLANE_LOCALNET_TOKEN", firstNonEmpty(params.AlgodToken, defaultToken))
	cfg.walletName = envDefault("APLANE_LOCALNET_WALLET", defaultWalletName)
	cfg.walletPassword = os.Getenv("APLANE_LOCALNET_WALLET_PASSWORD")

	logInfo("initialized network=%s algod=%s kmd=%s wallet=%s",
		cfg.network, cfg.algodURL, cfg.kmdURL, cfg.walletName)

	return successResponse(req.ID, InitializeResult{
		Success:  true,
		Message:  fmt.Sprintf("%s initialized on %s", pluginName, cfg.network),
		Protocol: pluginProtocol,
	})
}

func handleExecute(req *Request) *Response {
	var params ExecuteParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return errorResponse(req.ID, -32602, "Invalid params", err.Error())
	}

	execNetwork := firstNonEmpty(params.Context.Network, cfg.network)
	if execNetwork != "" && execNetwork != "localnet" {
		return errorResponse(req.ID, -32000, "algokit-localnet only supports localnet", execNetwork)
	}
	cfg.network = firstNonEmpty(execNetwork, "localnet")

	args := params.Args
	if params.Command != "" && params.Command != "localnet" {
		args = append([]string{params.Command}, params.Args...)
	}

	subcommand := "help"
	if len(args) > 0 {
		subcommand = strings.ToLower(args[0])
		args = args[1:]
	}

	var (
		result ExecuteResult
		err    error
	)
	switch subcommand {
	case "help", "-h", "--help":
		result = helpResult()
	case "status":
		result, err = statusResult()
	case "genesis":
		result, err = genesisResult()
	case "accounts":
		result, err = accountsResult()
	case "fund":
		result, err = fundResult(args, params.Context)
	default:
		return errorResponse(req.ID, -32602, "Unknown localnet subcommand", subcommand)
	}
	if err != nil {
		return errorResponse(req.ID, -32000, err.Error(), nil)
	}
	return successResponse(req.ID, result)
}

func handleGetInfo(req *Request) *Response {
	return successResponse(req.ID, GetInfoResult{
		Name:        pluginName,
		Version:     pluginVersion,
		Description: "AlgoKit LocalNet operations for status, KMD account listing, and local funding",
		Commands:    []string{"localnet"},
		Networks:    []string{"localnet"},
		Status:      "ready",
	})
}

func handleShutdown(req *Request) *Response {
	resp := successResponse(req.ID, ShutdownResult{
		Success: true,
		Message: fmt.Sprintf("%s shutdown", pluginName),
	})

	go func() {
		os.Exit(0)
	}()

	return resp
}

func helpResult() ExecuteResult {
	text := strings.Join([]string{
		"localnet status",
		"localnet genesis",
		"localnet accounts",
		"localnet fund <address|alias> [amount] [algo|microalgo] [from <address|alias>]",
		"",
		"Defaults target a standard AlgoKit LocalNet:",
		"algod http://localhost:4001, kmd http://localhost:4002.",
	}, "\n")

	return ExecuteResult{
		Success: true,
		Message: "AlgoKit LocalNet operations",
		Data: map[string]interface{}{
			"commands": []string{"status", "genesis", "accounts", "fund"},
		},
		Presentation: &Presentation{
			Title: "AlgoKit LocalNet",
			Sections: []PresentationSection{{
				Kind: "text",
				Text: text,
			}},
		},
	}
}

func statusResult() (ExecuteResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	algodClient, err := algod.MakeClient(cfg.algodURL, cfg.token)
	if err != nil {
		return ExecuteResult{}, fmt.Errorf("failed to create algod client: %w", err)
	}
	status, err := algodClient.Status().Do(ctx)
	if err != nil {
		return ExecuteResult{}, fmt.Errorf("failed to read algod status: %w", err)
	}
	version, err := algodClient.Versions().Do(ctx)
	if err != nil {
		return ExecuteResult{}, fmt.Errorf("failed to read algod versions: %w", err)
	}

	kmdStatus := "reachable"
	kmdVersions := []string{}
	kmdClient, err := kmd.MakeClient(cfg.kmdURL, cfg.token)
	if err != nil {
		kmdStatus = err.Error()
	} else if resp, err := kmdClient.Version(); err != nil {
		kmdStatus = err.Error()
	} else {
		kmdVersions = resp.Versions
	}

	items := []PresentationItem{
		{Label: "Network", Value: cfg.network},
		{Label: "Algod", Value: cfg.algodURL},
		{Label: "KMD", Value: cfg.kmdURL},
		{Label: "Genesis ID", Value: version.GenesisID},
		{Label: "Genesis hash", Value: base64.StdEncoding.EncodeToString(version.GenesisHash)},
		{Label: "Last round", Value: strconv.FormatUint(status.LastRound, 10)},
		{Label: "KMD status", Value: kmdStatus},
	}
	if len(kmdVersions) > 0 {
		items = append(items, PresentationItem{Label: "KMD versions", Value: strings.Join(kmdVersions, ", ")})
	}

	return ExecuteResult{
		Success: kmdStatus == "reachable",
		Message: "LocalNet status",
		Data: map[string]interface{}{
			"network":     cfg.network,
			"algodUrl":    cfg.algodURL,
			"kmdUrl":      cfg.kmdURL,
			"genesisId":   version.GenesisID,
			"genesisHash": base64.StdEncoding.EncodeToString(version.GenesisHash),
			"lastRound":   status.LastRound,
			"kmdStatus":   kmdStatus,
			"kmdVersions": kmdVersions,
		},
		Presentation: &Presentation{
			Title: "AlgoKit LocalNet Status",
			Sections: []PresentationSection{{
				Kind:  "key_value",
				Items: items,
			}},
		},
	}, nil
}

func genesisResult() (ExecuteResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	algodClient, err := algod.MakeClient(cfg.algodURL, cfg.token)
	if err != nil {
		return ExecuteResult{}, fmt.Errorf("failed to create algod client: %w", err)
	}
	version, err := algodClient.Versions().Do(ctx)
	if err != nil {
		return ExecuteResult{}, fmt.Errorf("failed to read algod versions: %w", err)
	}

	genesisHash := base64.StdEncoding.EncodeToString(version.GenesisHash)
	return ExecuteResult{
		Success: true,
		Message: "LocalNet genesis",
		Data: map[string]string{
			"genesisId":   version.GenesisID,
			"genesisHash": genesisHash,
		},
		Presentation: &Presentation{
			Title: "AlgoKit LocalNet Genesis",
			Sections: []PresentationSection{{
				Kind: "key_value",
				Items: []PresentationItem{
					{Label: "Genesis ID", Value: version.GenesisID},
					{Label: "Genesis hash", Value: genesisHash},
				},
			}},
		},
	}, nil
}

func accountsResult() (ExecuteResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	algodClient, err := algod.MakeClient(cfg.algodURL, cfg.token)
	if err != nil {
		return ExecuteResult{}, fmt.Errorf("failed to create algod client: %w", err)
	}
	session, err := openWallet()
	if err != nil {
		return ExecuteResult{}, err
	}
	defer session.close()

	rows := make([]accountRow, 0, len(session.addresses))
	for _, address := range session.addresses {
		account, err := algodClient.AccountInformation(address).Do(ctx)
		if err != nil {
			return ExecuteResult{}, fmt.Errorf("failed to read account %s: %w", address, err)
		}
		rows = append(rows, accountRow{
			address:    address,
			balance:    account.Amount,
			minBalance: account.MinBalance,
			spendable:  spendable(account.Amount, account.MinBalance),
		})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].balance == rows[j].balance {
			return rows[i].address < rows[j].address
		}
		return rows[i].balance > rows[j].balance
	})

	tableRows := make([]PresentationTableRow, 0, len(rows))
	dataRows := make([]map[string]interface{}, 0, len(rows))
	for _, row := range rows {
		tableRows = append(tableRows, PresentationTableRow{Cells: []string{
			row.address,
			formatAlgo(row.balance),
			formatAlgo(row.spendable),
			strconv.FormatUint(row.minBalance, 10),
		}})
		dataRows = append(dataRows, map[string]interface{}{
			"address":     row.address,
			"balance":     row.balance,
			"minBalance":  row.minBalance,
			"spendable":   row.spendable,
			"balanceAlgo": formatAlgo(row.balance),
		})
	}

	return ExecuteResult{
		Success: true,
		Message: fmt.Sprintf("Found %d KMD account(s)", len(rows)),
		Data: map[string]interface{}{
			"wallet":   cfg.walletName,
			"accounts": dataRows,
		},
		Presentation: &Presentation{
			Title:   "AlgoKit LocalNet KMD Accounts",
			Summary: fmt.Sprintf("Wallet: %s", cfg.walletName),
			Sections: []PresentationSection{{
				Kind:    "table",
				Columns: []string{"Address", "Balance", "Spendable", "Min balance (uALGO)"},
				Rows:    tableRows,
			}},
		},
	}, nil
}

func fundResult(args []string, execCtx Context) (ExecuteResult, error) {
	fundArgs, err := parseFundArgs(args, execCtx.AddressMap)
	if err != nil {
		return ExecuteResult{}, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	algodClient, err := algod.MakeClient(cfg.algodURL, cfg.token)
	if err != nil {
		return ExecuteResult{}, fmt.Errorf("failed to create algod client: %w", err)
	}
	params, err := algodClient.SuggestedParams().Do(ctx)
	if err != nil {
		return ExecuteResult{}, fmt.Errorf("failed to read suggested params: %w", err)
	}

	session, err := openWallet()
	if err != nil {
		return ExecuteResult{}, err
	}
	defer session.close()

	from := fundArgs.from
	if from == "" {
		from, err = selectFundingAddress(ctx, algodClient, session.addresses, fundArgs.amount, params.MinFee)
		if err != nil {
			return ExecuteResult{}, err
		}
	} else if !contains(session.addresses, from) {
		return ExecuteResult{}, fmt.Errorf("funding account %s is not in KMD wallet %s", from, cfg.walletName)
	}

	note := []byte("aplane algokit-localnet fund")
	tx, err := transaction.MakePaymentTxn(from, fundArgs.to, fundArgs.amount, note, "", params)
	if err != nil {
		return ExecuteResult{}, fmt.Errorf("failed to build funding transaction: %w", err)
	}
	signed, err := session.client.SignTransaction(session.handle, cfg.walletPassword, tx)
	if err != nil {
		return ExecuteResult{}, fmt.Errorf("failed to sign funding transaction with KMD: %w", err)
	}
	txid, err := algodClient.SendRawTransaction(signed.SignedTransaction).Do(ctx)
	if err != nil {
		return ExecuteResult{}, fmt.Errorf("failed to submit funding transaction: %w", err)
	}

	confirmed, err := transaction.WaitForConfirmation(algodClient, txid, 4, ctx)
	if err != nil {
		return ExecuteResult{}, fmt.Errorf("submitted %s but confirmation failed: %w", txid, err)
	}

	items := []PresentationItem{
		{Label: "From", Value: from},
		{Label: "To", Value: fundArgs.to},
		{Label: "Amount", Value: formatAlgo(fundArgs.amount)},
		{Label: "Transaction ID", Value: txid},
		{Label: "Confirmed round", Value: strconv.FormatUint(confirmed.ConfirmedRound, 10)},
	}

	return ExecuteResult{
		Success: true,
		Message: fmt.Sprintf("Funded %s with %s", fundArgs.to, formatAlgo(fundArgs.amount)),
		Data: map[string]interface{}{
			"from":           from,
			"to":             fundArgs.to,
			"amount":         fundArgs.amount,
			"amountAlgo":     formatAlgo(fundArgs.amount),
			"txid":           txid,
			"confirmedRound": confirmed.ConfirmedRound,
		},
		Presentation: &Presentation{
			Title: "LocalNet Funding Complete",
			Sections: []PresentationSection{{
				Kind:  "key_value",
				Items: items,
			}},
		},
	}, nil
}

type fundArgs struct {
	to     string
	from   string
	amount uint64
}

func parseFundArgs(args []string, addressMap map[string]string) (fundArgs, error) {
	if len(args) == 0 {
		return fundArgs{}, errors.New("usage: localnet fund <address|alias> [amount] [algo|microalgo] [from <address|alias>]")
	}

	to, err := resolveAddress(args[0], addressMap)
	if err != nil {
		return fundArgs{}, fmt.Errorf("invalid target address: %w", err)
	}

	fromIndex := -1
	for i, arg := range args[1:] {
		if strings.EqualFold(arg, "from") {
			fromIndex = i + 1
			break
		}
	}

	amountTokens := args[1:]
	from := ""
	if fromIndex >= 0 {
		amountTokens = args[1:fromIndex]
		if fromIndex+1 >= len(args) {
			return fundArgs{}, errors.New("from requires an address")
		}
		if fromIndex+2 != len(args) {
			return fundArgs{}, errors.New("from accepts exactly one address")
		}
		from, err = resolveAddress(args[fromIndex+1], addressMap)
		if err != nil {
			return fundArgs{}, fmt.Errorf("invalid funding address: %w", err)
		}
	}

	amount, err := parseAmount(amountTokens)
	if err != nil {
		return fundArgs{}, err
	}

	return fundArgs{to: to, from: from, amount: amount}, nil
}

func parseAmount(tokens []string) (uint64, error) {
	switch len(tokens) {
	case 0:
		return defaultFundAmount, nil
	case 1:
		return parseAmountToken(tokens[0])
	case 2:
		return parseAmountValueUnit(tokens[0], tokens[1])
	default:
		return 0, errors.New("amount must be omitted, a single value, or value plus unit")
	}
}

func parseAmountToken(token string) (uint64, error) {
	value := strings.TrimSpace(strings.ToLower(token))
	for _, suffix := range []string{"microalgos", "microalgo", "ualgos", "ualgo"} {
		if strings.HasSuffix(value, suffix) {
			return parseMicroAlgo(strings.TrimSuffix(value, suffix))
		}
	}
	for _, suffix := range []string{"algos", "algo"} {
		if strings.HasSuffix(value, suffix) {
			return parseAlgo(strings.TrimSuffix(value, suffix))
		}
	}
	return parseMicroAlgo(value)
}

func parseAmountValueUnit(value, unit string) (uint64, error) {
	switch strings.ToLower(unit) {
	case "algo", "algos":
		return parseAlgo(value)
	case "microalgo", "microalgos", "ualgo", "ualgos":
		return parseMicroAlgo(value)
	default:
		return 0, fmt.Errorf("unknown amount unit %q", unit)
	}
}

func parseMicroAlgo(value string) (uint64, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, errors.New("amount is empty")
	}
	amount, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid microAlgo amount %q", value)
	}
	if amount == 0 {
		return 0, errors.New("amount must be greater than zero")
	}
	return amount, nil
}

func parseAlgo(value string) (uint64, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, errors.New("amount is empty")
	}
	parts := strings.Split(value, ".")
	if len(parts) > 2 {
		return 0, fmt.Errorf("invalid ALGO amount %q", value)
	}
	whole, err := strconv.ParseUint(parts[0], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid ALGO amount %q", value)
	}
	if whole > ^uint64(0)/microAlgosPerAlgo {
		return 0, errors.New("amount is too large")
	}
	amount := whole * microAlgosPerAlgo
	if len(parts) == 2 {
		frac := parts[1]
		if len(frac) > 6 {
			return 0, errors.New("ALGO amount supports at most 6 decimal places")
		}
		for len(frac) < 6 {
			frac += "0"
		}
		fraction, err := strconv.ParseUint(frac, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("invalid ALGO amount %q", value)
		}
		if fraction > ^uint64(0)-amount {
			return 0, errors.New("amount is too large")
		}
		amount += fraction
	}
	if amount == 0 {
		return 0, errors.New("amount must be greater than zero")
	}
	return amount, nil
}

func resolveAddress(value string, addressMap map[string]string) (string, error) {
	if addressMap != nil {
		if resolved, ok := addressMap[value]; ok {
			value = resolved
		} else {
			lowerValue := strings.ToLower(value)
			for alias, resolved := range addressMap {
				if strings.ToLower(alias) == lowerValue {
					value = resolved
					break
				}
			}
		}
	}
	if _, err := types.DecodeAddress(value); err != nil {
		return "", err
	}
	return value, nil
}

func selectFundingAddress(
	ctx context.Context,
	algodClient *algod.Client,
	addresses []string,
	amount uint64,
	minFee uint64,
) (string, error) {
	if minFee == 0 {
		minFee = 1000
	}
	requiredSpendable, ok := addUint64(amount, minFee)
	if !ok {
		return "", errors.New("amount plus fee is too large")
	}

	var best accountRow
	for _, address := range addresses {
		account, err := algodClient.AccountInformation(address).Do(ctx)
		if err != nil {
			continue
		}
		row := accountRow{
			address:    address,
			balance:    account.Amount,
			minBalance: account.MinBalance,
			spendable:  spendable(account.Amount, account.MinBalance),
		}
		if row.spendable >= requiredSpendable && row.balance > best.balance {
			best = row
		}
	}
	if best.address == "" {
		return "", fmt.Errorf("no KMD account has enough spendable balance for %s plus fee", formatAlgo(amount))
	}
	return best.address, nil
}

func openWallet() (*walletSession, error) {
	client, err := kmd.MakeClient(cfg.kmdURL, cfg.token)
	if err != nil {
		return nil, fmt.Errorf("failed to create KMD client: %w", err)
	}
	wallets, err := client.ListWallets()
	if err != nil {
		return nil, fmt.Errorf("failed to list KMD wallets: %w", err)
	}

	walletID := ""
	for _, wallet := range wallets.Wallets {
		if wallet.Name == cfg.walletName {
			walletID = wallet.ID
			break
		}
	}
	if walletID == "" {
		return nil, fmt.Errorf("KMD wallet %q not found", cfg.walletName)
	}

	handle, err := client.InitWalletHandle(walletID, cfg.walletPassword)
	if err != nil {
		return nil, fmt.Errorf("failed to open KMD wallet %q: %w", cfg.walletName, err)
	}

	keys, err := client.ListKeys(handle.WalletHandleToken)
	if err != nil {
		_, _ = client.ReleaseWalletHandle(handle.WalletHandleToken)
		return nil, fmt.Errorf("failed to list KMD keys: %w", err)
	}

	return &walletSession{
		client:    client,
		handle:    handle.WalletHandleToken,
		addresses: keys.Addresses,
	}, nil
}

func (s *walletSession) close() {
	if s == nil || s.handle == "" {
		return
	}
	if _, err := s.client.ReleaseWalletHandle(s.handle); err != nil {
		logError("failed to release KMD wallet handle: %v", err)
	}
}

func spendable(balance, minBalance uint64) uint64 {
	if balance <= minBalance {
		return 0
	}
	return balance - minBalance
}

func formatAlgo(amount uint64) string {
	whole := amount / microAlgosPerAlgo
	frac := amount % microAlgosPerAlgo
	if frac == 0 {
		return fmt.Sprintf("%d ALGO", whole)
	}
	fracText := fmt.Sprintf("%06d", frac)
	fracText = strings.TrimRight(fracText, "0")
	return fmt.Sprintf("%d.%s ALGO", whole, fracText)
}

func addUint64(a, b uint64) (uint64, bool) {
	if b > ^uint64(0)-a {
		return 0, false
	}
	return a + b, true
}

func contains(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

func cleanURL(value string) string {
	return strings.TrimRight(strings.TrimSpace(value), "/")
}

func envDefault(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func successResponse(id interface{}, result interface{}) *Response {
	return &Response{Jsonrpc: "2.0", Result: result, ID: id}
}

func errorResponse(id interface{}, code int, message string, data interface{}) *Response {
	return &Response{
		Jsonrpc: "2.0",
		Error: &Error{
			Code:    code,
			Message: message,
			Data:    data,
		},
		ID: id,
	}
}

func logInfo(format string, args ...interface{}) {
	_, _ = fmt.Fprintf(os.Stderr, "[INFO] "+format+"\n", args...)
}

func logError(format string, args ...interface{}) {
	_, _ = fmt.Fprintf(os.Stderr, "[ERROR] "+format+"\n", args...)
}
