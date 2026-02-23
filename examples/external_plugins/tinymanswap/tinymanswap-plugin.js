#!/usr/bin/env node
const readline = require('readline');
const { spawn } = require('child_process');
const path = require('path');

// JSON-RPC state
let network = 'testnet';
let apiServer = '';
let currentAddress = '';

// Create interface for reading from stdin
const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
  terminal: false
});

// Log to stderr for debugging
function logInfo(msg) {
  console.error(`[INFO] ${msg}`);
}

function logError(msg) {
  console.error(`[ERROR] ${msg}`);
}

// Send JSON-RPC response
function sendResponse(id, result, error = null) {
  const response = {
    jsonrpc: "2.0",
    id: id
  };

  if (error) {
    response.error = error;
  } else {
    response.result = result;
  }

  console.log(JSON.stringify(response));
}

// Handle initialize method
function handleInitialize(req) {
  const params = req.params;
  network = params.network || 'testnet';
  apiServer = params.apiServer || '';

  logInfo(`Initialized with network=${network}, api=${apiServer}`);

  sendResponse(req.id, {
    success: true,
    message: `Tinymanswap plugin initialized on ${network}`,
    version: "1.0.0"
  });
}

// Handle execute method
async function handleExecute(req) {
  const params = req.params;
  const command = params.command;
  const args = params.args || [];
  const context = params.context || {};

  currentAddress = context.currentAddress || '';

  if (command === 'tinymanswap') {
    try {
      const result = await executeSwap(args, context);
      sendResponse(req.id, result);
    } catch (error) {
      sendResponse(req.id, null, {
        code: -32000,
        message: error.message
      });
    }
  } else {
    sendResponse(req.id, null, {
      code: -32601,
      message: `Unknown command: ${command}`
    });
  }
}

// Execute the swap by calling the TypeScript script
// Syntax: tinymanswap <amount> <from_asset> to <to_asset> for <account> [via router|direct]
async function executeSwap(args, context) {
  // Use network from execution context (may differ from initialization if user switched networks)
  const execNetwork = context.network || network;
  if (execNetwork !== network) {
    logInfo(`Network changed: ${network} -> ${execNetwork}`);
    network = execNetwork;
  }

  // Parse arguments: <amount> <from_asset> to <to_asset> for <account> [via <mode>]
  // Minimum: amount, from_asset, "to", to_asset, "for", account = 6 args
  // Optional: "via", mode = 8 args
  if (args.length < 6 || args[2].toLowerCase() !== 'to' || args[4].toLowerCase() !== 'for') {
    throw new Error(
      "Usage: tinymanswap <amount> <from_asset> to <to_asset> for <account> [via router|direct]\n\n" +
      "Arguments:\n" +
      "  amount      - Amount to swap (in whole units, e.g., 10 = 10 ALGO)\n" +
      "  from_asset  - Asset to swap from (ID or 'ALGO')\n" +
      "  to_asset    - Asset to swap to (ID or 'ALGO')\n" +
      "  account     - Account name (alias) or address\n" +
      "  via         - Optional: 'router' or 'direct' (default: direct)"
    );
  }

  const amount = args[0];
  let fromAsset = args[1];
  let toAsset = args[3];
  const account = args[5];

  // Parse optional "via <mode>" at the end
  let mode = "direct";
  if (args.length >= 8 && args[6].toLowerCase() === 'via') {
    mode = args[7].toLowerCase();
    if (mode !== 'router' && mode !== 'direct') {
      throw new Error("Mode must be 'router' or 'direct'");
    }
  }
  const slippage = "0.01";

  // PRIORITY 1: Resolve ASA names to asset IDs (first)
  // Case-insensitive lookup for ASA names
  if (context.assetMap) {
    // Build case-insensitive lookup
    const assetMapLower = {};
    for (const [name, id] of Object.entries(context.assetMap)) {
      assetMapLower[name.toLowerCase()] = { id, originalName: name };
    }

    // Resolve fromAsset if it's a name (case-insensitive)
    const fromAssetLower = fromAsset.toLowerCase();
    if (fromAssetLower in assetMapLower) {
      const resolvedFromID = assetMapLower[fromAssetLower].id;
      logInfo(`Resolved ASA name '${fromAsset}' to asset ID ${resolvedFromID}`);
      fromAsset = resolvedFromID.toString();
    }

    // Resolve toAsset if it's a name (case-insensitive)
    const toAssetLower = toAsset.toLowerCase();
    if (toAssetLower in assetMapLower) {
      const resolvedToID = assetMapLower[toAssetLower].id;
      logInfo(`Resolved ASA name '${toAsset}' to asset ID ${resolvedToID}`);
      toAsset = resolvedToID.toString();
    }
  }

  // PRIORITY 2: Resolve account alias to address (second)
  // Normalize to uppercase (Algorand addresses are case-insensitive base32)
  const normalizedAccount = account.toUpperCase();
  let userAddr = normalizedAccount;

  // Check if it looks like an Algorand address (58 base32 uppercase chars)
  const isAddress = /^[A-Z2-7]{58}$/.test(normalizedAccount);

  if (isAddress) {
    userAddr = normalizedAccount;
  } else if (context.addressMap && context.addressMap[account]) {
    // It's an alias - resolve it
    userAddr = context.addressMap[account];
    logInfo(`Resolved alias '${account}' to ${userAddr}`);
  } else {
    // Not an address and not in the map
    throw new Error(`Unknown account alias: ${account}. Please use a valid alias or address.`);
  }

  if (!userAddr) {
    throw new Error("No account address provided");
  }

  // Convert amount to microunits (assuming 6 decimals for both ALGO and most ASAs)
  // The TypeScript script expects the amount in microunits, not whole units
  const amountFloat = parseFloat(amount);
  if (isNaN(amountFloat) || amountFloat <= 0) {
    throw new Error("Amount must be a positive number");
  }
  const amountMicro = Math.floor(amountFloat * 1_000_000);

  // Call the TypeScript generate-swap script
  return new Promise((resolve, reject) => {
    const tsNode = spawn('npx', [
      'ts-node',
      path.join(__dirname, 'generate-swap.ts'),
      network,
      userAddr,
      amountMicro.toString(),  // Pass amount in microunits
      fromAsset,
      toAsset,
      slippage,
      mode
    ], {
      cwd: __dirname,
      env: { ...process.env, NODE_ENV: 'production' }
    });

    let stdout = '';
    let stderr = '';

    tsNode.stdout.on('data', (data) => {
      stdout += data.toString();
    });

    tsNode.stderr.on('data', (data) => {
      stderr += data.toString();
    });

    tsNode.on('close', (code) => {
      if (code !== 0) {
        logError(`TypeScript script failed: ${stderr}`);
        reject(new Error(`Swap generation failed: ${stderr}`));
        return;
      }

      try {
        const output = JSON.parse(stdout);

        // Convert to transaction intents
        const transactions = output.swap.transactions.map((txBase64, index) => ({
          type: "raw",
          encoded: txBase64,
          description: index === 0 ? "Tinyman swap transaction" : `Tinyman swap transaction ${index + 1}`
        }));

        resolve({
          success: true,
          message: output.swap.description,
          transactions: transactions,
          requiresApproval: true,
          data: {
            pool_address: output.swap.pool_address,
            asset_in: output.swap.asset_in,
            asset_out: output.swap.asset_out,
            amount_in: output.swap.amount_in,
            amount_out_expected: output.swap.amount_out_expected,
            price_impact: output.swap.price_impact,
            slippage: output.swap.slippage
          }
        });
      } catch (error) {
        logError(`Failed to parse TypeScript output: ${error.message}`);
        reject(new Error(`Failed to parse swap output: ${error.message}`));
      }
    });
  });
}

// Handle getInfo method
function handleGetInfo(req) {
  sendResponse(req.id, {
    name: "tinymanswap",
    version: "1.0.0",
    description: "Tinyman DEX swap integration",
    commands: ["tinymanswap"],
    networks: ["testnet", "mainnet"],
    status: "ready"
  });
}

// Handle shutdown method
function handleShutdown(req) {
  logInfo("Shutting down...");

  sendResponse(req.id, {
    success: true,
    message: "Tinymanswap plugin shutdown"
  });

  // Exit after ensuring response is sent
  setTimeout(() => process.exit(0), 100);
}

// Process JSON-RPC requests
rl.on('line', async (line) => {
  if (!line.trim()) return;

  let request;
  try {
    request = JSON.parse(line);
  } catch (error) {
    logError(`Failed to parse request: ${error.message}`);
    return;
  }

  logInfo(`Received method: ${request.method}`);

  try {
    switch (request.method) {
      case 'initialize':
        handleInitialize(request);
        break;
      case 'execute':
        await handleExecute(request);
        break;
      case 'getInfo':
        handleGetInfo(request);
        break;
      case 'shutdown':
        handleShutdown(request);
        break;
      default:
        sendResponse(request.id, null, {
          code: -32601,
          message: `Method not found: ${request.method}`
        });
    }
  } catch (error) {
    logError(`Error handling request: ${error.message}`);
    sendResponse(request.id, null, {
      code: -32603,
      message: `Internal error: ${error.message}`
    });
  }
});

// Start the plugin
logInfo("Tinymanswap plugin starting...");