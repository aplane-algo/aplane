#!/usr/bin/env ts-node
import {
  poolUtils,
  Swap,
  SwapType,
  SupportedNetwork,
  SwapQuoteType,
  ALGO_ASSET_ID,
} from '@tinymanorg/tinyman-js-sdk';
import algosdk, { Algodv2 } from 'algosdk';

type Network = 'testnet' | 'mainnet';

interface SwapOutput {
  swap: {
    description: string;
    transactions: string[];
    pool_address: string;
    asset_in: {
      id: number;
      name: string;
      decimals: number;
    };
    asset_out: {
      id: number;
      name: string;
      decimals: number;
    };
    amount_in: string;
    amount_out_expected: string;
    price_impact: string;
    slippage: number;
  };
}

/**
 * Convert transactions to base64-encoded msgpack format
 */
function transactionsToBase64(txns: any[]): string[] {
  return txns.map(txn => {
    const encoded = algosdk.encodeUnsignedTransaction(txn);
    return Buffer.from(encoded).toString('base64');
  });
}

/**
 * Create algod client for the given network
 */
function createAlgodClient(network: Network): Algodv2 {
  if (network === 'testnet') {
    return new Algodv2('', 'https://testnet-api.algonode.cloud', '');
  } else {
    return new Algodv2('', 'https://mainnet-api.algonode.cloud', '');
  }
}

/**
 * Parse asset identifier (can be ID or ALGO)
 */
function resolveAssetId(assetIdentifier: string): number {
  // If it's ALGO or 0 - use SDK constant
  if (assetIdentifier.toLowerCase() === 'algo' || assetIdentifier === '0') {
    return ALGO_ASSET_ID; // SDK constant for ALGO (0)
  }

  // Try to parse as number (asset ID)
  const assetId = parseInt(assetIdentifier);
  if (!isNaN(assetId) && assetId >= 0) {
    return assetId;
  }

  throw new Error(
    `Unknown asset '${assetIdentifier}'. Use a numeric asset ID (e.g., 10458941) or 'ALGO'. ` +
    `To use asset names, first add them to apshell: asa add <asset-id>`
  );
}

/**
 * Get asset decimals from algod
 */
async function getAssetDecimals(
  algodClient: Algodv2,
  assetId: number
): Promise<number> {
  if (assetId === 0) {
    return 6; // ALGO has 6 decimals
  }

  const assetInfo = await algodClient.getAssetByID(assetId).do();
  return assetInfo.params.decimals;
}

/**
 * Generate Tinyman swap transactions
 */
async function generateSwapTransactions(
  network: Network,
  userAddress: string,
  amountIn: number, // in micro-units
  fromAsset: string,
  toAsset: string,
  slippage: number = 0.01, // 1% default
  swapMode: 'direct' | 'router' = 'direct'
): Promise<SwapOutput> {
  const algodClient = createAlgodClient(network);

  // Resolve assets
  const assetInId = resolveAssetId(fromAsset);
  const assetOutId = resolveAssetId(toAsset);

  // Get asset decimals
  const assetInDecimals = await getAssetDecimals(algodClient, assetInId);
  const assetOutDecimals = await getAssetDecimals(algodClient, assetOutId);

  const assetInName = assetInId === 0 ? 'ALGO' : `Asset ${assetInId}`;
  const assetOutName = assetOutId === 0 ? 'ALGO' : `Asset ${assetOutId}`;

  let pool: any = null;
  let poolAddress = '';

  // Only fetch pool info if forcing direct swap
  if (swapMode === 'direct') {
    console.error(`Resolving pool for ${assetInName} → ${assetOutName}...`);

    pool = await poolUtils.v2.getPoolInfo({
      network: network as SupportedNetwork,
      client: algodClient,
      asset1ID: assetInId,
      asset2ID: assetOutId,
    });

    if (!pool) {
      throw new Error(
        `No pool found for ${assetInName} (${assetInId}) and ${assetOutName} (${assetOutId})`
      );
    }

    poolAddress = pool.account.address().toString();
    console.error(`Pool found: ${poolAddress}`);
  } else {
    console.error(`Finding best route for ${assetInName} → ${assetOutName} (router mode)...`);
  }

  // Get quote for fixed input swap
  // When pool is provided, forces direct swap; when null, allows router swaps
  const quote = await Swap.v2.getQuote({
    type: SwapType.FixedInput,
    amount: BigInt(amountIn),
    assetIn: {id: assetInId, decimals: assetInDecimals},
    assetOut: {id: assetOutId, decimals: assetOutDecimals},
    ...(pool && {pool}), // Only include pool parameter if we have one
    network: network as SupportedNetwork,
    slippage,
  });

  // Extract quote data (handle both direct and router swaps)
  let amountOutDisplay: number;
  let priceImpact: number;
  const amountInDisplay = amountIn / Math.pow(10, assetInDecimals);

  if (quote.type === SwapQuoteType.Direct) {
    // Direct swap through a single pool
    const quoteData = quote.data.quote;
    amountOutDisplay = Number(quoteData.assetOutAmount) / Math.pow(10, assetOutDecimals);
    priceImpact = quoteData.priceImpact;
    console.error('Using direct swap (single pool)');
  } else {
    // Router swap through multiple pools (better rate)
    const routerData = quote.data;
    amountOutDisplay = routerData.output_amount
      ? parseFloat(routerData.output_amount) / Math.pow(10, assetOutDecimals)
      : 0;
    priceImpact = routerData.price_impact ? parseFloat(routerData.price_impact) : 0;
    console.error(`Using router swap (${routerData.transaction_count} transactions through ${routerData.pool_ids?.length || 0} pools)`);
  }

  console.error(`Quote: ${amountInDisplay} ${assetInName} → ${amountOutDisplay} ${assetOutName}`);
  console.error(`Price impact: ${priceImpact}%`);
  console.error(`Slippage tolerance: ${slippage * 100}%`);

  // Generate transactions
  const txnGroup = await Swap.v2.generateTxns({
    client: algodClient,
    network: network as SupportedNetwork,
    quote,
    swapType: SwapType.FixedInput,
    slippage,
    initiatorAddr: userAddress,
  });

  // Extract unsigned transactions
  const transactions = txnGroup.map((txnGroup: any) => txnGroup.txn);

  // Get pool address(es) depending on swap type
  const poolInfo = quote.type === SwapQuoteType.Direct
    ? poolAddress
    : (quote.data.pool_ids?.join(', ') || 'Router swap');

  return {
    swap: {
      description: `Swap ${amountInDisplay} ${assetInName} for ~${amountOutDisplay} ${assetOutName}`,
      transactions: transactionsToBase64(transactions),
      pool_address: poolInfo,
      asset_in: {
        id: assetInId,
        name: assetInName,
        decimals: assetInDecimals,
      },
      asset_out: {
        id: assetOutId,
        name: assetOutName,
        decimals: assetOutDecimals,
      },
      amount_in: amountInDisplay.toString(),
      amount_out_expected: amountOutDisplay.toString(),
      price_impact: priceImpact.toString(),
      slippage,
    },
  };
}

/**
 * Main entry point
 */
async function main() {
  const args = process.argv.slice(2);

  if (args.length < 5 || args.length > 7) {
    console.error('Usage: generate-swap.ts <network> <user_address> <amount_in_micro> <from_asset> <to_asset> [slippage] [mode]');
    console.error('');
    console.error('Arguments:');
    console.error('  network          - "testnet" or "mainnet"');
    console.error('  user_address     - Address performing the swap');
    console.error('  amount_in_micro  - Amount to swap in micro-units (e.g., 1000000 = 1 ALGO)');
    console.error('  from_asset       - Asset to swap from (ID or "ALGO")');
    console.error('  to_asset         - Asset to swap to (ID or "ALGO")');
    console.error('  slippage         - Optional slippage tolerance (e.g., 0.01 = 1%, default: 0.01)');
    console.error('  mode             - Optional swap mode: "direct" or "router" (default: direct)');
    console.error('');
    console.error('Example:');
    console.error('  generate-swap.ts testnet ABC123... 1000000 ALGO 10458941 0.01 direct');
    process.exit(1);
  }

  const [network, userAddress, amountInStr, fromAsset, toAsset, slippageStr, swapModeStr] = args;

  // Validate network
  if (network !== 'testnet' && network !== 'mainnet') {
    console.error(`Error: Invalid network "${network}". Must be "testnet" or "mainnet".`);
    process.exit(1);
  }

  // Parse amount
  const amountIn = parseInt(amountInStr);
  if (isNaN(amountIn) || amountIn <= 0) {
    console.error(`Error: Invalid amount "${amountInStr}". Must be a positive integer in micro-units.`);
    process.exit(1);
  }

  // Parse slippage (optional)
  const slippage = slippageStr ? parseFloat(slippageStr) : 0.01;
  if (isNaN(slippage) || slippage < 0 || slippage > 1) {
    console.error(`Error: Invalid slippage "${slippageStr}". Must be between 0 and 1 (e.g., 0.01 = 1%).`);
    process.exit(1);
  }

  // Parse swap mode (optional)
  const swapMode = swapModeStr || 'direct';
  if (swapMode !== 'direct' && swapMode !== 'router') {
    console.error(`Error: Invalid swap mode "${swapModeStr}". Must be "direct" or "router".`);
    process.exit(1);
  }

  try {
    const result = await generateSwapTransactions(
      network as Network,
      userAddress,
      amountIn,
      fromAsset,
      toAsset,
      slippage,
      swapMode
    );

    // Output as JSON
    console.log(JSON.stringify(result, null, 2));
  } catch (error) {
    console.error(`Error generating swap transactions: ${error}`);
    process.exit(1);
  }
}

main();
