#!/usr/bin/env node
/**
 * Reti Staking Pool Plugin for aPlane Shell
 *
 * Uses Reti typed clients with AlgoKit's populateAppCallResources
 * for automatic box reference discovery.
 */
import * as readline from 'readline';
import algosdk from 'algosdk';
import { AlgorandClient, populateAppCallResources } from '@algorandfoundation/algokit-utils';
import { AlgoAmount } from '@algorandfoundation/algokit-utils/types/amount';
import { ValidatorRegistryClient } from './contracts/ValidatorRegistryClient.js';
import { StakingPoolClient } from './contracts/StakingPoolClient.js';
// Reti ValidatorRegistry App IDs
const RETI_APP_IDS = {
    testnet: 734834614n,
    mainnet: 2714516089n,
    betanet: 639070n
};
// Fee sink for read-only simulations
const FEE_SINK = 'Y76M3MSY6DKBRHBL7C3NNDXGS5IIMQVQVUAB6MP4XEMMGVF2QWNPL226CA';
let pluginState = {
    network: '',
    apiServer: '',
    initialized: false,
    algorand: null,
    retiAppId: 0n
};
// Setup readline
const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
    terminal: false
});
function bigIntReplacer(_key, value) {
    return typeof value === 'bigint' ? Number(value) : value;
}
function sendResponse(id, result, error = null) {
    const response = { jsonrpc: '2.0', id };
    if (error)
        response.error = error;
    else
        response.result = result;
    console.log(JSON.stringify(response, bigIntReplacer));
}
function logError(message) {
    process.stderr.write(`[reti-plugin] ${message}\n`);
}
function parseAmount(amountStr) {
    const amount = parseFloat(amountStr);
    if (isNaN(amount) || amount <= 0)
        throw new Error('Invalid amount');
    return BigInt(Math.floor(amount * 1_000_000));
}
function formatAlgo(microAlgos) {
    return (Number(microAlgos) / 1_000_000).toFixed(6);
}
// Get typed client for read operations
async function getValidatorClient(sender = FEE_SINK) {
    if (!pluginState.algorand)
        throw new Error('Not initialized');
    return pluginState.algorand.client.getTypedAppClientById(ValidatorRegistryClient, {
        defaultSender: sender,
        appId: pluginState.retiAppId,
    });
}
async function getStakingPoolClient(poolAppId, sender = FEE_SINK) {
    if (!pluginState.algorand)
        throw new Error('Not initialized');
    return pluginState.algorand.client.getTypedAppClientById(StakingPoolClient, {
        defaultSender: sender,
        appId: poolAppId,
    });
}
// Initialize
async function handleInitialize(params) {
    pluginState.network = params.network || 'testnet';
    pluginState.apiServer = params.apiServer || 'https://testnet-api.algonode.cloud';
    pluginState.retiAppId = RETI_APP_IDS[pluginState.network] || RETI_APP_IDS.testnet;
    pluginState.algorand = AlgorandClient.fromConfig({
        algodConfig: { server: pluginState.apiServer, token: params.apiToken || '' }
    }).setDefaultValidityWindow(100); // 100 blocks (~5 min) - longer than AlgoKit's 10, shorter than SDK's 1000
    pluginState.initialized = true;
    logError(`Initialized on ${pluginState.network}, Reti app: ${pluginState.retiAppId}`);
    return { success: true, message: `Reti plugin initialized on ${pluginState.network}` };
}
// Execute command
async function handleExecute(params) {
    if (!pluginState.initialized)
        throw new Error('Plugin not initialized');
    const args = params.args || [];
    const context = params.context || {};
    // Check if network changed since initialization and update if needed
    if (context.network && context.network !== pluginState.network) {
        logError(`Network changed: ${pluginState.network} -> ${context.network}, reinitializing...`);
        pluginState.network = context.network;
        pluginState.retiAppId = RETI_APP_IDS[context.network] || RETI_APP_IDS.testnet;
        // Update algod client URL based on network
        const apiServer = context.network === 'mainnet'
            ? 'https://mainnet-api.algonode.cloud'
            : context.network === 'betanet'
                ? 'https://betanet-api.algonode.cloud'
                : 'https://testnet-api.algonode.cloud';
        pluginState.apiServer = apiServer;
        pluginState.algorand = AlgorandClient.fromConfig({
            algodConfig: { server: apiServer, token: '' }
        }).setDefaultValidityWindow(100);
        logError(`Reinitialized for ${pluginState.network}, Reti app: ${pluginState.retiAppId}`);
    }
    if (args.length === 0) {
        return {
            success: false,
            message: 'Usage: reti <subcommand> [args...]\n' +
                'Subcommands:\n' +
                '  list [count]                              - List validators (default: all)\n' +
                '  pools <validator_id>                      - Show pools for a validator\n' +
                '  deposit <amount> algo into <validator_id> for <account> - Stake ALGO\n' +
                '  withdraw <amount> algo from <pool_app_id> for <account> - Unstake (0 = all)\n' +
                '  balance <account>                         - Show staking positions'
        };
    }
    const subcommand = args[0];
    const subArgs = args.slice(1);
    try {
        switch (subcommand) {
            case 'list': return await handleList(subArgs);
            case 'pools': return await handlePools(subArgs);
            case 'deposit': return await handleDeposit(subArgs, context);
            case 'withdraw': return await handleWithdraw(subArgs, context);
            case 'balance': return await handleBalance(subArgs, context);
            default:
                return { success: false, message: `Unknown: ${subcommand}` };
        }
    }
    catch (error) {
        return { success: false, message: error.message };
    }
}
// List validators
async function handleList(args) {
    const client = await getValidatorClient();
    const numValidators = (await client.send.getNumValidators({ args: {} })).return;
    if (numValidators === 0n) {
        return { success: true, message: 'No validators found', data: { validators: [] } };
    }
    // Parse optional count argument (default: show all)
    let count = Number(numValidators);
    if (args.length > 0) {
        const requestedCount = parseInt(args[0], 10);
        if (!isNaN(requestedCount) && requestedCount > 0) {
            count = Math.min(requestedCount, Number(numValidators));
        }
    }
    let message = `Reti Validators (${pluginState.network}) - showing ${count} of ${numValidators}\n${'═'.repeat(60)}\n\n`;
    const validators = [];
    for (let i = 1; i <= count; i++) {
        try {
            const config = (await client.send.getValidatorConfig({ args: { validatorId: BigInt(i) } })).return;
            const state = (await client.send.getValidatorState({ args: { validatorId: BigInt(i) } })).return;
            const commission = Number(config.percentToValidator) / 10000;
            const totalStaked = Number(state.totalAlgoStaked) / 1_000_000;
            const minEntry = Number(config.minEntryStake) / 1_000_000;
            validators.push({
                id: i,
                name: `Validator #${i}`,
                commission: commission,
                totalStaked: totalStaked,
                numPools: Number(state.numPools),
                totalStakers: Number(state.totalStakers),
                minEntryStake: minEntry
            });
            message += `[${i}] Validator #${i}\n`;
            message += `    Pools: ${state.numPools} | Stakers: ${state.totalStakers} | Staked: ${formatAlgo(state.totalAlgoStaked)} ALGO\n`;
            message += `    Commission: ${commission.toFixed(2)}% | Min: ${minEntry.toFixed(2)} ALGO\n\n`;
        }
        catch (e) {
            logError(`Error fetching validator ${i}: ${e.message}`);
        }
    }
    return { success: true, message, data: { validators } };
}
// Show pools
async function handlePools(args) {
    if (args.length !== 1)
        throw new Error('Usage: reti pools <validator_id>');
    const validatorId = BigInt(args[0]);
    const client = await getValidatorClient();
    const rawPools = (await client.send.getPools({ args: { validatorId } })).return;
    let message = `Pools for Validator #${validatorId}\n${'═'.repeat(60)}\n\n`;
    const pools = [];
    if (rawPools.length === 0) {
        message += 'No pools found\n';
    }
    else {
        for (let i = 0; i < rawPools.length; i++) {
            const pool = rawPools[i];
            const appId = Number(pool[0]);
            const stakersCount = Number(pool[1]);
            const balance = Number(pool[2]) / 1_000_000;
            pools.push({
                id: i + 1,
                appId: appId,
                stakersCount: stakersCount,
                balance: balance
            });
            message += `Pool #${i + 1} (App ID: ${appId})\n`;
            message += `  Stakers: ${stakersCount} | Staked: ${formatAlgo(pool[2])} ALGO\n\n`;
        }
    }
    return { success: true, message, data: { pools } };
}
// Resolve address or alias to Algorand address
function resolveAddress(addrOrAlias, context) {
    // Normalize to uppercase (Algorand addresses are case-insensitive base32)
    const normalized = addrOrAlias.toUpperCase();
    // Check if it looks like an address
    if (/^[A-Z2-7]{58}$/.test(normalized)) {
        return normalized;
    }
    // It's an alias - try to resolve it (use original case for alias lookup)
    const resolved = context.addressMap?.[addrOrAlias];
    if (resolved)
        return resolved;
    throw new Error(`Unknown alias: ${addrOrAlias}`);
}
// Check if user already has stake with a specific validator
async function hasExistingStake(userAddr, validatorId) {
    try {
        // Build box name: "sps" prefix + 32-byte public key
        const prefix = Buffer.from('sps');
        const addrBytes = algosdk.decodeAddress(userAddr).publicKey;
        const boxName = Buffer.concat([prefix, Buffer.from(addrBytes)]);
        // Read box directly using algod client
        const algodClient = pluginState.algorand.client.algod;
        const boxResponse = await algodClient.getApplicationBoxByName(Number(pluginState.retiAppId), boxName).do();
        const boxValue = boxResponse.value;
        // Parse box value: 6 x (uint64, uint64, uint64) = 144 bytes
        for (let i = 0; i < 6; i++) {
            const offset = i * 24;
            const storedValidatorId = BigInt('0x' + Buffer.from(boxValue.slice(offset, offset + 8)).toString('hex'));
            if (storedValidatorId === validatorId) {
                return true;
            }
        }
        return false;
    }
    catch {
        // Box not found means no staking positions
        return false;
    }
}
// Deposit - uses SDK with populateAppCallResources
// Syntax: deposit <amount> algo into <validator_id> for <account>
async function handleDeposit(args, context) {
    // Parse: <amount> algo into <validator_id> for <account>
    if (args.length < 6 || args[1].toLowerCase() !== 'algo' || args[2].toLowerCase() !== 'into' || args[4].toLowerCase() !== 'for') {
        throw new Error('Usage: reti deposit <amount> algo into <validator_id> for <account>');
    }
    const stakeAmount = parseAmount(args[0]);
    const validatorId = BigInt(args[3]);
    const userAddr = resolveAddress(args[5], context);
    logError(`Deposit ${formatAlgo(stakeAmount)} ALGO to validator ${validatorId} from ${userAddr}`);
    const client = await getValidatorClient(userAddr);
    // Check min stake only for new stakers (not for additional deposits)
    const config = (await client.send.getValidatorConfig({ args: { validatorId } })).return;
    const alreadyStaking = await hasExistingStake(userAddr, validatorId);
    if (!alreadyStaking && stakeAmount < config.minEntryStake) {
        throw new Error(`Below minimum stake (${formatAlgo(config.minEntryStake)} ALGO)`);
    }
    // Check if validator has any pools
    const pools = (await client.send.getPools({ args: { validatorId } })).return;
    if (pools.length === 0) {
        throw new Error(`Validator #${validatorId} has no staking pools available`);
    }
    // Check MBR
    const needsMbr = (await client.send.doesStakerNeedToPayMbr({ args: { staker: userAddr } })).return;
    const mbrAmounts = (await client.send.getMbrAmounts({ args: {} })).return;
    // Find pool
    const findResult = await client.newGroup()
        .gas({ args: {} })
        .findPoolForStaker({
        args: { validatorId, staker: userAddr, amountToStake: stakeAmount },
        extraFee: AlgoAmount.MicroAlgos(1000),
    })
        .simulate({ skipSignatures: true, allowUnnamedResources: true });
    const poolInfo = findResult.returns[1];
    const [, poolId, poolAppId] = poolInfo[0];
    logError(`Found pool: poolId=${poolId}, poolAppId=${poolAppId}`);
    // Calculate payment
    let totalPayment = stakeAmount;
    if (needsMbr)
        totalPayment += mbrAmounts.addStakerMbr;
    // Create payment transaction
    const stakeTransferPayment = await client.appClient.createTransaction.fundAppAccount({
        sender: userAddr,
        amount: AlgoAmount.MicroAlgo(totalPayment),
    });
    // First simulate to calculate fees
    const simulateComposer = client.newGroup()
        .gas({ args: [], note: '1' })
        .gas({ args: [], note: '2' })
        .addStake({
        args: {
            stakedAmountPayment: stakeTransferPayment,
            validatorId: Number(validatorId),
            valueToVerify: 0n,
        },
        staticFee: AlgoAmount.MicroAlgos(240_000),
    });
    const simulateResults = await simulateComposer.simulate({
        skipSignatures: true,
        allowUnnamedResources: true,
    });
    // Clear group for reuse
    stakeTransferPayment.group = undefined;
    // Calculate fee from opcode budget
    const appBudgetAdded = simulateResults.simulateResponse.txnGroups[0].appBudgetAdded || 0;
    const feeAmount = AlgoAmount.MicroAlgos(1000 * Math.floor((appBudgetAdded + 699) / 700) - 1000);
    // Build final transaction group
    const composer = client.newGroup()
        .gas({ args: [], note: '1' })
        .gas({ args: [], note: '2' })
        .addStake({
        args: {
            stakedAmountPayment: stakeTransferPayment,
            validatorId: Number(validatorId),
            valueToVerify: 0n,
        },
        extraFee: feeAmount,
    });
    // Simulate to get built transactions
    const buildResult = await composer.simulate({ skipSignatures: true, allowUnnamedResources: true });
    // Create ATC and populate resources
    const atc = new algosdk.AtomicTransactionComposer();
    const emptySigner = algosdk.makeEmptyTransactionSigner();
    for (const txn of buildResult.transactions) {
        txn.group = undefined;
        atc.addTransaction({ txn, signer: emptySigner });
    }
    const algodClient = pluginState.algorand.client.algod;
    const populatedAtc = await populateAppCallResources(atc, algodClient);
    const txns = populatedAtc.buildGroup().map(t => t.txn);
    // Encode for apshell
    const transactions = txns.map((txn, i) => ({
        type: 'raw',
        encoded: Buffer.from(algosdk.encodeUnsignedTransaction(txn)).toString('base64'),
        description: i < 2 ? 'Gas (opcode budget)' :
            i === 2 ? `Payment to Reti (${formatAlgo(totalPayment)} ALGO)` : 'Reti addStake'
    }));
    let message = `Staking ${formatAlgo(stakeAmount)} ALGO with Validator #${validatorId}\n`;
    message += `Pool: #${poolId} (App ID: ${poolAppId})\n`;
    if (needsMbr) {
        message += `First-time staker MBR: ${formatAlgo(mbrAmounts.addStakerMbr)} ALGO\n`;
        message += `Total payment: ${formatAlgo(totalPayment)} ALGO\n`;
    }
    return {
        success: true,
        message,
        transactions,
        requiresApproval: true,
        data: { validatorId: Number(validatorId), poolAppId: Number(poolAppId) }
    };
}
// Withdraw - uses SDK with populateAppCallResources
// Syntax: withdraw <amount> algo from <pool_app_id> for <account>
async function handleWithdraw(args, context) {
    // Parse: <amount> algo from <pool_app_id> for <account>
    if (args.length < 6 || args[1].toLowerCase() !== 'algo' || args[2].toLowerCase() !== 'from' || args[4].toLowerCase() !== 'for') {
        throw new Error('Usage: reti withdraw <amount> algo from <pool_app_id> for <account>\n(Use 0 to withdraw all)');
    }
    const amountStr = args[0];
    const unstakeAmount = amountStr === '0' || amountStr === 'all' ? 0n : parseAmount(amountStr);
    const poolAppId = BigInt(args[3]);
    const userAddr = resolveAddress(args[5], context);
    logError(`Withdraw ${unstakeAmount === 0n ? 'all' : formatAlgo(unstakeAmount)} from pool ${poolAppId}`);
    const poolClient = await getStakingPoolClient(poolAppId, userAddr);
    // Get staker info
    const stakerInfo = (await poolClient.send.getStakerInfo({
        args: { staker: userAddr },
        extraFee: AlgoAmount.MicroAlgos(20000),
    })).return;
    if (stakerInfo.balance === 0n) {
        throw new Error('You have no stake in this pool');
    }
    const withdrawAmount = unstakeAmount === 0n ? stakerInfo.balance : unstakeAmount;
    // First simulate to calculate fees
    const simulateComposer = poolClient.newGroup()
        .gas({ args: [], note: '1', staticFee: AlgoAmount.MicroAlgos(0) })
        .gas({ args: [], note: '2', staticFee: AlgoAmount.MicroAlgos(0) })
        .removeStake({
        args: { staker: userAddr, amountToUnstake: unstakeAmount },
        staticFee: AlgoAmount.MicroAlgos(240_000),
    });
    const simulateResult = await simulateComposer.simulate({
        skipSignatures: true,
        allowUnnamedResources: true,
    });
    const appBudgetAdded = simulateResult.simulateResponse.txnGroups[0].appBudgetAdded || 0;
    const feeAmount = AlgoAmount.MicroAlgos(1000 * Math.floor((appBudgetAdded + 699) / 700) - 2000);
    // Build final transaction group
    const composer = poolClient.newGroup()
        .gas({ args: [], note: '1' })
        .gas({ args: [], note: '2' })
        .removeStake({
        args: { staker: userAddr, amountToUnstake: unstakeAmount },
        extraFee: feeAmount,
    });
    // Simulate to get built transactions
    const buildResult = await composer.simulate({ skipSignatures: true, allowUnnamedResources: true });
    // Create ATC and populate resources
    const atc = new algosdk.AtomicTransactionComposer();
    const emptySigner = algosdk.makeEmptyTransactionSigner();
    for (const txn of buildResult.transactions) {
        txn.group = undefined;
        atc.addTransaction({ txn, signer: emptySigner });
    }
    const algodClient = pluginState.algorand.client.algod;
    const populatedAtc = await populateAppCallResources(atc, algodClient);
    const txns = populatedAtc.buildGroup().map(t => t.txn);
    const transactions = txns.map((txn, i) => ({
        type: 'raw',
        encoded: Buffer.from(algosdk.encodeUnsignedTransaction(txn)).toString('base64'),
        description: i < 2 ? 'Gas (opcode budget)' : 'Reti removeStake'
    }));
    let message = `Withdrawing ${formatAlgo(withdrawAmount)} ALGO from Pool (App ID: ${poolAppId})\n`;
    message += `Current balance: ${formatAlgo(stakerInfo.balance)} ALGO\n`;
    return {
        success: true,
        message,
        transactions,
        requiresApproval: true,
        data: { poolAppId: Number(poolAppId), withdrawAmount: formatAlgo(withdrawAmount) }
    };
}
// Balance - reads directly from box state
async function handleBalance(args, context) {
    if (args.length === 0) {
        throw new Error('Usage: reti balance <address|alias>');
    }
    // Resolve address or alias
    const userAddr = resolveAddress(args[0], context);
    // Get display label (alias or truncated address)
    const addrLabel = context.addressMap ?
        Object.entries(context.addressMap).find(([_, v]) => v === userAddr)?.[0] || userAddr.slice(0, 8) + '...' :
        userAddr.slice(0, 8) + '...';
    let message = `Reti Staking Positions for ${addrLabel}\n${'═'.repeat(60)}\n\n`;
    // Read staker pool set directly from box state
    let stakerPools;
    try {
        // Build box name: "sps" prefix + 32-byte public key
        const prefix = Buffer.from('sps');
        const addrBytes = algosdk.decodeAddress(userAddr).publicKey;
        const boxName = Buffer.concat([prefix, Buffer.from(addrBytes)]);
        // Read box directly using algod client
        const algodClient = pluginState.algorand.client.algod;
        const boxResponse = await algodClient.getApplicationBoxByName(Number(pluginState.retiAppId), boxName).do();
        const boxValue = boxResponse.value;
        // Parse box value: 6 x (uint64, uint64, uint64) = 144 bytes
        stakerPools = [];
        for (let i = 0; i < 6; i++) {
            const offset = i * 24;
            const validatorId = BigInt('0x' + Buffer.from(boxValue.slice(offset, offset + 8)).toString('hex'));
            const poolId = BigInt('0x' + Buffer.from(boxValue.slice(offset + 8, offset + 16)).toString('hex'));
            const poolAppId = BigInt('0x' + Buffer.from(boxValue.slice(offset + 16, offset + 24)).toString('hex'));
            stakerPools.push([validatorId, poolId, poolAppId]);
        }
    }
    catch (e) {
        // Box not found (404) means no staking positions
        return { success: true, message: message + 'No staking positions found\n', data: { stakes: [], totalStaked: 0 } };
    }
    // Filter out empty pool entries (validatorId = 0 means empty slot)
    const activePools = stakerPools.filter(pool => pool[0] !== 0n);
    if (activePools.length === 0) {
        return { success: true, message: message + 'No staking positions found\n', data: { stakes: [], totalStaked: 0 } };
    }
    let totalStaked = 0n;
    const stakes = [];
    for (const pool of activePools) {
        const [validatorId, poolId, poolAppId] = pool;
        try {
            const poolClient = await getStakingPoolClient(poolAppId);
            const stakerInfo = (await poolClient.send.getStakerInfo({
                args: { staker: userAddr },
                extraFee: AlgoAmount.MicroAlgos(20000),
            })).return;
            if (stakerInfo.balance > 0n) {
                totalStaked += stakerInfo.balance;
                const balanceAlgo = Number(stakerInfo.balance) / 1_000_000;
                stakes.push({
                    poolAppId: Number(poolAppId),
                    validatorId: Number(validatorId),
                    balance: balanceAlgo
                });
                message += `Validator #${validatorId} / Pool #${poolId} (App ID: ${poolAppId})\n`;
                message += `  Balance: ${formatAlgo(stakerInfo.balance)} ALGO\n\n`;
            }
        }
        catch (e) {
            logError(`Error getting pool ${poolAppId}: ${e.message}`);
        }
    }
    if (totalStaked === 0n) {
        message += 'No staking positions found\n';
    }
    else {
        message += `${'─'.repeat(60)}\nTotal Staked: ${formatAlgo(totalStaked)} ALGO\n`;
    }
    return { success: true, message, data: { stakes, totalStaked: Number(totalStaked) / 1_000_000 } };
}
// Info and shutdown
function handleGetInfo() {
    return {
        name: 'reti',
        version: '1.0.0',
        description: 'Reti staking pool integration',
        commands: ['reti'],
        networks: ['testnet', 'mainnet'],
    };
}
function handleShutdown() {
    return { success: true };
}
// Main handler
rl.on('line', async (line) => {
    let request = { jsonrpc: '2.0', id: 0, method: '', params: {} };
    try {
        request = JSON.parse(line);
        const { id, method, params } = request;
        let result;
        switch (method) {
            case 'initialize':
                result = await handleInitialize(params);
                break;
            case 'execute':
                result = await handleExecute(params);
                break;
            case 'getInfo':
                result = handleGetInfo();
                break;
            case 'shutdown':
                result = handleShutdown();
                sendResponse(id, result);
                process.exit(0);
            default: throw new Error(`Unknown method: ${method}`);
        }
        sendResponse(id, result);
    }
    catch (error) {
        logError(`Error: ${error.message}`);
        sendResponse(request.id || null, null, { code: -32603, message: error.message });
    }
});
process.on('SIGTERM', () => process.exit(0));
process.on('SIGINT', () => process.exit(0));
logError('Reti plugin started');
