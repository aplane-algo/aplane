#!/usr/bin/env node

import * as readline from 'readline'
import algosdk from 'algosdk'
import { AlgorandClient, populateAppCallResources } from '@algorandfoundation/algokit-utils'
import { AlgoAmount } from '@algorandfoundation/algokit-utils/types/amount'
import { StakingPoolClient } from './contracts/StakingPoolClient.js'
import { ValidatorRegistryClient, type ValidatorConfig } from './contracts/ValidatorRegistryClient.js'

const GATING_TYPE_NONE = 0
const GATING_TYPE_ASSETS_CREATED_BY = 1
const GATING_TYPE_ASSET_ID = 2
const GATING_TYPE_CREATED_BY_NFD_ADDRESSES = 3
const GATING_TYPE_SEGMENT_OF_NFD = 4

type JSONValue = string | number | boolean | null | JSONValue[] | { [key: string]: JSONValue | undefined }

interface JsonRpcRequest {
  jsonrpc: string
  id: number | string | null
  method: string
  params: any
}

interface Context {
  accounts?: string[]
  assets?: Array<{ assetId: number; name?: string; unitName?: string; decimals: number }>
  addressMap?: Record<string, string>
  network?: string
  genesisId?: string
  genesisHash?: string
}

interface TransactionIntent {
  type: string
  encoded: string
}

interface ExecuteResult {
  success: boolean
  message?: string
  transactions?: TransactionIntent[]
  requiresApproval?: boolean
  data?: Record<string, JSONValue | undefined> | JSONValue[]
  presentation?: Presentation
}

interface Presentation {
  title?: string
  summary?: string
  sections?: PresentationSection[]
}

interface PresentationSection {
  kind: 'text' | 'key_value' | 'table'
  title?: string
  text?: string
  items?: PresentationItem[]
  columns?: string[]
  rows?: PresentationTableRow[]
}

interface PresentationItem {
  label: string
  value: string
}

interface PresentationTableRow {
  cells: string[]
}

interface NetworkDefaults {
  algodUrl?: string
  nfdApiUrl?: string
  retiAppId?: bigint
  feeSink?: string
}

interface PluginState {
  initialized: boolean
  network: string
  algodUrl: string
  algodToken: string
  nfdApiUrl: string
  retiAppId: bigint
  feeSink: string
  algorand: AlgorandClient | null
}

interface NfdRecord {
  appID?: number
  caAlgo?: string[]
  owner?: string
  name?: string
}

interface NfdSearchResult {
  nfds: NfdRecord[]
}

interface ImmutableValidatorSummary {
  [key: string]: JSONValue
  id: number
  owner: string
  minEntryStakeAlgo: string
  maxAlgoPerPoolAlgo: string
  epochRoundLength: number
  commissionPct: number
  poolsPerNode: number
}

const NETWORK_DEFAULTS: Record<string, NetworkDefaults> = {
  mainnet: {
    algodUrl: 'https://mainnet-api.4160.nodely.dev',
    nfdApiUrl: 'https://api.nf.domains',
    retiAppId: 2714516089n,
    feeSink: 'Y76M3MSY6DKBRHBL7C3NNDXGS5IIMQVQVUAB6MP4XEMMGVF2QWNPL226CA',
  },
  testnet: {
    algodUrl: 'https://testnet-api.4160.nodely.dev',
    nfdApiUrl: 'https://api.testnet.nf.domains',
    retiAppId: 734834614n,
    feeSink: 'A7NMWS3NT3IUDMLVO26ULGXGIIOUQ3ND2TXSER6EBGRZNOBOUIQXHIBGDE',
  },
  betanet: {
    algodUrl: 'https://betanet-api.4160.nodely.dev',
    nfdApiUrl: 'https://api.betanet.nf.domains',
    retiAppId: 2020356933n,
    feeSink: 'A7NMWS3NT3IUDMLVO26ULGXGIIOUQ3ND2TXSER6EBGRZNOBOUIQXHIBGDE',
  },
  fnet: {
    algodUrl: 'https://fnet-api.4160.nodely.dev',
    nfdApiUrl: 'https://api.testnet.nf.domains',
    retiAppId: 639070n,
    feeSink: 'FEESINK7OJKODDB5ZB4W2SRYPUSTOTK65UDCUYZ5DB4BW3VOHDHGO6JUNE',
  },
  localnet: {
    algodUrl: 'http://localhost:4001',
    nfdApiUrl: 'https://api.testnet.nf.domains',
    feeSink: 'A7NMWS3NT3IUDMLVO26ULGXGIIOUQ3ND2TXSER6EBGRZNOBOUIQXHIBGDE',
  },
  sandbox: {
    algodUrl: 'http://localhost:4001',
    nfdApiUrl: 'https://api.testnet.nf.domains',
    feeSink: 'A7NMWS3NT3IUDMLVO26ULGXGIIOUQ3ND2TXSER6EBGRZNOBOUIQXHIBGDE',
  },
}

const pluginState: PluginState = {
  initialized: false,
  network: '',
  algodUrl: '',
  algodToken: '',
  nfdApiUrl: '',
  retiAppId: 0n,
  feeSink: '',
  algorand: null,
}

const immutableValidatorCache = new Map<string, ImmutableValidatorSummary>()

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
  terminal: false,
})

function sendResponse(id: number | string | null, result: any, error: any = null): void {
  const response: any = { jsonrpc: '2.0', id }
  if (error) {
    response.error = error
  } else {
    response.result = result
  }
  process.stdout.write(`${JSON.stringify(response)}\n`)
}

function logError(message: string): void {
  process.stderr.write(`[reti-plugin] ${message}\n`)
}

function parseAmount(amountStr: string): bigint {
  if (!/^\d+(\.\d{1,6})?$/.test(amountStr)) {
    throw new Error(`invalid amount: ${amountStr}`)
  }

  const [wholePart, fractionalPart = ''] = amountStr.split('.')
  const whole = BigInt(wholePart)
  const fractional = BigInt(fractionalPart.padEnd(6, '0'))
  const amount = whole * 1_000_000n + fractional
  if (amount <= 0n) {
    throw new Error(`invalid amount: ${amountStr}`)
  }
  return amount
}

function formatAlgo(microAlgos: bigint | number): string {
  const value = typeof microAlgos === 'bigint' ? microAlgos : BigInt(microAlgos)
  const sign = value < 0n ? '-' : ''
  const absolute = value < 0n ? -value : value
  const whole = absolute / 1_000_000n
  const fractional = (absolute % 1_000_000n).toString().padStart(6, '0')
  return `${sign}${whole.toString()}.${fractional}`
}

function abbreviateAddress(address: string): string {
  if (address.length <= 23) {
    return address
  }
  return `${address.slice(0, 10)}...${address.slice(-10)}`
}

function makeRewardTokenOptInTxn(
  userAddr: string,
  rewardTokenId: bigint,
  suggestedParams: algosdk.SuggestedParams,
): algosdk.Transaction {
  return algosdk.makeAssetTransferTxnWithSuggestedParamsFromObject({
    sender: userAddr,
    receiver: userAddr,
    amount: 0,
    assetIndex: Number(rewardTokenId),
    suggestedParams,
  })
}

function makeKeyValueItems(
  items: Array<PresentationItem | undefined>,
): PresentationItem[] {
  return items.filter((item): item is PresentationItem => Boolean(item))
}

function getEnvBigInt(...names: string[]): bigint | undefined {
  for (const name of names) {
    const value = process.env[name]
    if (value && /^\d+$/.test(value)) {
      return BigInt(value)
    }
  }
  return undefined
}

function getEnvString(...names: string[]): string | undefined {
  for (const name of names) {
    const value = process.env[name]
    if (value && value.trim() !== '') {
      return value.trim()
    }
  }
  return undefined
}

function getNetworkDefaults(network: string): NetworkDefaults {
  return NETWORK_DEFAULTS[network] || NETWORK_DEFAULTS.testnet
}

function resolveAddress(addrOrAlias: string, context: Context): string {
  const normalized = addrOrAlias.toUpperCase()
  if (/^[A-Z2-7]{58}$/.test(normalized)) {
    return normalized
  }
  const resolved = context.addressMap?.[addrOrAlias]
  if (resolved) {
    return resolved
  }
  throw new Error(`unknown alias: ${addrOrAlias}`)
}

async function configurePlugin(options: {
  network?: string
  algodUrl?: string
  algodToken?: string
}): Promise<void> {
  const network = options.network || pluginState.network || 'testnet'
  const defaults = getNetworkDefaults(network)
  const algodUrl = options.algodUrl || defaults.algodUrl || pluginState.algodUrl
  const algodToken = options.algodToken ?? pluginState.algodToken ?? ''
  const retiAppId = getEnvBigInt('RETI_APP_ID', 'RETI_APPID') || defaults.retiAppId || 0n
  const feeSink = defaults.feeSink || pluginState.feeSink
  const nfdApiUrl =
    getEnvString('RETI_NFD_API_URL', 'ALGO_NFD_URL') || defaults.nfdApiUrl || pluginState.nfdApiUrl

  pluginState.network = network
  pluginState.algodUrl = algodUrl
  pluginState.algodToken = algodToken
  pluginState.nfdApiUrl = nfdApiUrl
  pluginState.retiAppId = retiAppId
  pluginState.feeSink = feeSink
  pluginState.algorand = AlgorandClient.fromConfig({
    algodConfig: {
      server: algodUrl,
      token: algodToken,
    },
  }).setDefaultValidityWindow(100)
  pluginState.initialized = true
}

function ensureInitialized(): void {
  if (!pluginState.initialized || !pluginState.algorand) {
    throw new Error('plugin not initialized')
  }
}

function ensureRetiAppConfigured(): void {
  if (pluginState.retiAppId === 0n) {
    throw new Error(
      `Reti app ID is not configured for network ${pluginState.network}; set RETI_APP_ID or RETI_APPID`,
    )
  }
}

async function handleInitialize(params: any): Promise<any> {
  await configurePlugin({
    network: params.network || 'testnet',
    algodUrl: params.algodUrl,
    algodToken: params.algodToken,
  })

  const appIdMessage =
    pluginState.retiAppId === 0n
      ? 'Reti app id unset'
      : `Reti app id ${pluginState.retiAppId.toString()}`
  return {
    success: true,
    message: `Reti plugin initialized on ${pluginState.network} (${appIdMessage})`,
    version: params.version,
  }
}

async function ensureContextNetwork(context: Context): Promise<void> {
  if (!context.network || context.network === pluginState.network) {
    return
  }
  await configurePlugin({ network: context.network })
  logError(`Reconfigured for network ${pluginState.network} (app ${pluginState.retiAppId.toString() || 'unset'})`)
}

async function getValidatorClient(sender = pluginState.feeSink): Promise<ValidatorRegistryClient> {
  ensureInitialized()
  ensureRetiAppConfigured()
  return pluginState.algorand!.client.getTypedAppClientById(ValidatorRegistryClient, {
    defaultSender: sender,
    appId: pluginState.retiAppId,
  })
}

async function getStakingPoolClient(poolAppId: bigint, sender = pluginState.feeSink): Promise<StakingPoolClient> {
  ensureInitialized()
  return pluginState.algorand!.client.getTypedAppClientById(StakingPoolClient, {
    defaultSender: sender,
    appId: poolAppId,
  })
}

function getImmutableValidatorCacheKey(validatorId: bigint): string {
  return `${pluginState.network}:${pluginState.retiAppId.toString()}:${validatorId.toString()}`
}

function summarizeImmutableValidatorConfig(config: ValidatorConfig, validatorId: bigint): ImmutableValidatorSummary {
  return {
    id: Number(config.id || validatorId),
    owner: config.owner,
    minEntryStakeAlgo: formatAlgo(config.minEntryStake),
    maxAlgoPerPoolAlgo: formatAlgo(config.maxAlgoPerPool),
    epochRoundLength: Number(config.epochRoundLength),
    commissionPct: Number(config.percentToValidator) / 10000,
    poolsPerNode: Number(config.poolsPerNode),
  }
}

async function fetchImmutableValidatorSummary(validatorId: bigint): Promise<ImmutableValidatorSummary> {
  const key = getImmutableValidatorCacheKey(validatorId)
  const cached = immutableValidatorCache.get(key)
  if (cached) {
    return cached
  }

  const client = await getValidatorClient()
  const config = (await client.send.getValidatorConfig({ args: { validatorId } })).return
  if (!config) {
    throw new Error(`validator ${validatorId.toString()} not found`)
  }

  const summary = summarizeImmutableValidatorConfig(config, validatorId)
  immutableValidatorCache.set(key, summary)
  return summary
}

async function mapWithConcurrency<T, R>(
  items: T[],
  concurrency: number,
  mapper: (item: T) => Promise<R>,
): Promise<R[]> {
  const results = new Array<R>(items.length)
  let nextIndex = 0
  const workerCount = Math.min(Math.max(concurrency, 1), items.length)
  const workers = Array.from({ length: workerCount }, async () => {
    while (nextIndex < items.length) {
      const currentIndex = nextIndex++
      results[currentIndex] = await mapper(items[currentIndex])
    }
  })
  await Promise.all(workers)
  return results
}

async function fetchAccountInformation(address: string, exclude = 'none'): Promise<any> {
  ensureInitialized()
  return pluginState.algorand!.client.algod.accountInformation(address).exclude(exclude).do()
}

async function fetchAssetHoldings(address: string): Promise<any[]> {
  const accountInfo = await fetchAccountInformation(address)
  return accountInfo.assets || []
}

async function fetchAccountAssetInformation(address: string, assetId: bigint): Promise<any> {
  ensureInitialized()
  return pluginState.algorand!.client.algod.accountAssetInformation(address, assetId).do()
}

async function isOptedInToAsset(address: string, assetId: bigint): Promise<boolean> {
  try {
    await fetchAccountAssetInformation(address, assetId)
    return true
  } catch (error: any) {
    if (error?.response?.status === 404) {
      return false
    }
    throw error
  }
}

async function fetchNfd(nameOrId: string | bigint | number, view: 'tiny' | 'brief' | 'full' = 'tiny'): Promise<NfdRecord> {
  const url = new URL(`/nfd/${nameOrId}`, pluginState.nfdApiUrl)
  url.searchParams.set('view', view)
  const response = await fetch(url)
  if (!response.ok) {
    throw new Error(`failed to fetch NFD ${nameOrId}: ${response.status}`)
  }
  return (await response.json()) as NfdRecord
}

async function searchNfdSegments(parentAppID: bigint, owner: string): Promise<NfdSearchResult> {
  const url = new URL('/nfd/v2/search', pluginState.nfdApiUrl)
  url.searchParams.set('parentAppID', parentAppID.toString())
  url.searchParams.append('state', 'owned')
  url.searchParams.set('owner', owner)
  url.searchParams.set('view', 'brief')
  url.searchParams.set('limit', '1')
  const response = await fetch(url)
  if (!response.ok) {
    throw new Error(`failed to search NFD segments: ${response.status}`)
  }
  return (await response.json()) as NfdSearchResult
}

function findValueToVerify(heldAssets: any[], gatingAssets: bigint[], minBalance: bigint): bigint {
  const asset = heldAssets.find((holding) => {
    const heldAssetId = BigInt(holding.assetId)
    const heldAmount = BigInt(holding.amount)
    return gatingAssets.includes(heldAssetId) && heldAmount >= minBalance
  })
  return asset ? BigInt(asset.assetId) : 0n
}

async function fetchValueToVerify(config: any, staker: string): Promise<bigint> {
  const entryGatingType = Number(config.entryGatingType || 0)
  if (entryGatingType === GATING_TYPE_NONE) {
    return 0n
  }

  const heldAssets = await fetchAssetHoldings(staker)
  const minBalance = BigInt(config.gatingAssetMinBalance || 0)
  const entryGatingAssets = (config.entryGatingAssets || []).map((value: bigint) => BigInt(value))

  if (entryGatingType === GATING_TYPE_ASSETS_CREATED_BY) {
    const creatorInfo = await fetchAccountInformation(config.entryGatingAddress)
    const createdAssets = (creatorInfo.createdAssets || []).map((asset: any) => BigInt(asset.index))
    return findValueToVerify(heldAssets, createdAssets, minBalance)
  }

  if (entryGatingType === GATING_TYPE_ASSET_ID) {
    return findValueToVerify(
      heldAssets,
      entryGatingAssets.filter((asset: bigint) => asset !== 0n),
      minBalance,
    )
  }

  if (entryGatingType === GATING_TYPE_CREATED_BY_NFD_ADDRESSES) {
    const nfd = await fetchNfd(entryGatingAssets[0], 'tiny')
    const creatorAddresses = nfd.caAlgo || []
    const assetIds: bigint[] = []
    for (const creatorAddress of creatorAddresses) {
      const creatorInfo = await fetchAccountInformation(creatorAddress)
      for (const asset of creatorInfo.createdAssets || []) {
        assetIds.push(BigInt(asset.index))
      }
    }
    return findValueToVerify(heldAssets, assetIds, minBalance)
  }

  if (entryGatingType === GATING_TYPE_SEGMENT_OF_NFD) {
    const result = await searchNfdSegments(entryGatingAssets[0], staker)
    if (!result.nfds || result.nfds.length === 0 || !result.nfds[0].appID) {
      return 0n
    }
    return BigInt(result.nfds[0].appID)
  }

  return 0n
}

async function fetchStakedPoolsForAccount(staker: string): Promise<Array<{ id: bigint; poolId: bigint; poolAppId: bigint }>> {
  const validatorClient = await getValidatorClient()
  const result = await validatorClient.send.getStakedPoolsForAccount({ args: { staker } })
  const pools = result.return || []

  const deduped = new Map<string, { id: bigint; poolId: bigint; poolAppId: bigint }>()
  for (const [validatorId, poolId, poolAppId] of pools) {
    const key = `${validatorId.toString()}:${poolId.toString()}:${poolAppId.toString()}`
    deduped.set(key, { id: validatorId, poolId, poolAppId })
  }
  return Array.from(deduped.values())
}

async function resolveWithdrawPoolAppId(
  staker: string,
  poolRef: string,
): Promise<{ poolAppId: bigint; validatorId?: bigint; poolId?: bigint }> {
  const requested = BigInt(poolRef)
  const stakedPools = await fetchStakedPoolsForAccount(staker)

  if (stakedPools.length === 0) {
    throw new Error('no Réti staking positions found for this account')
  }

  const exactPoolAppId = stakedPools.find((pool) => pool.poolAppId === requested)
  if (exactPoolAppId) {
    return {
      poolAppId: exactPoolAppId.poolAppId,
      validatorId: exactPoolAppId.id,
      poolId: exactPoolAppId.poolId,
    }
  }

  const knownPools = stakedPools
    .map((pool) => `validator #${pool.id.toString()} pool #${pool.poolId.toString()} => app ${pool.poolAppId.toString()}`)
    .join(', ')
  throw new Error(`unknown Réti pool app ID ${poolRef}; use reti balance to find a valid app ID (${knownPools})`)
}

async function resolveWithdrawValidatorPool(
  staker: string,
  validatorRef: string,
  poolRef: string,
): Promise<{ poolAppId: bigint; validatorId: bigint; poolId: bigint }> {
  const validatorId = BigInt(validatorRef)
  const poolId = BigInt(poolRef)
  const stakedPools = await fetchStakedPoolsForAccount(staker)

  if (stakedPools.length === 0) {
    throw new Error('no Réti staking positions found for this account')
  }

  const match = stakedPools.find((pool) => pool.id === validatorId && pool.poolId === poolId)
  if (match) {
    return {
      poolAppId: match.poolAppId,
      validatorId: match.id,
      poolId: match.poolId,
    }
  }

  const knownPools = stakedPools
    .map((pool) => `validator #${pool.id.toString()} pool #${pool.poolId.toString()} => app ${pool.poolAppId.toString()}`)
    .join(', ')
  throw new Error(
    `unknown Réti validator/pool reference validator ${validatorRef} pool ${poolRef}; known positions: ${knownPools}`,
  )
}

async function parseWithdrawTarget(
  args: string[],
  context: Context,
): Promise<{ userAddr: string; resolvedPool: { poolAppId: bigint; validatorId?: bigint; poolId?: bigint } }> {
  if (args.length >= 9 && args[3].toLowerCase() === 'validator' && args[5].toLowerCase() === 'pool' && args[7].toLowerCase() === 'for') {
    const userAddr = resolveAddress(args[8], context)
    const resolvedPool = await resolveWithdrawValidatorPool(userAddr, args[4], args[6])
    return { userAddr, resolvedPool }
  }

  if (args.length >= 7 && args[3].toLowerCase() === 'app' && args[5].toLowerCase() === 'for') {
    const userAddr = resolveAddress(args[6], context)
    const resolvedPool = await resolveWithdrawPoolAppId(userAddr, args[4])
    return { userAddr, resolvedPool }
  }

  throw new Error(
    'Usage: reti withdraw <amount|all> algo from app <pool_app_id> for <account>\n' +
      '   or: reti withdraw <amount|all> algo from validator <validator_id> pool <pool_id> for <account>',
  )
}

async function getRewardTokenIdForPool(staker: string, poolAppId: bigint): Promise<bigint> {
  const stakedPools = await fetchStakedPoolsForAccount(staker)
  const pool = stakedPools.find((entry) => entry.poolAppId === poolAppId)
  if (!pool) {
    return 0n
  }

  const validatorClient = await getValidatorClient()
  const config = (await validatorClient.send.getValidatorConfig({ args: { validatorId: pool.id } })).return
  return config ? BigInt(config.rewardTokenId) : 0n
}

async function buildUnsignedGroup(txns: algosdk.Transaction[]): Promise<TransactionIntent[]> {
  const atc = new algosdk.AtomicTransactionComposer()
  const emptySigner = algosdk.makeEmptyTransactionSigner()
  for (const txn of txns) {
    txn.group = undefined
    atc.addTransaction({ txn, signer: emptySigner })
  }

  const populatedAtc = await populateAppCallResources(atc, pluginState.algorand!.client.algod)
  return populatedAtc.buildGroup().map((entry) => ({
    type: 'raw',
    encoded: Buffer.from(algosdk.encodeUnsignedTransaction(entry.txn)).toString('base64'),
  }))
}

async function fetchValidatorSummary(validatorId: bigint): Promise<{
  id: number
  commissionPct: number
  totalStakedAlgo: string
  numPools: number
  totalStakers: number
  minEntryStakeAlgo: string
  gatingType: number
  rewardTokenId: number
  owner: string
  manager: string
  pools: Array<{ poolId: number; appId: number; totalStakers: number; totalStakedAlgo: string }>
}> {
  const client = await getValidatorClient()
  const [configResult, stateResult, ownerManagerResult, poolsResult] = await Promise.all([
    client.send.getValidatorConfig({ args: { validatorId } }),
    client.send.getValidatorState({ args: { validatorId } }),
    client.send.getValidatorOwnerAndManager({ args: { validatorId } }),
    client.send.getPools({ args: { validatorId } }),
  ])

  const config = configResult.return
  const state = stateResult.return
  const ownerManager = ownerManagerResult.return
  const pools = poolsResult.return || []

  if (!config || !state || !ownerManager) {
    throw new Error(`validator ${validatorId.toString()} not found`)
  }

  const [owner, manager] = ownerManager

  return {
    id: Number(validatorId),
    commissionPct: Number(config.percentToValidator) / 10000,
    totalStakedAlgo: formatAlgo(state.totalAlgoStaked),
    numPools: Number(state.numPools),
    totalStakers: Number(state.totalStakers),
    minEntryStakeAlgo: formatAlgo(config.minEntryStake),
    gatingType: Number(config.entryGatingType),
    rewardTokenId: Number(config.rewardTokenId),
    owner,
    manager,
    pools: pools.map(([poolAppId, totalStakers, totalAlgoStaked], index) => ({
      poolId: index + 1,
      appId: Number(poolAppId),
      totalStakers: Number(totalStakers),
      totalStakedAlgo: formatAlgo(totalAlgoStaked),
    })),
  }
}

async function handleList(args: string[]): Promise<ExecuteResult> {
  const client = await getValidatorClient()
  const numValidators = (await client.send.getNumValidators({ args: {} })).return || 0n
  if (numValidators === 0n) {
    return {
      success: true,
      message: 'No validators found',
      data: { validators: [] },
      presentation: {
        title: 'Reti Validators',
        summary: `Network: ${pluginState.network}`,
        sections: [{ kind: 'text', text: 'No validators found' }],
      },
    }
  }

  let count = Number(numValidators)
  if (args.length > 0) {
    const requested = Number(args[0])
    if (Number.isFinite(requested) && requested > 0) {
      count = Math.min(requested, Number(numValidators))
    }
  }

  const validatorIds = Array.from({ length: count }, (_, index) => BigInt(index + 1))
  const loadedValidators = await mapWithConcurrency(validatorIds, 8, async (validatorId) => {
    try {
      return await fetchImmutableValidatorSummary(validatorId)
    } catch (error: any) {
      logError(`Error fetching validator ${validatorId.toString()}: ${error.message}`)
      return undefined
    }
  })
  const validators = loadedValidators.filter((validator): validator is ImmutableValidatorSummary => Boolean(validator))

  return {
    success: true,
    message: `Loaded ${validators.length} validator config(s) from Réti on ${pluginState.network}`,
    data: { validators },
    presentation: {
      title: 'Reti Validators',
      summary: `Network: ${pluginState.network}. Showing ${validators.length} of ${numValidators.toString()} validator(s).`,
      sections: [{
        kind: 'table',
        columns: ['ID', 'Owner', 'Commission', 'Min ALGO', 'Max/Pool ALGO', 'Epoch', 'Pools/Node'],
        rows: validators.map((validator) => ({
          cells: [
            validator.id.toString(),
            abbreviateAddress(validator.owner),
            `${validator.commissionPct.toFixed(2)}%`,
            validator.minEntryStakeAlgo,
            validator.maxAlgoPerPoolAlgo,
            validator.epochRoundLength.toString(),
            validator.poolsPerNode.toString(),
          ],
        })),
      }],
    },
  }
}

async function handleValidator(args: string[]): Promise<ExecuteResult> {
  if (args.length !== 1) {
    throw new Error('Usage: reti validator <validator_id>')
  }

  const validatorId = BigInt(args[0])
  const validator = await fetchValidatorSummary(validatorId)

  return {
    success: true,
    message: `Loaded validator #${validator.id}`,
    data: { validator },
    presentation: {
      title: `Reti Validator #${validator.id}`,
      sections: [
        {
          kind: 'key_value',
          items: [
            { label: 'Owner', value: validator.owner },
            { label: 'Manager', value: validator.manager },
            { label: 'Commission', value: `${validator.commissionPct.toFixed(2)}%` },
            { label: 'Min Entry Stake', value: `${validator.minEntryStakeAlgo} ALGO` },
            { label: 'Staked', value: `${validator.totalStakedAlgo} ALGO` },
            { label: 'Stakers', value: validator.totalStakers.toString() },
            { label: 'Pools', value: validator.numPools.toString() },
            { label: 'Gating', value: validator.gatingType.toString() },
            { label: 'Reward Token', value: validator.rewardTokenId > 0 ? validator.rewardTokenId.toString() : '-' },
          ],
        },
        {
          kind: 'table',
          title: 'Pools',
          columns: ['Pool', 'App ID', 'Stakers', 'Staked ALGO'],
          rows: validator.pools.map((pool) => ({
            cells: [
              pool.poolId.toString(),
              pool.appId.toString(),
              pool.totalStakers.toString(),
              pool.totalStakedAlgo,
            ],
          })),
        },
      ],
    },
  }
}

async function handlePools(args: string[]): Promise<ExecuteResult> {
  if (args.length !== 1) {
    throw new Error('Usage: reti pools <validator_id>')
  }
  const validatorId = BigInt(args[0])
  const client = await getValidatorClient()
  const pools = (await client.send.getPools({ args: { validatorId } })).return || []

  const data = pools.map(([poolAppId, totalStakers, totalAlgoStaked], index) => ({
    poolId: index + 1,
    appId: Number(poolAppId),
    totalStakers: Number(totalStakers),
    totalStakedAlgo: formatAlgo(totalAlgoStaked),
  }))

  return {
    success: true,
    message:
      data.length === 0
        ? `No pools found for validator #${validatorId.toString()}`
        : `Loaded ${data.length} pool(s) for validator #${validatorId.toString()}`,
    data: { pools: data },
    presentation: {
      title: `Validator #${validatorId.toString()} Pools`,
      summary:
        data.length === 0
          ? 'No pools found'
          : `${data.length} pool(s) available for staking`,
      sections: data.length === 0
        ? [{ kind: 'text', text: 'No pools found' }]
        : [{
            kind: 'table',
            columns: ['Pool', 'App ID', 'Stakers', 'Staked ALGO'],
            rows: data.map((pool) => ({
              cells: [
                pool.poolId.toString(),
                pool.appId.toString(),
                pool.totalStakers.toString(),
                pool.totalStakedAlgo,
              ],
            })),
          }],
    },
  }
}

async function handleDeposit(args: string[], context: Context): Promise<ExecuteResult> {
  if (
    args.length < 6 ||
    args[1].toLowerCase() !== 'algo' ||
    args[2].toLowerCase() !== 'into' ||
    args[4].toLowerCase() !== 'for'
  ) {
    throw new Error('Usage: reti deposit <amount> algo into <validator_id> for <account>')
  }

  const stakeAmount = parseAmount(args[0])
  const validatorId = BigInt(args[3])
  const userAddr = resolveAddress(args[5], context)

  const validatorClient = await getValidatorClient(userAddr)
  const config = (await validatorClient.send.getValidatorConfig({ args: { validatorId } })).return
  if (!config) {
    throw new Error(`validator ${validatorId.toString()} not found`)
  }

  const pools = (await validatorClient.send.getPools({ args: { validatorId } })).return || []
  if (pools.length === 0) {
    throw new Error(`validator #${validatorId.toString()} has no staking pools available`)
  }

  const stakedPools = await fetchStakedPoolsForAccount(userAddr)
  const alreadyStakingValidator = stakedPools.some((pool) => pool.id === validatorId)
  if (!alreadyStakingValidator && stakeAmount < BigInt(config.minEntryStake)) {
    throw new Error(`below minimum stake (${formatAlgo(config.minEntryStake)} ALGO)`)
  }

  const valueToVerify = await fetchValueToVerify(config, userAddr)
  if (Number(config.entryGatingType) !== GATING_TYPE_NONE && valueToVerify === 0n) {
    throw new Error('staker does not meet validator entry gating requirements')
  }

  const findResult = await validatorClient
    .newGroup()
    .gas({ args: {} })
    .findPoolForStaker({
      args: { validatorId, staker: userAddr, amountToStake: stakeAmount },
      extraFee: AlgoAmount.MicroAlgos(1000),
    })
    .simulate({ skipSignatures: true, allowUnnamedResources: true })

  const failureMessage = findResult.simulateResponse.txnGroups[0].failureMessage
  if (failureMessage || !findResult.returns[1]) {
    throw new Error(`error finding pool for staker: ${failureMessage || 'no pool found'}`)
  }

  const [[_, poolId, poolAppId]] = findResult.returns[1]
  const needsMbr =
    (await validatorClient.send.doesStakerNeedToPayMbr({ args: { staker: userAddr } })).return || false
  const mbrAmounts = (await validatorClient.send.getMbrAmounts({ args: {} })).return
  const totalStakeAmount =
    stakeAmount + (needsMbr && mbrAmounts ? BigInt(mbrAmounts.addStakerMbr) : 0n)

  const stakeTransferPayment = await validatorClient.appClient.createTransaction.fundAppAccount({
    sender: userAddr,
    amount: AlgoAmount.MicroAlgo(totalStakeAmount),
  })

  const rewardTokenId = BigInt(config.rewardTokenId || 0)
  const needsOptInTxn =
    rewardTokenId > 0n && !(await isOptedInToAsset(userAddr, rewardTokenId))
  const suggestedParams = await pluginState.algorand!.getSuggestedParams()
  const rewardTokenOptInTxn = needsOptInTxn
    ? makeRewardTokenOptInTxn(userAddr, rewardTokenId, suggestedParams)
    : undefined

  let simulateComposer: any = validatorClient
    .newGroup()
    .gas({ args: [], note: '1' })
    .gas({ args: [], note: '2' })
  if (rewardTokenOptInTxn) {
    simulateComposer = simulateComposer.addTransaction(rewardTokenOptInTxn)
  }
  simulateComposer = simulateComposer
    .addStake({
      args: {
        stakedAmountPayment: stakeTransferPayment,
        validatorId: Number(validatorId),
        valueToVerify,
      },
      staticFee: AlgoAmount.MicroAlgos(240_000),
      validityWindow: 200,
    })

  const simulateResults = await simulateComposer.simulate({
    skipSignatures: true,
    allowUnnamedResources: true,
  })

  stakeTransferPayment.group = undefined
  const appBudgetAdded = Number(simulateResults.simulateResponse.txnGroups[0].appBudgetAdded || 0)
  const feeAmount = AlgoAmount.MicroAlgos(1000 * Math.floor((appBudgetAdded + 699) / 700) - 1000)

  const finalRewardTokenOptInTxn = rewardTokenOptInTxn
    ? makeRewardTokenOptInTxn(userAddr, rewardTokenId, suggestedParams)
    : undefined

  let composer: any = validatorClient
    .newGroup()
    .gas({ args: [], note: '1' })
    .gas({ args: [], note: '2' })
  if (finalRewardTokenOptInTxn) {
    composer = composer.addTransaction(finalRewardTokenOptInTxn)
  }
  composer = composer
    .addStake({
      args: {
        stakedAmountPayment: stakeTransferPayment,
        validatorId: Number(validatorId),
        valueToVerify,
      },
      extraFee: feeAmount,
    })

  const buildResult = await composer.simulate({ skipSignatures: true, allowUnnamedResources: true })
  const transactions = await buildUnsignedGroup(buildResult.transactions)

  const stakeAmountAlgo = formatAlgo(stakeAmount)
  const totalStakeAmountAlgo = formatAlgo(totalStakeAmount)
  const addStakerMbrAlgo =
    needsMbr && mbrAmounts ? formatAlgo(mbrAmounts.addStakerMbr) : undefined

  return {
    success: true,
    message: `Prepared Réti deposit into validator #${validatorId.toString()}`,
    transactions,
    requiresApproval: true,
    data: {
      account: userAddr,
      validatorId: Number(validatorId),
      poolId: Number(poolId),
      poolAppId: Number(poolAppId),
      stakeAmountAlgo,
      totalPaymentAlgo: totalStakeAmountAlgo,
      addStakerMbrAlgo,
      rewardTokenId: rewardTokenId > 0n ? Number(rewardTokenId) : undefined,
      rewardTokenOptInRequired: needsOptInTxn,
    },
    presentation: {
      title: 'Réti Deposit',
      summary: `Stake ${stakeAmountAlgo} ALGO with validator #${validatorId.toString()}`,
      sections: [{
        kind: 'key_value',
        items: makeKeyValueItems([
          { label: 'Account', value: userAddr },
          { label: 'Validator', value: validatorId.toString() },
          { label: 'Pool', value: `${poolId.toString()} (App ID: ${poolAppId.toString()})` },
          { label: 'Stake Amount', value: `${stakeAmountAlgo} ALGO` },
          addStakerMbrAlgo
            ? { label: 'First-Time MBR', value: `${addStakerMbrAlgo} ALGO` }
            : undefined,
          needsOptInTxn
            ? { label: 'Reward Token Opt-In', value: rewardTokenId.toString() }
            : undefined,
          { label: 'Total Payment', value: `${totalStakeAmountAlgo} ALGO` },
        ]),
      }],
    },
  }
}

async function handleWithdraw(args: string[], context: Context): Promise<ExecuteResult> {
  if (args.length < 7 || args[1].toLowerCase() !== 'algo' || args[2].toLowerCase() !== 'from') {
    throw new Error(
      'Usage: reti withdraw <amount|all> algo from app <pool_app_id> for <account>\n' +
        '   or: reti withdraw <amount|all> algo from validator <validator_id> pool <pool_id> for <account>',
    )
  }

  const unstakeAmount =
    args[0].toLowerCase() === 'all' || args[0] === '0' ? 0n : parseAmount(args[0])
  const { userAddr, resolvedPool } = await parseWithdrawTarget(args, context)
  const poolAppId = resolvedPool.poolAppId

  const poolClient = await getStakingPoolClient(poolAppId, userAddr)
  const stakerInfo = await poolClient.getStakerInfo({
    args: { staker: userAddr },
    extraFee: AlgoAmount.MicroAlgos(20_000),
  })

  if (!stakerInfo || BigInt(stakerInfo.balance) === 0n) {
    throw new Error('you have no stake in this pool')
  }

  const withdrawAmount = unstakeAmount === 0n ? BigInt(stakerInfo.balance) : unstakeAmount
  const rewardTokenId = await getRewardTokenIdForPool(userAddr, poolAppId)
  const needsOptInTxn =
    rewardTokenId > 0n && !(await isOptedInToAsset(userAddr, rewardTokenId))
  const suggestedParams = await pluginState.algorand!.getSuggestedParams()
  const rewardTokenOptInTxn = needsOptInTxn
    ? makeRewardTokenOptInTxn(userAddr, rewardTokenId, suggestedParams)
    : undefined

  let simulateComposer: any = poolClient
    .newGroup()
    .gas({ args: [], note: '1', staticFee: AlgoAmount.MicroAlgos(0) })
    .gas({ args: [], note: '2', staticFee: AlgoAmount.MicroAlgos(0) })
  if (rewardTokenOptInTxn) {
    simulateComposer = simulateComposer.addTransaction(rewardTokenOptInTxn)
  }
  simulateComposer = simulateComposer
    .removeStake({
      args: { staker: userAddr, amountToUnstake: unstakeAmount },
      staticFee: AlgoAmount.MicroAlgos(240_000),
    })

  const simulateResult = await simulateComposer.simulate({
    skipSignatures: true,
    allowUnnamedResources: true,
  })
  const appBudgetAdded = Number(simulateResult.simulateResponse.txnGroups[0].appBudgetAdded || 0)
  const feeAmount = AlgoAmount.MicroAlgos(1000 * Math.floor((appBudgetAdded + 699) / 700) - 2000)

  const finalRewardTokenOptInTxn = rewardTokenOptInTxn
    ? makeRewardTokenOptInTxn(userAddr, rewardTokenId, suggestedParams)
    : undefined

  let composer: any = poolClient
    .newGroup()
    .gas({ args: [], note: '1' })
    .gas({ args: [], note: '2' })
  if (finalRewardTokenOptInTxn) {
    composer = composer.addTransaction(finalRewardTokenOptInTxn)
  }
  composer = composer
    .removeStake({
      args: { staker: userAddr, amountToUnstake: unstakeAmount },
      extraFee: feeAmount,
    })

  const buildResult = await composer.simulate({ skipSignatures: true, allowUnnamedResources: true })
  const transactions = await buildUnsignedGroup(buildResult.transactions)

  const withdrawAmountAlgo = formatAlgo(withdrawAmount)
  const currentBalanceAlgo = formatAlgo(stakerInfo.balance)
  const postWithdrawalStake = BigInt(stakerInfo.balance) - withdrawAmount
  const postWithdrawalStakeAlgo = formatAlgo(postWithdrawalStake)

  return {
    success: true,
    message: `Prepared Réti withdrawal from pool ${poolAppId.toString()}`,
    transactions,
    requiresApproval: true,
    data: {
      account: userAddr,
      poolAppId: Number(poolAppId),
      validatorId: resolvedPool.validatorId ? Number(resolvedPool.validatorId) : undefined,
      poolId: resolvedPool.poolId ? Number(resolvedPool.poolId) : undefined,
      withdrawAmountAlgo,
      currentBalanceAlgo,
      postWithdrawalStakeAlgo,
      rewardTokenId: rewardTokenId > 0n ? Number(rewardTokenId) : undefined,
      rewardTokenOptInRequired: needsOptInTxn,
    },
    presentation: {
      title: 'Réti Withdrawal',
      summary: `Withdraw ${withdrawAmountAlgo} ALGO from pool ${poolAppId.toString()}`,
      sections: [{
        kind: 'key_value',
        items: makeKeyValueItems([
          { label: 'Account', value: userAddr },
          resolvedPool.validatorId && resolvedPool.poolId
            ? { label: 'Pool', value: `${resolvedPool.poolId.toString()} (Validator #${resolvedPool.validatorId.toString()})` }
            : undefined,
          { label: 'Pool App ID', value: poolAppId.toString() },
          { label: 'Pre-Withdrawal Stake', value: `${currentBalanceAlgo} ALGO` },
          { label: 'Withdrawal', value: `${withdrawAmountAlgo} ALGO` },
          { label: 'Post-Withdrawal Stake', value: `${postWithdrawalStakeAlgo} ALGO` },
          needsOptInTxn
            ? { label: 'Reward Token Opt-In', value: rewardTokenId.toString() }
            : undefined,
        ]),
      }],
    },
  }
}

async function handleBalance(args: string[], context: Context): Promise<ExecuteResult> {
  if (args.length !== 1) {
    throw new Error('Usage: reti balance <account>')
  }

  const userAddr = resolveAddress(args[0], context)
  const stakedPools = await fetchStakedPoolsForAccount(userAddr)

  if (stakedPools.length === 0) {
    return {
      success: true,
      message: 'No staking positions found',
      data: { stakes: [], totalStakedAlgo: formatAlgo(0n) },
      presentation: {
        title: 'Reti Staking Positions',
        summary: `Account: ${args[0]}`,
        sections: [{ kind: 'text', text: 'No staking positions found' }],
      },
    }
  }

  let totalStaked = 0n
  const stakes: any[] = []

  for (const pool of stakedPools) {
    try {
      const poolClient = await getStakingPoolClient(pool.poolAppId)
      const stakerInfo = await poolClient.getStakerInfo({
        args: { staker: userAddr },
        extraFee: AlgoAmount.MicroAlgos(20_000),
      })
      if (!stakerInfo || BigInt(stakerInfo.balance) === 0n) {
        continue
      }

      totalStaked += BigInt(stakerInfo.balance)
      stakes.push({
        validatorId: Number(pool.id),
        poolId: Number(pool.poolId),
        poolAppId: Number(pool.poolAppId),
        balanceAlgo: formatAlgo(stakerInfo.balance),
        rewardTokenBalance: BigInt(stakerInfo.rewardTokenBalance).toString(),
        totalRewardedAlgo: formatAlgo(stakerInfo.totalRewarded),
      })
    } catch (error: any) {
      logError(`Error reading pool ${pool.poolAppId.toString()}: ${error.message}`)
    }
  }

  return {
    success: true,
    message:
      stakes.length === 0
        ? 'No staking positions found'
        : `Loaded ${stakes.length} Réti staking position(s) for ${args[0]}`,
    data: {
      stakes,
      totalStakedAlgo: formatAlgo(totalStaked),
    },
    presentation: {
      title: 'Reti Staking Positions',
      summary: `Account: ${args[0]}`,
      sections: stakes.length === 0
        ? [{ kind: 'text', text: 'No staking positions found' }]
        : [
            {
              kind: 'table',
              columns: ['Validator', 'Pool', 'App ID', 'Balance ALGO', 'Total Rewarded ALGO'],
              rows: stakes.map((stake) => ({
                cells: [
                  stake.validatorId.toString(),
                  stake.poolId.toString(),
                  stake.poolAppId.toString(),
                  stake.balanceAlgo,
                  stake.totalRewardedAlgo,
                ],
              })),
            },
            {
              kind: 'key_value',
              title: 'Totals',
              items: [{ label: 'Total Staked', value: `${formatAlgo(totalStaked)} ALGO` }],
            },
          ],
    },
  }
}

async function handleClaim(args: string[], context: Context): Promise<ExecuteResult> {
  if (args.length !== 1) {
    throw new Error('Usage: reti claim <account>')
  }

  const userAddr = resolveAddress(args[0], context)
  const stakedPools = await fetchStakedPoolsForAccount(userAddr)
  if (stakedPools.length === 0) {
    return {
      success: true,
      message: 'No staking positions found',
      data: { claimedPools: [], count: 0 },
      presentation: {
        title: 'Réti Reward Claims',
        summary: `Account: ${args[0]}`,
        sections: [{ kind: 'text', text: 'No staking positions found' }],
      },
    }
  }

  const claimablePools: Array<{ poolAppId: bigint; poolId: bigint; rewardTokenId: bigint; rewardTokenBalance: bigint }> = []
  for (const pool of stakedPools) {
    const client = await getStakingPoolClient(pool.poolAppId, userAddr)
    const stakerInfo = await client.getStakerInfo({
      args: { staker: userAddr },
      extraFee: AlgoAmount.MicroAlgos(20_000),
    })
    if (stakerInfo && BigInt(stakerInfo.rewardTokenBalance) > 0n) {
      const rewardTokenId = await getRewardTokenIdForPool(userAddr, pool.poolAppId)
      claimablePools.push({
        poolAppId: pool.poolAppId,
        poolId: pool.poolId,
        rewardTokenId,
        rewardTokenBalance: BigInt(stakerInfo.rewardTokenBalance),
      })
    }
  }

  if (claimablePools.length === 0) {
    return {
      success: true,
      message: 'No claimable Réti rewards found',
      data: { claimedPools: [], count: 0 },
      presentation: {
        title: 'Réti Reward Claims',
        summary: `Account: ${args[0]}`,
        sections: [{ kind: 'text', text: 'No claimable Réti rewards found' }],
      },
    }
  }

  const suggestedParams = await pluginState.algorand!.getSuggestedParams()
  const rewardTokenOptIns: bigint[] = []
  const rewardTokenOptInSet = new Set<string>()
  for (const pool of claimablePools) {
    if (
      pool.rewardTokenId > 0n &&
      !rewardTokenOptInSet.has(pool.rewardTokenId.toString()) &&
      !(await isOptedInToAsset(userAddr, pool.rewardTokenId))
    ) {
      rewardTokenOptIns.push(pool.rewardTokenId)
      rewardTokenOptInSet.add(pool.rewardTokenId.toString())
    }
  }

  let feeComposer = pluginState.algorand!.newGroup()
  for (const rewardTokenId of rewardTokenOptIns) {
    feeComposer = feeComposer.addTransaction(makeRewardTokenOptInTxn(userAddr, rewardTokenId, suggestedParams))
  }
  for (const pool of claimablePools) {
    const client = await getStakingPoolClient(pool.poolAppId, userAddr)
    feeComposer
      .addAppCallMethodCall(await client.params.gas({ args: [], note: '1', staticFee: AlgoAmount.MicroAlgos(0) }))
      .addAppCallMethodCall(await client.params.gas({ args: [], note: '2', staticFee: AlgoAmount.MicroAlgos(0) }))
      .addAppCallMethodCall(
        await client.params.claimTokens({
          args: {},
          staticFee: AlgoAmount.MicroAlgos(240_000),
        }),
      )
  }

  const simulateResult = await feeComposer.simulate({
    skipSignatures: true,
    allowUnnamedResources: true,
  })
  const appBudgetAdded = Number(simulateResult.simulateResponse.txnGroups[0].appBudgetAdded || 0)
  const feeAmount = AlgoAmount.MicroAlgos(1000 * Math.floor((appBudgetAdded + 699) / 700) - 2000)

  let composer = pluginState.algorand!.newGroup()
  for (const rewardTokenId of rewardTokenOptIns) {
    composer = composer.addTransaction(makeRewardTokenOptInTxn(userAddr, rewardTokenId, suggestedParams))
  }
  for (const pool of claimablePools) {
    const client = await getStakingPoolClient(pool.poolAppId, userAddr)
    composer
      .addAppCallMethodCall(await client.params.gas({ args: [], note: '1' }))
      .addAppCallMethodCall(await client.params.gas({ args: [], note: '2' }))
      .addAppCallMethodCall(await client.params.claimTokens({ args: {}, extraFee: feeAmount }))

  }

  const buildResult = await composer.simulate({ skipSignatures: true, allowUnnamedResources: true })
  const transactions = await buildUnsignedGroup(buildResult.transactions)

  return {
    success: true,
    message: `Prepared Réti reward claim for ${claimablePools.length} pool(s)`,
    transactions,
    requiresApproval: true,
    data: {
      account: userAddr,
      claimedPools: claimablePools.map((pool) => ({
        poolId: Number(pool.poolId),
        poolAppId: Number(pool.poolAppId),
        rewardTokenId: pool.rewardTokenId > 0n ? Number(pool.rewardTokenId) : undefined,
        rewardTokenBalance: pool.rewardTokenBalance.toString(),
      })),
      count: claimablePools.length,
      rewardTokenOptInRequired: rewardTokenOptIns.length > 0,
      rewardTokenOptIns: rewardTokenOptIns.map((rewardTokenId) => Number(rewardTokenId)),
    },
    presentation: {
      title: 'Réti Reward Claims',
      summary: `Account: ${args[0]}`,
      sections: [{
        kind: 'table',
        columns: ['Pool', 'App ID', 'Claimable Reward Tokens'],
        rows: claimablePools.map((pool) => ({
          cells: [
            pool.poolId.toString(),
            pool.poolAppId.toString(),
            pool.rewardTokenBalance.toString(),
          ],
        })),
      }],
    },
  }
}

async function handleExecute(params: any): Promise<ExecuteResult> {
  ensureInitialized()
  const args: string[] = params.args || []
  const context: Context = params.context || {}
  await ensureContextNetwork(context)

  if (args.length === 0) {
    const usage =
      'Usage: reti <subcommand> [args...]\n' +
      'Subcommands:\n' +
      '  list [count]\n' +
      '  validator <validator_id>\n' +
      '  pools <validator_id>\n' +
      '  deposit <amount> algo into <validator_id> for <account>\n' +
      '  withdraw <amount|all> algo from app <pool_app_id> for <account>\n' +
      '  withdraw <amount|all> algo from validator <validator_id> pool <pool_id> for <account>\n' +
      '  balance <account>\n' +
      '  claim <account>'
    return {
      success: false,
      message: usage,
      presentation: {
        title: 'Réti Plugin',
        sections: [{ kind: 'text', text: usage }],
      },
    }
  }

  switch (args[0]) {
    case 'list':
      return handleList(args.slice(1))
    case 'validator':
      return handleValidator(args.slice(1))
    case 'pools':
      return handlePools(args.slice(1))
    case 'deposit':
      return handleDeposit(args.slice(1), context)
    case 'withdraw':
      return handleWithdraw(args.slice(1), context)
    case 'balance':
      return handleBalance(args.slice(1), context)
    case 'claim':
      return handleClaim(args.slice(1), context)
    default:
      return { success: false, message: `Unknown subcommand: ${args[0]}` }
  }
}

function handleGetInfo(): any {
  return {
    name: 'reti-plugin',
    version: '1.0.0',
    description: 'Reti staking protocol integration',
    commands: ['reti'],
    networks: ['testnet', 'mainnet', 'betanet', 'fnet', 'localnet', 'sandbox'],
    status: pluginState.initialized ? 'ready' : 'starting',
  }
}

function handleShutdown(): any {
  return { success: true, message: 'Reti plugin shutdown' }
}

rl.on('line', async (line: string) => {
  let request: JsonRpcRequest = { jsonrpc: '2.0', id: null, method: '', params: {} }
  try {
    request = JSON.parse(line)
    const { id, method, params } = request

    let result: any
    switch (method) {
      case 'initialize':
        result = await handleInitialize(params)
        break
      case 'execute':
        result = await handleExecute(params)
        break
      case 'getInfo':
        result = handleGetInfo()
        break
      case 'shutdown':
        result = handleShutdown()
        sendResponse(id, result)
        process.exit(0)
      default:
        throw new Error(`Unknown method: ${method}`)
    }

    sendResponse(id, result)
  } catch (error: any) {
    logError(`Error: ${error.message}`)
    sendResponse(request.id, null, { code: -32603, message: error.message })
  }
})

process.on('SIGTERM', () => process.exit(0))
process.on('SIGINT', () => process.exit(0))

logError('Reti plugin started')
