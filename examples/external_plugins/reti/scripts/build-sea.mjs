#!/usr/bin/env node

import { execFile } from 'node:child_process'
import { constants } from 'node:fs'
import { access, chmod, copyFile, mkdir, rm, writeFile } from 'node:fs/promises'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { promisify } from 'node:util'
import * as esbuild from 'esbuild'

const execFileAsync = promisify(execFile)

const pluginRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..')

function parseArgs(argv) {
  const args = {
    node: process.execPath,
    output: join(pluginRoot, process.env.RETI_SEA_OUTPUT || 'reti'),
    targetOs: process.platform,
    targetArch: process.arch,
    targetLabel: 'host',
  }

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i]
    const next = () => {
      i += 1
      if (i >= argv.length) {
        throw new Error(`${arg} requires a value`)
      }
      return argv[i]
    }

    switch (arg) {
      case '--node':
        args.node = resolve(next())
        break
      case '--output':
        args.output = resolve(next())
        break
      case '--target-os':
        args.targetOs = next()
        break
      case '--target-arch':
        args.targetArch = next()
        break
      case '--target-label':
        args.targetLabel = next()
        break
      case '-h':
      case '--help':
        console.log('Usage: node scripts/build-sea.mjs [--node <node-binary>] [--output <path>] [--target-os <os>] [--target-arch <arch>] [--target-label <label>]')
        process.exit(0)
        break
      default:
        throw new Error(`unknown argument: ${arg}`)
    }
  }

  return args
}

const buildArgs = parseArgs(process.argv.slice(2))
const seaDir = join(pluginRoot, '.sea', buildArgs.targetLabel)
const bundlePath = join(seaDir, 'reti-plugin.bundle.cjs')
const seaConfigPath = join(seaDir, 'sea-config.json')
const seaBlobPath = join(seaDir, 'sea-prep.blob')
const executablePath = buildArgs.output
const sentinelFuse = 'NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2'

async function run(command, args, options = {}) {
  try {
    await execFileAsync(command, args, {
      cwd: pluginRoot,
      maxBuffer: 32 * 1024 * 1024,
      ...options,
    })
  } catch (error) {
    const details = [error.stdout, error.stderr].filter(Boolean).join('\n').trim()
    const message = details ? `${error.message}\n${details}` : error.message
    throw new Error(message)
  }
}

async function fileExists(path) {
  try {
    await access(path, constants.F_OK)
    return true
  } catch {
    return false
  }
}

async function signMacOSExecutable(path) {
  if (process.platform !== 'darwin' || buildArgs.targetOs !== 'darwin') {
    return
  }

  await run('codesign', ['--sign', '-', path])
}

async function main() {
  await rm(seaDir, { recursive: true, force: true })
  await mkdir(seaDir, { recursive: true })

  await esbuild.build({
    entryPoints: [join(pluginRoot, 'src', 'reti-plugin.ts')],
    outfile: bundlePath,
    bundle: true,
    platform: 'node',
    target: 'node20',
    format: 'cjs',
    logLevel: 'silent',
  })

  await writeFile(
    seaConfigPath,
    `${JSON.stringify(
      {
        main: bundlePath,
        output: seaBlobPath,
        disableExperimentalSEAWarning: true,
        useSnapshot: false,
        useCodeCache: false,
      },
      null,
      2,
    )}\n`,
  )

  await run(process.execPath, ['--experimental-sea-config', seaConfigPath])
  await mkdir(dirname(executablePath), { recursive: true })
  await copyFile(buildArgs.node, executablePath)
  await chmod(executablePath, 0o755)

  if (process.platform === 'darwin' && buildArgs.targetOs === 'darwin') {
    await run('codesign', ['--remove-signature', executablePath])
  }

  const postjectBin = process.platform === 'win32'
    ? join(pluginRoot, 'node_modules', '.bin', 'postject.cmd')
    : join(pluginRoot, 'node_modules', '.bin', 'postject')
  const postjectArgs = [
    executablePath,
    'NODE_SEA_BLOB',
    seaBlobPath,
    '--sentinel-fuse',
    sentinelFuse,
  ]
  if (process.platform === 'darwin') {
    postjectArgs.push('--macho-segment-name', 'NODE_SEA')
  }
  await run(postjectBin, postjectArgs)

  await signMacOSExecutable(executablePath)

  if (process.env.RETI_KEEP_SEA !== '1') {
    await rm(seaDir, { recursive: true, force: true })
  }

  if (!(await fileExists(executablePath))) {
    throw new Error(`expected standalone executable was not created: ${executablePath}`)
  }

  console.log(`Built standalone Reti plugin executable: ${executablePath}`)
}

main().catch((error) => {
  console.error(error.message)
  process.exit(1)
})
