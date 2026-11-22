// @vitest-environment node

import { spawnSync } from 'node:child_process'
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { afterEach, describe, expect, it } from 'vitest'

const projectRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../..')
const script = resolve(projectRoot, 'scripts/check-no-external-urls.sh')
const fixtures = []

/**
 * @brief Run the URL check script against a repository root.
 *
 * @param {string} root Directory containing src/ and src_assets/.
 * @return {import('node:child_process').SpawnSyncReturns<string>} Script result.
 */
function runCheck(root) {
  return spawnSync('bash', [script, root], { encoding: 'utf8', timeout: 30_000 })
}

/**
 * @brief Create a throw-away source tree.
 *
 * @param {Record<string, string>} files Relative paths and contents.
 * @return {string} Root directory of the tree.
 */
function makeTree(files) {
  const root = mkdtempSync(join(tmpdir(), 'sunshine-url-check-'))
  fixtures.push(root)
  for (const [path, content] of Object.entries(files)) {
    mkdirSync(dirname(join(root, path)), { recursive: true })
    writeFileSync(join(root, path), content)
  }
  return root
}

afterEach(() => {
  for (const root of fixtures.splice(0)) {
    rmSync(root, { recursive: true, force: true })
  }
})

describe('scripts/check-no-external-urls.sh', () => {
  it('passes on the repository sources', () => {
    const result = runCheck(projectRoot)
    expect(result.error).toBeUndefined()
    expect(result.status, result.stdout + result.stderr).toBe(0)
  }, 35_000)

  it('reports external URLs and network APIs outside the allowlist', () => {
    const root = makeTree({
      'src/a.cpp': [
        '// Comments may cite https://example.org/spec',
        'int x = 1;  // Workaround for https://github.com/foo/bar/issues/1',
        'auto url = "https://api.github.com/repos/x/y/releases/latest";',
        'CURL *curl = curl_easy_init();',
        'auto local = "https://localhost:47990/pin";',
      ].join('\n'),
      'src_assets/web/b.js': 'fetch("https://telemetry.example/collect")\n',
    })

    const result = runCheck(root)
    expect(result.status).toBe(1)
    expect(result.stdout).toContain('src/a.cpp:3: external URL not on the allowlist: https://api.github.com/repos/x/y/releases/latest')
    expect(result.stdout).toContain('src/a.cpp:4: network API not on the allowlist')
    expect(result.stdout).toContain('src_assets/web/b.js:1: external URL not on the allowlist: https://telemetry.example/collect')
    expect(result.stdout).not.toContain('example.org')
    expect(result.stdout).not.toContain('localhost')
    expect(result.stdout).not.toContain('issues/1')
  })
})
