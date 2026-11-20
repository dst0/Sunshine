// @vitest-environment node

import { readFileSync, readdirSync, statSync } from 'node:fs'
import { dirname, extname, relative, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'

const projectRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../..')
const webRoot = resolve(projectRoot, 'src_assets/common/assets/web')
const scannedExtensions = new Set(['.vue', '.js', '.mjs', '.html', '.css', '.svg', '.json'])

/**
 * Plain, user-clickable links that may stay in the Web UI, per file. They are only ever used as
 * anchor targets; the Web UI never requests them by itself.
 */
const allowedLinks = {
  'Apps.vue': ['https://docs.lizardbyte.dev/projects/sunshine/latest'],
  'ResourceCard.vue': [
    'https://app.lizardbyte.dev',
    'https://app.lizardbyte.dev/discord',
    'https://docs.lizardbyte.dev/projects/sunshine/latest/',
    'https://github.com/orgs/LizardByte/discussions',
    'https://github.com/SunshineStream/Sunshine/blob/master/LICENSE',
    'https://github.com/SunshineStream/Sunshine/blob/master/NOTICE',
  ],
  'Troubleshooting.vue': [
    'https://github.com/LizardByte/libvirtualhid/releases/latest',
    'https://github.com/nefarius/ViGEmBus/releases/latest',
  ],
  'configs/tabs/AudioVideo.vue': ['https://github.com/mattingalls/Soundflower', 'https://github.com/ExistentialAudio/BlackHole'],
  'configs/tabs/Inputs.vue': ['https://learn.microsoft.com/en-us/windows/win32/inputdev/virtual-key-codes'],
  'configs/tabs/encoders/NvidiaNvencEncoder.vue': [
    'https://en.wikipedia.org/wiki/Video_buffering_verifier',
    'https://devblogs.microsoft.com/directx/hardware-accelerated-gpu-scheduling/',
  ],
}

/** XML namespace identifiers: never dereferenced. */
const namespaceUris = new Set([
  'http://www.w3.org/2000/svg',
  'http://www.w3.org/1999/xlink',
  'http://www.inkscape.org/namespaces/inkscape',
  'http://sodipodi.sourceforge.net/DTD/sodipodi-0.dtd',
])

/** Placeholder hosts used in translated help texts. */
const placeholderHosts = /^https:\/\/(example\.com|ejemplo\.com)/

/**
 * Code that would make the browser contact an absolute URL. Matching any of these is a violation,
 * even for allowed links.
 */
const networkSinks = [
  { name: 'fetch() with an absolute URL', pattern: /fetch\(\s*[`'"]https?:/ },
  { name: 'axios', pattern: /\baxios\b/ },
  { name: 'XMLHttpRequest.open() with an absolute URL', pattern: /\.open\(\s*[`'"][A-Z]+[`'"]\s*,\s*[`'"]https?:/ },
  { name: 'WebSocket', pattern: /new\s+WebSocket\(/ },
  { name: 'EventSource', pattern: /new\s+EventSource\(/ },
  { name: 'sendBeacon', pattern: /sendBeacon\(/ },
  { name: 'import() of an absolute URL', pattern: /import\(\s*[`'"]https?:/ },
  { name: 'img/script/iframe/source src with an absolute URL', pattern: /<(img|script|iframe|source|video|audio|embed)\b[^>]*\bsrc\s*=\s*["']https?:/i },
  { name: 'bound :src with an absolute URL', pattern: /:src\s*=\s*["'][^"']*https?:/ },
  { name: 'link href with an absolute URL', pattern: /<link\b[^>]*\bhref\s*=\s*["']https?:/i },
  { name: 'CSS url() with an absolute URL', pattern: /url\(\s*["']?https?:/i },
  { name: 'CSS @import of an absolute URL', pattern: /@import\s+(url\()?\s*["']?https?:/i },
]

/**
 * @brief List every scanned file under a directory.
 *
 * @param {string} directory Directory to walk.
 * @return {string[]} Absolute file paths.
 */
function listFiles(directory) {
  return readdirSync(directory).flatMap(entry => {
    const path = resolve(directory, entry)
    if (statSync(path).isDirectory()) {
      return listFiles(path)
    }
    return scannedExtensions.has(extname(path)) ? [path] : []
  })
}

/**
 * @brief Check whether a match position on a line is inside a comment.
 *
 * @param {string} line Source line.
 * @param {number} index Position of the match.
 * @return {boolean} True when the text before the match opens a comment.
 */
function isInComment(line, index) {
  const before = line.slice(0, index).replaceAll(/https?:\/\//g, '')
  return /(^|\s)\/\/|\/\*|^\s*\*|<!--/.test(before)
}

/**
 * @brief Collect every external URL and network sink violation in the Web UI sources.
 *
 * @return {string[]} Human-readable violations.
 */
function findViolations() {
  const violations = []
  for (const file of listFiles(webRoot)) {
    const name = relative(webRoot, file).replaceAll('\\', '/')
    const allowed = new Set(allowedLinks[name] || [])
    const lines = readFileSync(file, 'utf8').split('\n')
    lines.forEach((line, number) => {
      const location = `${name}:${number + 1}`
      for (const sink of networkSinks) {
        if (sink.pattern.test(line)) {
          violations.push(`${location}: ${sink.name}: ${line.trim()}`)
        }
      }
      for (const match of line.matchAll(/https?:\/\/[^\s"'`<>)\\]+/g)) {
        const url = match[0]
        if (isInComment(line, match.index) || namespaceUris.has(url)) {
          continue
        }
        if (name.startsWith('public/assets/locale/') && placeholderHosts.test(url)) {
          continue
        }
        if (!allowed.has(url)) {
          violations.push(`${location}: external URL not on the documentation-link allowlist: ${url}`)
        }
      }
    })
  }
  return violations
}

describe('Web UI makes no external requests', () => {
  it('scans the Web UI sources', () => {
    expect(listFiles(webRoot).length).toBeGreaterThan(20)
  })

  it('references external URLs only as allowed documentation links', () => {
    expect(findViolations()).toEqual([])
  })

  it('detects fetches of external URLs, remote images and stray links', () => {
    const samples = [
      'fetch("https://api.github.com/repos/x/y/releases/latest")',
      '<img :src="`https://images.igdb.com/${slug}.jpg`">',
      '<img src="https://example.org/a.png">',
      'background: url(https://fonts.example/font.woff2);',
      '@import url("https://cdn.example/x.css");',
    ]
    for (const sample of samples) {
      expect(networkSinks.some(sink => sink.pattern.test(sample)), sample).toBe(true)
    }
    expect(isInComment('// see https://example.org', 7)).toBe(true)
    expect(isInComment('const u = "https://example.org"', 11)).toBe(false)
  })

  it('every allowed link is still used, so the allowlist stays minimal', () => {
    for (const [name, links] of Object.entries(allowedLinks)) {
      const source = readFileSync(resolve(webRoot, name), 'utf8')
      for (const link of links) {
        expect(source.includes(link), `${name}: ${link}`).toBe(true)
      }
    }
  })
})

describe('Web UI is compatible with the strict Content-Security-Policy', () => {
  const indexHtml = readFileSync(resolve(webRoot, 'index.html'), 'utf8')

  it('has no inline scripts or inline event handlers in the entry page', () => {
    const scripts = [...indexHtml.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi)]
    expect(scripts.length).toBeGreaterThan(0)
    for (const [, attributes, body] of scripts) {
      expect(attributes).toMatch(/\bsrc\s*=\s*["']\/[^/]/)
      expect(body.trim()).toBe('')
    }
    expect(indexHtml).not.toMatch(/\son[a-z]+\s*=/i)
    expect(indexHtml).not.toMatch(/<style\b/i)
  })

  it('only uses a same-origin <base> (the CSP allows base-uri \'self\')', () => {
    for (const [, href] of indexHtml.matchAll(/<base\b[^>]*\bhref\s*=\s*["']([^"']*)["']/gi)) {
      expect(href).toMatch(/^\/(?!\/)/)
    }
  })

  it('bundles the runtime-only Vue build, which never compiles templates with eval', () => {
    const viteConfig = readFileSync(resolve(projectRoot, 'vite.config.js'), 'utf8')
    expect(viteConfig).not.toMatch(/vue\/dist\/vue\.esm-bundler/)
    for (const file of listFiles(webRoot).filter(path => /\.(vue|js)$/.test(path))) {
      const source = readFileSync(file, 'utf8')
      expect(/\btemplate\s*:\s*[`'"]/.test(source), relative(webRoot, file)).toBe(false)
    }
  })
})
