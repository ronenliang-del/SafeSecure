export const maxBytes = 5 * 1024 * 1024
const maxPackages = 2000
const maxAdvisories = 100
const npmName = /^(?:@[a-z0-9._~-]+\/)?[a-z0-9._~-]+$/
const versionPattern = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/
type Dict = Record<string, unknown>
export type Package = { name: string; version: string }
export type Finding = { pkg: Package; id: string; summary: string; ranges: string[]; fixes: string[] }
const record = (x: unknown): x is Dict => !!x && typeof x === 'object' && !Array.isArray(x)
const list = (x: unknown): unknown[] => Array.isArray(x) ? x : []
const bounded = (x: unknown, n: number) => typeof x === 'string' ? x.slice(0, n) : ''

export function parseLockfile(source: string) {
  const lock: unknown = JSON.parse(source)
  if (!record(lock) || (lock.lockfileVersion !== 2 && lock.lockfileVersion !== 3) || !record(lock.packages)) {
    throw new Error('Choose an npm package-lock.json with lockfile version 2 or 3.')
  }
  const packages = new Map<string, Package>()
  let skipped = 0
  for (const [path, entry] of Object.entries(lock.packages)) {
    if (!path) continue
    const match = /(?:^|\/)node_modules\/((?:@[^/]+\/)?[^/]+)$/.exec(path)
    const name = record(entry) && typeof entry.name === 'string' ? entry.name : match?.[1]
    if (!record(entry) || !match || !name || name.length > 214 || !npmName.test(name) ||
      entry.link === true || typeof entry.version !== 'string' || entry.version.length > 128 ||
      !versionPattern.test(entry.version) || (typeof entry.resolved === 'string' &&
      !entry.resolved.startsWith('https://registry.npmjs.org/'))) {
      skipped++
      continue
    }
    packages.set(JSON.stringify([name, entry.version]), { name, version: entry.version })
    if (packages.size > maxPackages) throw new Error('This lockfile exceeds the 2,000-package scan limit.')
  }
  return { packages: [...packages.values()], skipped }
}

async function request(path: string, signal: AbortSignal, body?: unknown): Promise<unknown> {
  const response = await fetch('https://api.osv.dev/v1/' + path, {
    signal, credentials: 'omit', redirect: 'error', referrerPolicy: 'no-referrer',
    ...(body === undefined ? {} : {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
    }),
  })
  if (!response.ok || !response.body) throw new Error('OSV lookup unavailable.')
  const reader = response.body.getReader()
  const decoder = new TextDecoder()
  let bytes = 0
  let source = ''
  try {
    for (;;) {
      const { value, done } = await reader.read()
      if (done) break
      bytes += value.byteLength
      if (bytes > 4 * 1024 * 1024) throw new Error('OSV response exceeds the size limit.')
      source += decoder.decode(value, { stream: true })
    }
  } finally {
    await reader.cancel().catch(() => {})
    reader.releaseLock()
  }
  return JSON.parse(source + decoder.decode())
}

export async function scan(packages: Package[], signal: AbortSignal): Promise<Finding[]> {
  const matches: { pkg: Package; id: string }[] = []
  const ids = new Set<string>()
  for (let offset = 0; offset < packages.length; offset += 100) {
    const batch = packages.slice(offset, offset + 100)
    const result = await request('querybatch', signal, {
      queries: batch.map(({ name, version }) => ({ package: { ecosystem: 'npm', name }, version })),
    })
    if (!record(result) || !Array.isArray(result.results) || result.results.length !== batch.length) {
      throw new Error('Unexpected OSV response.')
    }
    result.results.forEach((hit: unknown, index: number) => {
      if (!record(hit) || hit.next_page_token || ('vulns' in hit && !Array.isArray(hit.vulns))) {
        throw new Error('OSV returned incomplete results.')
      }
      for (const advisory of list(hit.vulns)) {
        if (!record(advisory) || typeof advisory.id !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(advisory.id)) {
          throw new Error('OSV returned an invalid advisory ID.')
        }
        ids.add(advisory.id)
        matches.push({ pkg: batch[index], id: advisory.id })
      }
    })
    if (ids.size > maxAdvisories || matches.length > 1000) throw new Error('The advisory count exceeds the report limit.')
  }
  const details = new Map<string, Dict>()
  const advisoryIds = [...ids]
  for (let offset = 0; offset < advisoryIds.length; offset += 5) {
    await Promise.all(advisoryIds.slice(offset, offset + 5).map(async id => {
      const data = await request('vulns/' + encodeURIComponent(id), signal)
      if (!record(data) || data.id !== id || !Array.isArray(data.affected)) throw new Error('Advisory details unavailable.')
      details.set(id, data)
    }))
  }
  return matches.map(({ pkg, id }) => {
    const data = details.get(id)!
    const ranges = new Set<string>()
    const fixes = new Set<string>()
    for (const affected of list(data.affected)) {
      if (!record(affected) || !record(affected.package) || affected.package.ecosystem !== 'npm' || affected.package.name !== pkg.name) continue
      for (const range of list(affected.ranges)) {
        if (!record(range) || !['SEMVER', 'ECOSYSTEM'].includes(String(range.type))) continue
        const events: string[] = []
        for (const event of list(range.events)) {
          if (!record(event)) continue
          for (const field of ['introduced', 'fixed', 'last_affected', 'limit']) {
            const value = bounded(event[field], 128)
            if (!value) continue
            events.push(field.replace('_', ' ') + ' ' + value)
            if (field === 'fixed' && versionPattern.test(value)) fixes.add(value)
          }
        }
        if (events.length) ranges.add(events.join(' · '))
      }
    }
    return { pkg, id, summary: bounded(data.summary, 500) || 'See the OSV advisory for details.', ranges: [...ranges], fixes: [...fixes] }
  })
}
