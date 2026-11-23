import { afterEach, expect, test, vi } from 'vitest'
import { parseLockfile, scan } from './scan'

afterEach(() => vi.unstubAllGlobals())
const pkg = { name: 'lodash', version: '4.17.20' }
const signal = new AbortController().signal

test('deduplicates nested packages, handles aliases and skips non-registry entries', () => {
  const source = JSON.stringify({ lockfileVersion: 3, packages: {
    '': { version: '1.0.0' },
    'node_modules/lodash': { version: pkg.version },
    'node_modules/a/node_modules/lodash': { version: pkg.version },
    'node_modules/alias': { name: pkg.name, version: pkg.version },
    'node_modules/local': { version: '1.0.0', resolved: 'file:../local' },
  } })
  expect(parseLockfile(source)).toEqual({ packages: [pkg], skipped: 1 })
})

test('rejects unsupported lockfile layouts and invalid JSON', () => {
  expect(() => parseLockfile('{"lockfileVersion":1}')).toThrow()
  expect(() => parseLockfile('{')).toThrow(SyntaxError)
})

test('sends only npm coordinates and reads fixed versions from the matching package', async () => {
  const fetch = vi.fn()
    .mockResolvedValueOnce(Response.json({ results: [{ vulns: [{ id: 'TEST-1' }] }] }))
    .mockResolvedValueOnce(Response.json({ id: 'TEST-1', summary: 'Test advisory', affected: [
      { package: { name: pkg.name, ecosystem: 'npm' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '4.17.21' }] }] },
    ] }))
  vi.stubGlobal('fetch', fetch)
  const report = await scan([pkg], signal)
  expect(report[0].fixes).toEqual(['4.17.21'])
  expect(JSON.parse(fetch.mock.calls[0][1].body)).toEqual({
    queries: [{ package: { ecosystem: 'npm', name: pkg.name }, version: pkg.version }],
  })
  expect(fetch.mock.calls[0][1].credentials).toBe('omit')
})

test('distinguishes lookup failure or incomplete results from an empty report', async () => {
  const fetch = vi.fn()
    .mockResolvedValueOnce(new Response(null, { status: 503 }))
    .mockResolvedValueOnce(Response.json({ results: [{ next_page_token: 'next' }] }))
    .mockResolvedValueOnce(Response.json({ results: [{}] }))
  vi.stubGlobal('fetch', fetch)
  await expect(scan([pkg], signal)).rejects.toThrow()
  await expect(scan([pkg], signal)).rejects.toThrow()
  await expect(scan([pkg], signal)).resolves.toEqual([])
})
