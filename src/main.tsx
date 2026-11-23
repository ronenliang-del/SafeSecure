import { useRef, useState } from 'react'
import { createRoot } from 'react-dom/client'
import { maxBytes, parseLockfile, scan, type Finding } from './scan'
import './style.css'

const sample: Finding[] = [{
  pkg: { name: 'lodash', version: '4.17.20' }, id: 'GHSA-35jh-r3h4-6jhm',
  summary: 'Command injection in Lodash',
  ranges: ['introduced 0 · fixed 4.17.21'], fixes: ['4.17.21'],
}]

function App() {
  const [file, setFile] = useState<File>()
  const [input, setInput] = useState<ReturnType<typeof parseLockfile>>()
  const [report, setReport] = useState<Finding[]>()
  const [demo, setDemo] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const operation = useRef(0)

  async function choose(next?: File) {
    const current = ++operation.current
    setFile(next)
    setInput(undefined)
    setReport(undefined)
    setDemo(false)
    setError('')
    if (!next) return
    try {
      if (next.size > maxBytes) throw new Error('Choose a lockfile under 5 MiB.')
      const parsed = parseLockfile(await next.text())
      if (current === operation.current) setInput(parsed)
    } catch (cause) {
      if (current === operation.current) setError(cause instanceof SyntaxError ? 'This file contains invalid JSON.' : (cause as Error).message)
    }
  }

  async function check() {
    if (!input?.packages.length || busy) return
    setBusy(true)
    setError('')
    setDemo(false)
    setReport(undefined)
    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(), 30000)
    try {
      setReport(await scan(input.packages, controller.signal))
    } catch (cause) {
      setError('Check unavailable. ' + (controller.signal.aborted ? 'The lookup timed out.' : (cause as Error).message || 'Try again later.'))
    } finally {
      clearTimeout(timer)
      controller.abort()
      setBusy(false)
    }
  }

  return <div className="shell">
    <header><span className="mark" aria-hidden="true">◈</span> Lockscope <span className="header-label">DEPENDENCY REVIEW</span></header>
    <main>
      <section className="intro">
        <div className="eyebrow">NPM SECURITY</div>
        <h1>Review your dependencies.</h1>
        <p>Check the versions in your npm lockfile for known vulnerabilities and see the advisory behind each finding.</p>
      </section>
      <div className="workspace">
        <section className="panel">
          <h2>Scan a lockfile</h2>
          <p className="muted">Use a package-lock.json file, version 2 or 3, up to 5 MiB.</p>
          <label className="upload" onDragOver={event => event.preventDefault()} onDrop={event => {
            event.preventDefault()
            if (!busy && event.dataTransfer.files.length === 1) void choose(event.dataTransfer.files[0])
          }}>
            <span aria-hidden="true" className="upload-icon">⇧</span>
            <span className="filename">{file?.name || 'Choose a lockfile'}</span>
            <span className="muted">or drop it here</span>
            <input aria-label="Choose an npm lockfile" type="file" accept=".json,application/json" disabled={busy} onChange={event => {
              const next = event.currentTarget.files?.[0]
              event.currentTarget.value = ''
              if (next) void choose(next)
            }} />
          </label>
          {input && <p className="muted" role="status">{input.packages.length} unique npm versions ready. {input.skipped} entries skipped.</p>}
          <p className="privacy">Your file stays in this browser. Running a check sends package names and versions to OSV.</p>
          <div className="actions">
            <button className="primary" disabled={busy || !input?.packages.length} onClick={() => void check()}>{busy ? 'Checking OSV…' : 'Check with OSV'}</button>
            <button disabled={busy} onClick={() => {
              operation.current++
              setFile(undefined)
              setInput(undefined)
              setError('')
              setDemo(true)
              setReport(sample)
            }}>View sample</button>
          </div>
          {error && <p className="error" role="alert">{error}</p>}
        </section>
        <section className="panel results" aria-labelledby="report">
          <h2 id="report">Advisory report</h2>
          <div aria-live="polite">
            {!report && <div className="empty"><span aria-hidden="true">◎</span><p>{busy ? 'Looking up known advisories…' : 'Your findings will appear here.'}</p></div>}
            {report && <p className="muted">{demo ? 'Offline sample · ' : ''}{report.length === 0 ? 'OSV returned no known advisories for the checked versions.' : `${report.length} advisory match${report.length === 1 ? '' : 'es'}`}</p>}
          </div>
          {report?.map((finding, index) => <article key={index}>
            <h3>{finding.pkg.name} <code>{finding.pkg.version}</code></h3>
            <p>{finding.summary}</p>
            {finding.ranges.length > 0 && <p className="muted">Affected ranges: {finding.ranges.join(' / ')}</p>}
            {finding.fixes.length > 0 && <p className="muted">Fixed versions listed: {finding.fixes.join(', ')}</p>}
            <a href={'https://osv.dev/vulnerability/' + encodeURIComponent(finding.id)} target="_blank" rel="noopener noreferrer">{finding.id}</a>
          </article>)}
        </section>
      </div>
    </main>
    <footer>Lockscope <span>Advisory data from OSV</span></footer>
  </div>
}

createRoot(document.getElementById('root')!).render(<App />)
