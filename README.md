# SafeSecure

Lockscope checks npm lockfile versions against OSV and shows the evidence behind each advisory match. It is a static React and TypeScript app built with Vite.

## Run locally

Use Node.js 24 and npm.

```sh
npm ci --ignore-scripts
npm test
npm run build
npm run preview
```

Open the local URL printed by Vite. **View sample** displays an advisory report without contacting OSV. Choose a version 2 or 3 npm lockfile and select **Check with OSV** for a live report.

The `dist/` directory can be served by a static host, including GitHub Pages. Vite uses relative asset URLs so the build can run under a repository subpath.

## Data flow and scope

- File selection reads at most 5 MiB locally. The app parses JSON as data and never installs packages from a selected lockfile.
- Checking sends package names, resolved versions, and the npm ecosystem identifier to OSV. Follow-up requests retrieve advisory details by ID. Package names can reveal private dependencies. Use the sample if you want to evaluate the interface without sharing dependency coordinates.
- The app skips links, entries explicitly resolved outside the public npm registry, and entries it cannot associate with an npm name and version. The report counts skipped entries. It does not establish package provenance, assess reachability, or detect vulnerabilities missing from OSV.
- OSV failures and incomplete responses produce an unavailable status. Fixed versions are advisory evidence and may include multiple release branches.
- The app uses no persistent storage. It renders file names and advisory text through React and restricts network connections with a Content Security Policy. The policy is delivered in HTML. Hosts that support response headers can additionally set `frame-ancestors 'none'` in a header.
- This release covers npm advisory lookup. GitHub Actions review and optional local AI explanations are subsequent milestones.
