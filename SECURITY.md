# Security policy

Use the repository's private vulnerability reporting feature when available. Provide the affected version or commit, expected behavior, and a minimal synthetic reproduction. Exclude credentials and private repository data.

The app treats lockfiles and OSV responses as untrusted data. Its security boundary includes the browser, the static host, the build and dependency supply chain, and OSV. The application uses no server-side code, accounts, database, or API keys.

User-initiated OSV lookups disclose npm dependency coordinates and normal request metadata to OSV. Responses are size-limited, requests share a deadline, and report links use a fixed OSV origin. The sample runs offline. Limitations and deployment details are in the README.
