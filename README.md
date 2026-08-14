# TDS GA7 Release Gate

A deterministic policy endpoint that decides whether a GitHub Actions run may
promote a container image, enforcing least-privilege CI permissions, complete
matrix testing, action pinning, and hardened Docker image requirements.

## Endpoint

`POST /release-gate`

Request body:

```json
{
  "target": "preview | production",
  "event": "pull_request | push",
  "ref": "refs/heads/...",
  "workflow": {
    "trigger": "pull_request | pull_request_target | push",
    "permissions": { "contents": "read", "packages": "write", "id-token": "none" },
    "testsPassed": true,
    "matrixComplete": true,
    "failFast": false,
    "actions": [{ "owner": "actions", "name": "checkout", "ref": "v4" }],
    "environmentApproval": true
  },
  "image": {
    "multiStage": true,
    "runsAsRoot": false,
    "secretMode": "none | buildkit | arg | copy",
    "criticalVulnerabilities": 0,
    "digestPinned": true
  }
}
```

Response:

```json
{ "decision": "promote | block", "violations": ["CODE", "..."] }
```

## Rules

- **EXCESS_PERMISSION** — permissions must be exactly `contents:read`,
  `packages:write`, `id-token:none`, with no extra scopes.
- **UNSAFE_PR_TRIGGER** — `pull_request_target` is never allowed as the
  workflow trigger.
- **TESTS_INCOMPLETE** — tests must pass, the whole matrix must finish, and
  `failFast` must be `false`.
- **MUTABLE_ACTION** — actions owned by `actions` may use a version tag;
  every other action must be pinned to a full 40-character lowercase hex
  commit SHA.
- **SINGLE_STAGE_IMAGE** / **ROOT_RUNTIME** / **SECRET_IN_LAYER** /
  **CRITICAL_CVE** / **UNPINNED_IMAGE** — the image must be multi-stage, run
  as non-root, use no build secret or a BuildKit secret mount (never `arg` or
  `copy`), have zero critical vulnerabilities, and be referenced by digest.
- **INVALID_PRODUCTION_REF** / **APPROVAL_REQUIRED** — `production` targets
  additionally require a `push` to `refs/heads/main` and
  `workflow.environmentApproval: true`.

`decision` is `"promote"` only when `violations` is empty.

## Development

```bash
npm install
npm test    # unit tests over the policy engine
npm start   # runs the server on PORT (default 3000)
```

See `.github/workflows/tds-ga7-release-gate.yml` for the CI workflow that
runs the unit tests and smoke-tests the live endpoint on every push to
`main`.
