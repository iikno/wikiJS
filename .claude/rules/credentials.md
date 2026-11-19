---
paths:
  - "dev/specs/credentials.md"
  - "backend/helpers/credentialCrypto.ts"
  - "backend/helpers/credentialCrypto.test.ts"
  - "backend/helpers/totp.ts"
  - "backend/models/credentials.ts"
  - "backend/models/groups.ts"
  - "backend/models/tree.ts"
  - "backend/models/auditLog.ts"
  - "backend/models/personalTokens.ts"
  - "backend/api/credentials.ts"
  - "backend/api/tree.ts"
  - "backend/api/schemas/credentials.ts"
  - "backend/mcp/tools/credentials.ts"
  - "backend/models/mcp.ts"
  - "backend/base.yml"
  - "frontend/src/pages/AdminMcp.vue"
  - "backend/db/schema.ts"
  - "frontend/src/components/GroupEditOverlay.vue"
  - "frontend/src/helpers/personalTokens.js"
---

# Credentials

Records attached to a folder path of the wiki, built from a per-site **template**, whose secret
fields (`secret`, `totp`) are encrypted under an instance key from the environment. The spec is
`dev/specs/credentials.md`; phase 1 (core: crypto, tables, permissions, model, REST, audit, folder
moves and deletes) and phase 2 (MCP) are built. The search UI, frontend, storage sync and rotation
are not.

- **The key is never stored.** `WIKI_CREDENTIALS_KEY` (base64, exactly 32 bytes) is read once by
  `helpers/credentialCrypto.ts`, which is the only file touching `node:crypto` for this and the only
  holder of the key. A bad key is logged and behaves as a missing one. Without a key credentials are
  listable; reveal and any write that sets or clears a secret answer 503 `credentialsKeyMissing`. A
  blob sealed under an unknown key id answers 409 `credentialsKeyMismatch`. `npm test` in `backend/`
  runs the crypto test.
- **Blob** `"WKC1" | keyId(8) | nonce(12) | ciphertext | tag(16)`, AES-256-GCM, AAD
  `siteId|credentialId|secrets`. The path is not in the AAD, so a folder move re-seals nothing. The
  table has CHECKs that `secrets` and `keyId` are null together and that `secrets` starts with `WKC1`.
- **Three page permissions**, asked at the credential's path in the site's PRIMARY locale
  (`credentials.may`, which wraps `groups.checkAccess`): `read:credentials`, `reveal:credentials`,
  `manage:credentials`. `IMPLIED_PAGE_PERMISSIONS` in `models/groups.ts` makes manage and reveal imply
  read; **manage does not imply reveal** (an agent may write what it can never read back). Never to a
  request acting as no account — `may` refuses `userId === null`, a system API key included — and
  not in `GUEST_ROLES`. Not elevated, and no group is seeded with them.
- **Routes declare no route-level permissions** (page permissions, checked in the handler), except
  the template routes, which are `manage:sites`. `config.scope: 'credentials'` (the `credentials`
  token category: read is GET and reveal, write is the rest). Reveal is `maintenance: 'read'`, sends
  `Cache-Control: private, no-store` and is limited to 60 a minute per account.
- **Writes** (`PUT /` upserts by `(siteId, path, key)`): a secret field omitted or sent as
  `SENSITIVE_MASK` is unchanged, `null` clears, a string sets; the blob is re-sealed and
  `secretsUpdatedAt` moved only when a value actually changed. A credential keeps its template. A
  field removed from a template keeps its values, hidden, until the credential is next re-sealed
  (non-secret ones go on any save). `ts` is built from name, tags, template name and non-secret
  values with the `simple` dictionary — never a secret.
- **Audit** kind `credential`; actions are named `createCredential` etc. (keys are unique across
  kinds). `meta` carries ids, path and `handle` (the credential key — `sanitizeMeta` redacts a key
  literally named `key`) and, for an update, the changed field ids and `sealedChanged`. Never a value.
- **Folders.** Renaming or moving a folder in the primary locale moves the credentials at or under it
  (`tree.refreshDescendantPaths`); deleting it deletes them. `api/tree.ts` `guardCredentials` first
  asks `manage:credentials` at the folder and answers 409 with the count without it. A rename or move
  that would land a credential on an existing `(path, key)` is refused first by
  `credentials.assertRelocatable` (inside `renameFolder`/`moveFolder`, so every caller meets it) with
  409 `credentialPathConflict`. The delete route removes the credentials, not `tree.deleteFolder`, and
  `deleteEmptyFolders` skips a folder that holds any.
- **MCP** (`mcp/tools/credentials.ts`): groups `credentials` (on) and `credentials-reveal` (off) in
  `MCP_TOOL_GROUPS` and `base.yml`; `credential_delete` is in `destructive`. The tools call the model
  (not `callApi`, unlike the page tools: the rules are in the model) and share the REST audit helpers
  and the reveal rate limit from `api/credentials.ts`. A model `CustomError` becomes a `ToolError`
  naming its code, so a missing key reads as `credentialsKeyMissing` instead of a protocol fault. No
  account, no tool. `credential_search` is `credentials.list` with a `query` (the `ts` column).
- Boot logs (warn) how many rows are sealed under a key the instance does not hold.
