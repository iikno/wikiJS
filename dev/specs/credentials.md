# Credentials

**Status:** proposed. Phases 1 and 2 ([§15](#15-suggested-order)) are implemented; the rest is not.
**Covers:** what a credential is, the templates that shape it, how its secret fields are encrypted and
where the key comes from, who may see, reveal and change one, how credentials are searched, synced to
storage targets and managed over MCP, and the order to build it in.

A **credential** is a record attached to a folder path of the wiki, built from a **template** (a
server, a router, a licence, a web account…), whose **secret fields** are stored encrypted under an
instance key that is read from the environment and never stored. Everything else about it (its name,
tags, user name, URL, IP, notes) is plain metadata: listed, searched and synced like a page title.

It is meant for an MSP running client documentation in the wiki, IT Glue-style: each client is a
folder, the client's documentation and the client's credentials live together under it, and the page
rules that decide who reads the documentation decide who sees the credentials. Claude Code sessions
working in each client's project keep both up to date through MCP ([§9](#9-mcp)).

This is not the vault of [`vault.md`](./vault.md). A vault encrypts the pages of a folder and is
deliberately not a secret manager. This is a secret manager, scoped to the wiki's tree. The two
coexist ([§6.5](#65-vaults)).

The constraints this is written against:

- **The key is never stored by the wiki.** It comes from `WIKI_CREDENTIALS_KEY`, not from the
  database, `config.yml`, `settings` or a startup check (which stores what it makes in the database,
  next to the ciphertext it would protect).
- **Encryption happens in the application, not in PostgreSQL**, for the reasons in
  [`vault.md` §3.2](./vault.md#32-why-not-pgcrypto): the database and its logs never see a key.
- **Only secret fields are encrypted.** Metadata stays in the clear so that it can be listed,
  searched, synced and read by agents without the key.
- **A credential belongs to a path.** Access is the page rules at that path, asked like any page
  permission. There is no second access system.
- **The CLAUDE.md migration rule applies.** The tables are new, so the migration converts nothing.

---

## 1. Goals and non-goals

**Goals**

- **Templates with custom fields**, per site, managed by administrators ([§5.1](#51-credentialtemplates)).
- **Three page permissions**: see a credential, reveal its secrets, change it ([§6](#6-permissions)).
- **Encrypted secret fields**, AES-256-GCM under `WIKI_CREDENTIALS_KEY` ([§4](#4-keys)).
- **Every reveal audited**, with the user, the token if any, the credential and the field ([§12](#12-audit-log)).
- **TOTP fields** that reveal the current code, never the seed ([§10.3](#103-revealing)).
- **Search** over metadata, never over secrets ([§7](#7-search)).
- **Storage sync** of credentials and templates, with secrets as ciphertext ([§8](#8-storage-sync)).
- **Full management over MCP**, with an idempotent upsert so that an agent can run the same update
  twice without creating a duplicate, and with revealing as a separate tool group that is off by
  default ([§9](#9-mcp)).

**Non-goals**

- **Sealing, per-folder keys, key shares.** That is [`vault.md`](./vault.md).
- **End-to-end encryption.** The server decrypts to reveal.
- **Protection from the running server**, or from anybody holding both the environment and a dump
  ([§3](#3-threat-model)).
- **Search inside secret values.**
- **Secret history.** The audit log says who changed which field and when, not what it was. Kept
  for a later version ([§16](#16-open-questions)).
- **Webhook events and notifications** for credentials, in this version.
- **Browser autofill, a password generator, sharing a credential by link** outside the wiki.

---

## 2. Vocabulary

| Term             | Meaning                                                                                       |
| ---------------- | --------------------------------------------------------------------------------------------- |
| **Template**     | A row in `credentialTemplates`: a named list of fields                                        |
| **Field**        | `{ id, label, type, required, hint }` in a template. `id` is a stable slug                    |
| **Secret field** | A field of type `secret` or `totp`. Its value lives only in the encrypted blob                |
| **Credential**   | A row in `credentials`: a path, a stable `key` within that path, a template, and the values   |
| **Instance key** | The 32 bytes in `WIKI_CREDENTIALS_KEY`                                                        |
| **Key id**       | First 8 bytes of SHA-256 of the instance key, hex. Names which key sealed a row               |
| **Reveal**       | Returning one secret field's plain value (or a TOTP code) to a caller, one field per request  |

---

## 3. Threat model

| Protected                                                                                  | Not protected                                                                                                                         |
| ------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------- |
| A database dump, backup, snapshot or replica, without the environment                     | Somebody holding both the environment (or the host) and the database                                                                 |
| Read-only database access: a DBA, a reporting user, the hosting provider's staff           | A compromised application server: the key is in its memory and environment                                                           |
| PostgreSQL logs, `pg_stat_activity`, the WAL                                               | Somebody with **write** access to the database, who can grant themselves `reveal:credentials`                                        |
| Storage targets, git included: they receive ciphertext only                                | `manage:system`, which passes every check                                                                                            |
| The search index: secrets are never indexed                                                | **An agent granted reveal.** A revealed value enters the model's context and the local Claude Code transcript, and a prompt injection in a client's project can ask for it ([§9.4](#94-why-reveal-is-separate)) |
| A reader holding `read:credentials` but not `reveal:credentials`                           | Metadata: names, user names, URLs, IPs, notes. Users will put secrets in notes; the editor says not to                               |
|                                                                                            | Git history: every ciphertext ever exported stays there. If the key leaks, rotating it does not protect them — the real passwords have to be changed |

---

## 4. Keys

### 4.1 `WIKI_CREDENTIALS_KEY`

32 random bytes, base64. Generated once by the operator (`openssl rand -base64 32`) and given to
every instance (in the Helm chart, a Kubernetes Secret created at install and kept across upgrades
with `lookup`, as [`vault.md` §16](./vault.md#16-later-authenticating-peers) describes for its cluster
secret). A value that does not decode to exactly 32 bytes is a boot error logged at `error`, and the
feature behaves as if the key were absent.

`WIKI_CREDENTIALS_KEY_PREVIOUS` is read too, and used only to open rows during a rotation
([§4.4](#44-rotation)).

The key is read once at boot into a `Buffer` held by `helpers/credentialCrypto.ts` and nowhere else.
It is never logged, never sent over pubsub and never returned by any route. The admin screen shows
only its state and key id.

### 4.2 Without the key

The wiki boots. Credentials stay **listable and searchable**, since metadata needs no key. What needs
the key answers **503** `credentialsKeyMissing`: revealing, and any write that sets a secret field.
A write that touches only metadata still works. The MCP reveal tool is not listed, and the interface
shows the state on the admin screen and disables the reveal buttons.

### 4.3 The wrong key

There is no stored check value. Every blob carries its key id ([§5.3](#53-the-sealed-blob)), and
GCM authentication fails under the wrong key. At boot the model counts rows whose key id is neither
the current nor the previous key's and logs the count at `warn`. Revealing such a row answers
**409** `credentialsKeyMismatch`.

### 4.4 Rotation

Phase 6. The operator sets the new key in `WIKI_CREDENTIALS_KEY`, moves the old one to
`WIKI_CREDENTIALS_KEY_PREVIOUS`, restarts, and runs `npm run cli -- credentials-rekey`, which re-seals
every row under the previous key id in batches and re-exports it to storage targets. Once it reports
zero rows left, the previous key is removed from the environment.

Rotation protects the database from then on. It does not protect copies made before it: backups, and
git history ([§3](#3-threat-model)).

---

## 5. Data model

One migration, `npm run db-generate -- --name=credentials`. New tables only.

### 5.1 `credentialTemplates`

| Column                   | Type                | Notes                                                                   |
| ------------------------ | ------------------- | ----------------------------------------------------------------------- |
| `id`                     | `uuid` PK           |                                                                         |
| `siteId`                 | `uuid` FK → `sites` | Cascade                                                                 |
| `key`                    | `varchar(64)`       | Slug, unique per site. How storage files and MCP name a template        |
| `name`                   | `varchar(255)`      |                                                                         |
| `icon`                   | `varchar(255)`      | As page icons                                                           |
| `fields`                 | `jsonb`             | `[{ id, label, type, required, hint }]`, in display order               |
| `createdAt`, `updatedAt` | `timestamp`         |                                                                         |

Field types: `text`, `multiline`, `url`, `email`, `secret`, `totp`. Field ids are unique within a
template and never reused for another field.

- **A field's type may not cross the secret line** (`secret`/`totp` ↔ anything else) once any
  credential has a value for it: the value lives in a different column, and moving it is an
  explicit migration of the template, not an edit. Refused with 409.
- **Removing a field keeps its values.** They are stored by field id, are no longer shown or
  revealed, and come back if a field with that id is restored. They are dropped when the credential
  is next saved.
- **A template in use cannot be deleted** (409, with the count).

### 5.2 `credentials`

| Column                   | Type                                  | Notes                                                                                                         |
| ------------------------ | ------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| `id`                     | `uuid` PK                             | Stable across instances: it is written to the storage file and is part of the AAD ([§5.3](#53-the-sealed-blob)) |
| `siteId`                 | `uuid` FK → `sites`                   | Cascade                                                                                                       |
| `path`                   | `varchar(255)`, as `pages.path`       | The folder (or page path) the credential belongs to. Moved by `tree.refreshDescendantPaths` ([§11](#11-moves-and-deletes)) |
| `key`                    | `varchar(128)`                        | Slug. Unique per `(siteId, path, key)`. The upsert handle ([§10.2](#102-writing))                             |
| `templateId`             | `uuid` FK → `credentialTemplates`     | Restrict                                                                                                      |
| `name`                   | `varchar(255)`                        |                                                                                                               |
| `tags`                   | `text[]`                              |                                                                                                               |
| `fields`                 | `jsonb`                               | `{ fieldId: value }` for non-secret fields                                                                    |
| `secrets`                | `bytea`                               | The sealed blob of `{ fieldId: value }` for secret fields. Null when there are none                          |
| `secretFields`           | `text[]`                              | Which secret fields hold a value, so a listing can say "set" without decrypting                              |
| `keyId`                  | `varchar(16)`                         | Key id of `secrets`. Null exactly when `secrets` is                                                          |
| `ts`                     | `tsvector`                            | [§7](#7-search)                                                                                               |
| `createdBy`, `updatedBy` | `uuid` FK → `users`, set null         |                                                                                                               |
| `createdAt`, `updatedAt`, `secretsUpdatedAt` | `timestamp`       | `secretsUpdatedAt` moves only when a secret value changes                                                    |

There is no locale column. A credential belongs to a site's folder, not to a translation, and its
permissions are asked in the site's primary locale, as a live note's are (`liveNotes.permissionsFor`).

### 5.3 The sealed blob

```
"WKC1" (4 bytes) | keyId (8 bytes) | nonce (12 random bytes) | ciphertext | GCM tag (16 bytes)
```

The plaintext is the JSON of `{ fieldId: value }`. AAD: `siteId | credentialId | "secrets"`. Binding
the row stops one credential's blob from being copied under another's id. The path is not in the AAD,
so a folder move re-encrypts nothing.

`helpers/credentialCrypto.ts` exports `seal(siteId, id, values)`, `open(siteId, id, blob)`,
`keyIdOf(blob)` and `keyState()`. Nothing else touches `node:crypto` for this feature. It ships with a
test, `helpers/credentialCrypto.test.ts`, run by `npm test` in `backend/`: round trip, wrong AAD
fails, wrong key fails, truncated blob fails.

### 5.4 Constraints

- `(secrets IS NULL) = (keyId IS NULL)`.
- `secrets IS NULL OR substring(secrets FROM 1 FOR 4) = 'WKC1'::bytea`, so a code path that forgets to
  seal fails loudly.
- Unique `(siteId, path, key)`; unique `(siteId, key)` on templates.

---

## 6. Permissions

### 6.1 Three page permissions

Added to `PAGE_PERMISSIONS` in `models/groups.ts` and to the rule permissions of
`GroupEditOverlay.vue`. Approved by the maintainer of this fork. Asked at the credential's path, in
the site's primary locale, through `groups.checkAccess` with a `RulePageRef` of `{ siteId, path }`,
which needs no page row, so a folder works.

| Permission            | Grants                                                                          | Implies              |
| --------------------- | ------------------------------------------------------------------------------- | -------------------- |
| `read:credentials`    | Seeing the credential: metadata, and which secret fields are set                | —                    |
| `reveal:credentials`  | Revealing a secret field or a TOTP code                                         | `read:credentials`   |
| `manage:credentials`  | Creating, updating, moving and deleting credentials, and writing secret values  | `read:credentials`   |

The implications are `IMPLIED_PAGE_PERMISSIONS` in `models/groups.ts`, applied in `checkAccess` the
way `IMPLIED_LOCALE_PERMISSIONS` is applied in `checkLocaleAccess` (`grants(p) || grants(implied)`). **Managing does not imply revealing**: an
account can write a secret it can never read back, which is exactly what an agent needs
([§6.4](#64-one-service-account-per-client)). An administrator who should do both is granted both.

- **Never to a request with no account**, regardless of what the rules say, and not in
  `GUEST_ROLES`. A system API key acts as no user and is refused too.
- **No group is seeded with any of them.** An administrator grants them per client folder.
- **Not elevated.** They change nothing about who holds what.

### 6.2 Templates

Managing templates is part of a site's settings: `manage:sites`, the existing global permission.
Reading templates needs a signed-in account.

### 6.3 Acts

| Act                                         | Needs                                                            |
| ------------------------------------------- | ---------------------------------------------------------------- |
| List, search, read metadata                 | `read:credentials` at the credential's path                      |
| Reveal a field                              | `reveal:credentials` at the path, and the key ([§4.2](#42-without-the-key)) |
| Create, update, delete                      | `manage:credentials` at the path                                 |
| Move to another path                        | `manage:credentials` at both paths                               |
| Manage templates                            | `manage:sites`                                                   |

### 6.4 One service account per client

The setup the interface and the docs recommend for agents ([§9.5](#95-setting-up-a-client-project)):
an account per client (`bot-acme`) in a group of its own whose rules cover only `/clients/acme`, with
`read:pages`, `write:pages`, `read:credentials` and `manage:credentials`. A personal access token acts
as its owner, so a token from the administrator's own account would let one client's project reach
every client. With a service account, a mistake or a prompt injection in Acme's project stays inside
Acme's folder, and the audit log names the project that did it.

The service account holds no `reveal:credentials`, so it writes secrets it can never read back, over
REST or MCP. A project that genuinely needs to read a secret is given `reveal:credentials` on its
group **and** needs the instance's `credentials-reveal` MCP group on ([§9.2](#92-tool-groups)): two
separate decisions.

### 6.5 Vaults

[`vault.md`](./vault.md) makes everything under a vault invisible to MCP. Credentials therefore
cannot be created under a vault's path, nor moved into one, and a vault cannot be created over a path
that holds credentials. Both are checked through `vaults.vaultFor` once vaults exist. Until then
there is nothing to check.

---

## 7. Search

Today only pages are indexed (`searchPages`, `models/search.ts`). Credentials get an index of their
own:

- `ts` is built from the name, tags, the template's name, and the values of non-secret fields.
  Secret and TOTP values never enter it.
- `models/credentials.ts` `search(actor, siteId, query, { path })` uses `toTsQueryText` and ranks as
  pages do. Results are filtered by `read:credentials` per path, with the rule resolution cached per
  distinct path within one query.
- The search panel shows a **Credentials** section under the page results, for callers who hold
  `read:credentials` anywhere. Page search is unchanged.

---

## 8. Storage sync

Today storage targets carry pages and assets only. Credentials and templates are added as a third
kind of file, written and read through `helpers/storageFiles.ts` like the other two.

### 8.1 Files

A credential is one file in the site's primary locale directory, under its path:

```yaml
# <root>/<primary locale>/clients/acme/servers/web01.credential.yml
id: 3f2a6c1e-…
key: web01
template: server
name: web01 (production)
tags: [production, linux]
fields:
  username: root
  ip: 10.0.0.5
secrets: WKC1:9c1f…:base64…
updatedAt: 2026-11-18T10:00:00Z
```

Templates are one file per site, `<root>/<primary locale>/_credential-templates.yml`.

`.credential.yml` is added to the reserved extensions, as `pageExtensions` are, so an asset cannot
collide with a credential file.

### 8.2 Export

Every create, update, move and delete queues the matching put, move or delete on the site's targets,
through the same outbox as pages. `exportAll` writes every credential and the templates file. The
blob is written as stored; exporting never decrypts.

### 8.3 Import

`importTree` recognises `.credential.yml` and the templates file:

- The templates file is imported first.
- A credential whose template key is unknown is skipped and logged.
- A credential whose `secrets` does not open under the current or previous key is **refused** and
  logged, never stored: it would be data nobody can read. With no key configured, import of
  credentials with secrets is skipped and logged.
- Conflicts and deletions follow what the target already does for pages (`importAll` /
  `importAllOverwrite`, the git rebase with the remote winning).
- An import is not a caller, so it checks no permission, as page imports do not. It is audited once
  per run with counts ([§12](#12-audit-log)).

### 8.4 What this concedes

Every ciphertext ever exported stays in a git target's history. Another instance with the same key
reads them all. This is the trade for syncing at all, and the storage settings screen says so beside
the credentials switch: **Sync credentials**, per target, off by default.

---

## 9. MCP

### 9.1 Tools

| Tool                     | Group                 | Does                                                                                                                                 |
| ------------------------ | --------------------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| `credential_templates`   | `credentials`         | Lists templates with their fields, so an agent knows what to fill                                                                    |
| `credential_list`        | `credentials`         | `{ path?, recursive }`. Metadata only; no `path` lists everything the caller may read                                                                                                 |
| `credential_search`      | `credentials`         | `{ query, path? }`. Metadata only                                                                                                    |
| `credential_get`         | `credentials`         | `{ id }` or `{ path, key }`. Metadata only, plus which secret fields are set                                                         |
| `credential_upsert`      | `credentials`         | `{ path, key, template, name, tags, fields, secrets }`. Creates or updates by `(path, key)` ([§10.2](#102-writing)). Returns metadata |
| `credential_move`        | `credentials`         | `{ id, path }`                                                                                                                       |
| `credential_delete`      | `destructive`         | `{ id }`. In the existing destructive group, with the other deletes                                                                  |
| `credential_reveal`      | `credentials-reveal`  | `{ id, field }`. One field. A TOTP field answers the current code and its remaining seconds                                          |

Tools ask `McpContext` for `holdsScope` and for the page permission at the path, as the page tools
do. No tool returns a secret except `credential_reveal`.

The tools call `models/credentials.ts` directly rather than the REST routes in-process, since the
rules live in the model; the routes' audit helpers and the reveal rate limit are shared
(`api/credentials.ts`), so both surfaces write the same entries and count against one budget. A
refusal is a tool error naming its code (`credentialsKeyMissing`, `credentialsKeyMismatch`, …), 503
included. A caller with no account is refused. `credential_delete` needs `credentials:write` like the
other writes, not `pages:write`, although it sits in the `destructive` group. `credential_search` is
`list` with a `query`, which is the same `ts` match the REST `?q` will use ([§7](#7-search)).

### 9.2 Tool groups

`credentials` and `credentials-reveal` are added to `MCP_TOOL_GROUPS` (`models/mcp.ts`). Groups are
switched instance-wide in `mcp.tools`. Defaults in `backend/base.yml`:

```yaml
credentials: true
credentials-reveal: false
```

With `credentials-reveal` off, `credential_reveal` is listed to nobody, regardless of a token's
scopes or its owner's permissions.

### 9.3 Token scope

A new `credentials` category in `TOKEN_SCOPE_CATEGORIES` (`models/personalTokens.ts`, mirrored in
`frontend/src/helpers/personalTokens.js`): read for listing, searching and revealing, write for the
rest. The REST routes declare `config.scope: 'credentials'`.

### 9.4 Why reveal is separate

Writing a secret over MCP exposes nothing new: an agent that stores an API key read it from the
project first, so it was already in its context. Revealing does expose something new. The value
enters the model's context and the session transcript on the developer's machine, and an agent that
can reveal can be talked into it by text it reads — a README, an issue, a page — in the project it
is working on. So the default is write-only, and reveal is an instance-wide decision on top of a
per-account permission. Every reveal is audited with the token's id.

`credential_reveal`'s tool description says that the value must not be written to files, commits or
pages.

### 9.5 Setting up a client project

1. Create the service account and its group ([§6.4](#64-one-service-account-per-client)).
2. Create a personal access token for it with the `mcp`, `pages` and `credentials` scopes.
3. In the client project's `.mcp.json`, point the wiki's MCP server at that token, read from an
   environment variable rather than written into the file.

The project's `CLAUDE.md` then tells the agent where the client's folder is and which template to use
for what. That is documentation for the user, not code in the wiki.

---

## 10. API

All under `/_api/sites/:siteId/credentials`, tagged `Credentials`, with `config.scope: 'credentials'`.
None declares a route permission: the three permissions are page permissions, so each route checks in
its handler and says so with a `No route-level permissions:` comment, as `api/pages.ts` does.

### 10.1 Routes

| Route                   | Needs                              | What                                                                        |
| ----------------------- | ---------------------------------- | --------------------------------------------------------------------------- |
| `GET /`                 | `read:credentials`, per row        | `?path&recursive&q`. Metadata only                                          |
| `GET /:id`              | `read:credentials`                 | Metadata only                                                               |
| `PUT /`                 | `manage:credentials`               | Upsert by `(path, key)` ([§10.2](#102-writing))                             |
| `PUT /:id`              | `manage:credentials` (both paths)  | Update, a new `path` included                                               |
| `DELETE /:id`           | `manage:credentials`               |                                                                             |
| `POST /:id/reveal`      | `reveal:credentials`               | `{ field }` ([§10.3](#103-revealing))                                       |
| `GET /templates`        | signed in                          |                                                                             |
| `POST /templates`       | `manage:sites`                     |                                                                             |
| `PUT /templates/:id`    | `manage:sites`                     |                                                                             |
| `DELETE /templates/:id` | `manage:sites`                     | 409 while in use                                                            |
| `GET /status`           | `manage:sites`                     | Key state, key id, counts under the previous and unknown keys               |

Maintenance mode: reveal is `maintenance: 'read'` (a POST that changes nothing); every write is
refused by default, as everywhere.

### 10.2 Writing

- **Upsert** (`PUT /`) finds the credential by `(siteId, path, key)` and updates it, or creates it.
  This is what lets an agent run the same update twice and get one credential.
- **Secret values**, on create and update: a field omitted, or sent as `SENSITIVE_MASK`, is
  unchanged; `null` clears it; a string sets it. Only when something changed is the blob re-sealed and
  `secretsUpdatedAt` moved.
- **Validation** against the template: unknown field ids refused, required fields enforced on
  create, a secret value sent in `fields` (or the reverse) refused, `url` and `email` checked.
  Limits: 64 fields per template, 16 KB per value, 64 KB per sealed blob.
- **A credential keeps its template.** Naming another one on update is refused with 409
  `credentialTemplateChange`: its values are stored by the template's field ids.
- **A required field cannot be cleared** on update: sending `null` for one is refused with 400.

### 10.3 Revealing

`POST /:id/reveal { field }` answers `{ value }`, or for a TOTP field `{ code, expiresIn }`, computed
with `currentTotpCode` in `helpers/totp.ts` so the seed never leaves the server. One field per request, so that the audit
log says exactly what was seen. `Cache-Control: private, no-store`. Rate-limited per account with
a `TokenBucketPolicy` (60 a minute): far above what a person clicks, and an alarm for a script that
is draining a folder.

---

## 11. Moves and deletes

- **Folder rename and move.** `tree.refreshDescendantPaths` (`models/tree.ts`), which today updates
  `tree` and `pages` by `folderPath <@ path`, updates `credentials` in the same statement set, and the
  storage outbox gets the matching file moves. Credentials follow only a folder of the site's primary
  locale, which is the locale they are asked in ([§5.2](#52-credentials)); a folder of another
  locale holds none. Moving or renaming a folder that holds credentials also
  needs `manage:credentials` at the folder, so that somebody who cannot see them cannot carry them
  elsewhere.
- **A rename or move that would collide** with a credential already at the destination, same `key`,
  is refused before anything moves with 409 `credentialPathConflict`.
- **Deleting a folder** that holds credentials deletes them, and needs `manage:credentials` at the
  folder; without it the delete is refused with 409 and the count. The route deletes them, not
  `tree.deleteFolder`, and the empty-folder purge skips a folder that holds any.
- **Deleting a page** touches nothing: a credential belongs to a path, not to a page.
- **Page edit lock** (`isEditLocked`) does not apply to credentials.

---

## 12. Audit log

A new kind, `credential`, in `AUDIT_KINDS`, with the actions `createCredential`, `updateCredential`,
`moveCredential`, `deleteCredential`, `revealCredential`, `createCredentialTemplate`,
`updateCredentialTemplate`, `deleteCredentialTemplate` and `importCredentials`, in `AUDIT_ACTIONS`,
with
`admin.audit.kinds.credential` and the action strings in `backend/locales/en.json`.

Action keys are unique across kinds, so the generic `create` or `delete` would collide as translation
keys; each names what it acts on.

`meta` carries the credential's id, path and key — as `handle`, since `sanitizeMeta` redacts a key
named `key` — and: for `update`, the ids of the fields that
changed and whether any secret did, as `sealedChanged` (a name with `secret` in it would be redacted too); for `reveal`, the field id; for `import`, counts. `audit()` adds
`patId` for a token. Never a value, of any field, in any form.

---

## 13. Frontend

- **On a page:** a **Credentials** panel listing the credentials at the page's path and below, for
  readers who hold `read:credentials` there (gated on `pagePermissions`). Each row shows the template
  icon, name, tags and non-secret fields, and for each secret field **Reveal** and **Copy**. A
  revealed value hides itself after 30 seconds. A TOTP field shows the code with a countdown.
- **Editor dialog**, built from the template's fields, for `manage:credentials`. Secret fields show
  "set" or "not set" and are only ever replaced, never pre-filled.
- **`/_credentials`:** every credential the reader may see on the site, with search and a path
  filter.
- **Administration → Credentials:** the template editor and the key status ([§10.1](#101-routes)).
- **Group editor:** the three permissions in the rule permissions list.
- **Personal access token dialog:** the `credentials` scope category.
- **Storage settings:** the per-target **Sync credentials** switch and its warning
  ([§8.4](#84-what-this-concedes)).

Strings go in `backend/locales/en.json`.

---

## 14. What else is affected

| Subsystem                       | Effect                                                                                     |
| ------------------------------- | ------------------------------------------------------------------------------------------ |
| Webhooks, notifications, email  | No events in this version                                                                  |
| `.wkbackup` ([`wkbackup.md`](./wkbackup.md)) | Carries both tables as stored. A restore needs the same key to reveal anything |
| Sitemap, app shell, SEO         | Nothing: credentials are not pages                                                         |
| Page graph, backlinks           | Nothing                                                                                    |
| Vaults                          | [§6.5](#65-vaults)                                                                          |

---

## 15. Suggested order

1. **Core.** `helpers/credentialCrypto.ts` and its test, schema and migration, the constraints,
   templates, the three permissions and their implication chain, `models/credentials.ts`, the REST
   routes, audit, folder moves and deletes, `.claude/rules/credentials.md`.
2. **MCP.** The tools, the two groups and their defaults, the token scope category.
3. **Search.**
4. **Frontend.** The page panel, the editor, `/_credentials`, the admin screen, the group and token
   dialogs.
5. **Storage sync.** Files, export, import, the per-target switch.
6. **Rotation.** `WIKI_CREDENTIALS_KEY_PREVIOUS` and `credentials-rekey`.

MCP comes before the interface because agents filling the wiki is the main use. After phase 2 an
agent can already create and update credentials, and an administrator can read them over REST.

---

## 16. Open questions

- **Secret history.** Keeping previous values (sealed) for a time, for the "what was the password
  before Tuesday" case.
- **Templates per site or per instance.** Per site here; an MSP with several sites would repeat them.
- **Webhook events** carrying metadata only, for an external CMDB.
- **Sync on by default** for git targets, once the warning has been lived with.
