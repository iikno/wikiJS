import { CustomError } from '../../helpers/common.ts'
import { auditDelete, auditReveal, auditWrite, takeReveal } from '../../api/credentials.ts'
import { jsonResult, ToolError } from '../tool.ts'
import type { CredentialRequester, CredentialView } from '../../models/credentials.ts'
import type { McpContext } from '../context.ts'
import type { McpTool } from '../tool.ts'

/**
 * Credentials over MCP: the same model as `/_api/sites/:siteId/credentials`, with the same checks and
 * the same audit entries. See `dev/specs/credentials.md` §9.
 *
 * Every tool refuses an agent acting as no account, asks the page permission at the credential's own
 * path (inside the model, as the REST routes do), and answers metadata only — except
 * `credential_reveal`, which is the one tool that returns a secret and lives in a group of its own,
 * off by default.
 */

/** The caller as the credentials model wants it. */
function requesterOf(ctx: McpContext): CredentialRequester {
  if (!ctx.user) {
    throw new ToolError('Credentials need a signed-in account; an anonymous caller has none.')
  }
  return { actor: ctx.actor, userId: ctx.user.id }
}

/**
 * Run a model call, turning its refusals into what an agent can read and act on. A `CustomError`
 * carries a code in its name and, for a missing key, a 503, which the protocol layer would otherwise
 * let through as a server fault.
 */
async function attempt<T>(call: () => Promise<T>): Promise<T> {
  try {
    return await call()
  } catch (err: any) {
    if (err instanceof CustomError) {
      throw new ToolError(`${err.name}: ${err.message}`)
    }
    throw err
  }
}

/** Credentials as an agent reads them: the template by its key, which is what `credential_upsert` takes. */
async function present(ctx: McpContext, views: CredentialView[]) {
  const templates = new Map(
    (await WIKI.models.credentials.listTemplates(ctx.siteId)).map((t) => [t.id, t.key])
  )
  return views.map(({ templateId, siteId: _siteId, ...rest }) => ({
    ...rest,
    template: templates.get(templateId) ?? null
  }))
}

const notFound = () => new ToolError('No such credential, or you may not read it.')

const SECRET_NOTE =
  'Secret values are never returned, only which secret fields hold a value (`secretFields`).'

const templates: McpTool<Record<string, never>> = {
  name: 'credential_templates',
  title: 'List credential templates',
  description:
    'Lists the credential templates of the site: each one’s `key`, name and its fields (`id`, label, `type`, `required`, hint). Call this first to learn which template to use and which field ids a credential takes. A field of type `secret` or `totp` goes in `secrets` when writing; every other type goes in `fields`.',
  group: 'credentials',
  category: 'credentials',
  readOnly: true,
  idempotent: true,
  inputSchema: { type: 'object', properties: {}, additionalProperties: false },
  async run(ctx) {
    requesterOf(ctx)
    const list = await WIKI.models.credentials.listTemplates(ctx.siteId)
    return jsonResult(list.map(({ key, name, icon, fields }) => ({ key, name, icon, fields })))
  }
}

const list: McpTool<{ path?: string; recursive: boolean }> = {
  name: 'credential_list',
  title: 'List credentials',
  description: `Lists the credentials the caller may read, as metadata: name, tags, template, path, key and the non-secret fields. ${SECRET_NOTE} Give \`path\` (a folder, e.g. \`clients/acme\`) to list that folder, and \`recursive\` to take everything below it too; leave \`path\` out for every credential the caller may see.`,
  group: 'credentials',
  category: 'credentials',
  readOnly: true,
  idempotent: true,
  inputSchema: {
    type: 'object',
    properties: {
      path: {
        type: 'string',
        maxLength: 255,
        description: 'A folder path, without a leading slash.'
      },
      recursive: {
        type: 'boolean',
        default: false,
        description: 'Include credentials in folders below `path`.'
      }
    },
    additionalProperties: false
  },
  async run(ctx, args) {
    const views = await attempt(() =>
      WIKI.models.credentials.list(requesterOf(ctx), ctx.siteId, args)
    )
    return jsonResult(await present(ctx, views))
  }
}

const search: McpTool<{ query: string; path?: string }> = {
  name: 'credential_search',
  title: 'Search credentials',
  description: `Full-text search over the credentials the caller may read, best match first. It matches the name, tags, template name and non-secret field values (a user name, a host, an IP) — never a secret. Same syntax as the wiki search: several words must all match, \`-word\` excludes, \`word*\` is a prefix, \`a or b\` either. ${SECRET_NOTE} \`path\` limits the search to a folder and everything below it.`,
  group: 'credentials',
  category: 'credentials',
  readOnly: true,
  idempotent: true,
  inputSchema: {
    type: 'object',
    properties: {
      query: { type: 'string', minLength: 1, maxLength: 255 },
      path: { type: 'string', maxLength: 255, description: 'A folder path to search under.' }
    },
    required: ['query'],
    additionalProperties: false
  },
  async run(ctx, args) {
    const views = await attempt(() =>
      WIKI.models.credentials.list(requesterOf(ctx), ctx.siteId, {
        path: args.path,
        recursive: true,
        query: args.query
      })
    )
    return jsonResult(await present(ctx, views))
  }
}

const get: McpTool<{ id?: string; path?: string; key?: string }> = {
  name: 'credential_get',
  title: 'Get a credential',
  description: `One credential's metadata, by \`id\` or by \`path\` and \`key\` together. ${SECRET_NOTE}`,
  group: 'credentials',
  category: 'credentials',
  readOnly: true,
  idempotent: true,
  inputSchema: {
    type: 'object',
    properties: {
      id: { type: 'string', format: 'uuid' },
      path: { type: 'string', maxLength: 255 },
      key: { type: 'string', maxLength: 128 }
    },
    additionalProperties: false
  },
  async run(ctx, args) {
    const requester = requesterOf(ctx)
    if (!args.id && !(args.path !== undefined && args.key)) {
      throw new ToolError('Give either `id`, or both `path` and `key`.')
    }
    const view = await attempt(() =>
      args.id
        ? WIKI.models.credentials.get(requester, ctx.siteId, args.id)
        : WIKI.models.credentials.getByHandle(requester, ctx.siteId, args.path!, args.key!)
    )
    if (!view) {
      throw notFound()
    }
    return jsonResult((await present(ctx, [view]))[0])
  }
}

interface UpsertArgs {
  path: string
  key: string
  template?: string
  name?: string
  tags?: string[]
  fields?: Record<string, string | null>
  secrets?: Record<string, string | null>
}

const upsert: McpTool<UpsertArgs> = {
  name: 'credential_upsert',
  title: 'Create or update a credential',
  description: `Creates or updates a credential, found by \`(path, key)\`: that pair is the idempotency handle, so running the same call twice leaves ONE credential. Pick a stable \`key\` (a slug such as \`web01\`) and reuse it. Call \`credential_templates\` first to learn the template \`key\` and the field ids.

To create, give \`template\`, \`name\` and the template's required fields. A credential keeps its template. Non-secret values go in \`fields\`, values of \`secret\` and \`totp\` fields in \`secrets\`. For both: a field you leave out is UNCHANGED, \`null\` CLEARS it, a string SETS it, so send only what changes. You may write a secret without being able to read it back. A TOTP field takes the base32 seed. Never put a password in \`name\`, \`tags\`, notes or any non-secret field: those are searchable and listed in the clear. Returns the metadata; ${SECRET_NOTE}`,
  group: 'credentials',
  category: 'credentials',
  readOnly: false,
  idempotent: true,
  inputSchema: {
    type: 'object',
    properties: {
      path: {
        type: 'string',
        minLength: 1,
        maxLength: 255,
        description: 'The folder the credential belongs to, e.g. `clients/acme/servers`.'
      },
      key: {
        type: 'string',
        minLength: 1,
        maxLength: 128,
        description: 'Slug, unique within `path`.'
      },
      template: { type: 'string', description: 'The template key. Needed to create.' },
      name: { type: 'string', minLength: 1, maxLength: 255 },
      tags: { type: 'array', maxItems: 50, items: { type: 'string', minLength: 1, maxLength: 64 } },
      fields: {
        type: 'object',
        description: 'Non-secret field values by field id. Omitted = unchanged, null = clear.',
        additionalProperties: { type: ['string', 'null'] }
      },
      secrets: {
        type: 'object',
        description: 'Secret and TOTP field values by field id. Omitted = unchanged, null = clear.',
        additionalProperties: { type: ['string', 'null'] }
      }
    },
    required: ['path', 'key'],
    additionalProperties: false
  },
  async run(ctx, args) {
    const result = await attempt(() =>
      WIKI.models.credentials.upsert(requesterOf(ctx), ctx.siteId, args)
    )
    await auditWrite(ctx.req, ctx.siteId, result)
    return jsonResult({
      created: result.created,
      ...(await present(ctx, [result.credential]))[0]
    })
  }
}

const move: McpTool<{ id: string; path: string }> = {
  name: 'credential_move',
  title: 'Move a credential',
  description:
    'Moves a credential to another folder path. Needs permission to manage credentials at both the old and the new path. Fails if the new path already has a credential with the same key.',
  group: 'credentials',
  category: 'credentials',
  readOnly: false,
  idempotent: true,
  inputSchema: {
    type: 'object',
    properties: {
      id: { type: 'string', format: 'uuid' },
      path: { type: 'string', minLength: 1, maxLength: 255, description: 'The new folder path.' }
    },
    required: ['id', 'path'],
    additionalProperties: false
  },
  async run(ctx, args) {
    const result = await attempt(() =>
      WIKI.models.credentials.update(requesterOf(ctx), ctx.siteId, args.id, { path: args.path })
    )
    if (!result) {
      throw notFound()
    }
    await auditWrite(ctx.req, ctx.siteId, result)
    return jsonResult((await present(ctx, [result.credential]))[0])
  }
}

const remove: McpTool<{ id: string }> = {
  name: 'credential_delete',
  title: 'Delete a credential',
  description:
    'Permanently deletes a credential and its secrets. There is no recycle bin and no history of secret values: delete only when the person you are working for asked for it.',
  group: 'destructive',
  category: 'credentials',
  readOnly: false,
  destructive: true,
  inputSchema: {
    type: 'object',
    properties: { id: { type: 'string', format: 'uuid' } },
    required: ['id'],
    additionalProperties: false
  },
  async run(ctx, args) {
    const credential = await attempt(() =>
      WIKI.models.credentials.delete(requesterOf(ctx), ctx.siteId, args.id)
    )
    if (!credential) {
      throw notFound()
    }
    await auditDelete(ctx.req, ctx.siteId, credential)
    return jsonResult({
      deleted: true,
      id: credential.id,
      path: credential.path,
      key: credential.key
    })
  }
}

const reveal: McpTool<{ id: string; field: string }> = {
  name: 'credential_reveal',
  title: 'Reveal a credential field',
  description:
    'Returns the plain value of ONE secret field of a credential (a TOTP field returns its current `code` and `expiresIn` seconds instead, never the seed). Use it only when the task needs the value right now, to run a command or sign in. NEVER write the value to a file, a commit, a page, a comment, a log or a chat message, and do not repeat it in your answer. Every reveal is recorded in the audit log with who asked and which field.',
  group: 'credentials-reveal',
  category: 'credentials',
  readOnly: true,
  inputSchema: {
    type: 'object',
    properties: {
      id: { type: 'string', format: 'uuid' },
      field: { type: 'string', minLength: 1, maxLength: 64, description: 'The secret field id.' }
    },
    required: ['id', 'field'],
    additionalProperties: false
  },
  async run(ctx, args) {
    const requester = requesterOf(ctx)
    const verdict = takeReveal(requester.userId)
    if (!verdict.allowed) {
      throw new ToolError(`Too many reveals. Try again in ${verdict.retryAfter} seconds.`)
    }
    const revealed = await attempt(() =>
      WIKI.models.credentials.reveal(requester, ctx.siteId, args.id, args.field)
    )
    if (!revealed) {
      throw notFound()
    }
    await auditReveal(ctx.req, ctx.siteId, revealed.credential, args.field)
    return jsonResult(revealed.result)
  }
}

export const credentialTools: McpTool[] = [
  templates,
  list,
  search,
  get,
  upsert,
  move,
  remove,
  reveal
]
