import { audit } from '../helpers/audit.ts'
import { requestUser } from '../helpers/requester.ts'
import { TokenBucketLimiter } from '../helpers/tokenBucket.ts'
import { keyState } from '../helpers/credentialCrypto.ts'
import { userRequired } from './pages.ts'
import { CREDENTIAL_INPUT_PROPERTIES, TEMPLATE_INPUT_PROPERTIES } from './schemas/credentials.ts'
import type { FastifyReply, FastifyRequest } from 'fastify'
import type { FastifyInstance } from 'fastify'
import type {
  CredentialInput,
  CredentialRequester,
  CredentialView,
  CredentialWriteResult,
  TemplateInput
} from '../models/credentials.ts'

/** Sixty reveals a minute per account: far above what a person clicks, an alarm for a script. */
const revealLimiter = new TokenBucketLimiter()
const REVEAL_POLICY = { burst: 60, perMinute: 60 }

const siteIdParam = {
  type: 'object',
  properties: { siteId: { type: 'string', format: 'uuid' } },
  required: ['siteId']
}

const idParam = {
  type: 'object',
  properties: {
    siteId: { type: 'string', format: 'uuid' },
    id: { type: 'string', format: 'uuid' }
  },
  required: ['siteId', 'id']
}

/** The caller as the credentials model wants it, or null when the request acts as no account. */
function requesterOf(req: FastifyRequest): CredentialRequester | null {
  const user = requestUser(req)
  return user ? { actor: WIKI.models.groups.actorForRequest(req), userId: user.id } : null
}

/**
 * The checks every route makes first: the site, and an account. A system API key acts as nobody and
 * is refused here, as a guest is.
 */
function guard(
  req: FastifyRequest<{ Params: { siteId: string } }>,
  reply: FastifyReply,
  action: string
): CredentialRequester | null {
  if (!WIKI.sites[req.params.siteId]) {
    reply.notFound('Site does not exist.')
    return null
  }
  const requester = requesterOf(req)
  if (!requester) {
    reply.unauthorized(userRequired(req, action))
    return null
  }
  return requester
}

/**
 * The audit entries a write is owed. Identity only, never a value. Exported, with the two below, for
 * the MCP tools, which write through the same model and are owed the same entries.
 */
export async function auditWrite(
  req: FastifyRequest,
  siteId: string,
  result: CredentialWriteResult
) {
  const { credential } = result
  // -> `handle`, not `key`: `sanitizeMeta` redacts a key named `key` as a secret
  const meta = { siteId, id: credential.id, path: credential.path, handle: credential.key }
  if (result.created) {
    await audit(req, 'credential', 'createCredential', meta)
    return
  }
  if (result.previousPath !== null) {
    await audit(req, 'credential', 'moveCredential', {
      ...meta,
      previousPath: result.previousPath
    })
  }
  if (result.changed.length > 0 || result.secretsChanged) {
    await audit(req, 'credential', 'updateCredential', {
      ...meta,
      fields: result.changed,
      sealedChanged: result.secretsChanged
    })
  }
}

/** The entry a deletion is owed. */
export async function auditDelete(req: FastifyRequest, siteId: string, credential: CredentialView) {
  await audit(req, 'credential', 'deleteCredential', {
    siteId,
    id: credential.id,
    path: credential.path,
    handle: credential.key
  })
}

/** The entry a reveal is owed: which field, never its value. */
export async function auditReveal(
  req: FastifyRequest,
  siteId: string,
  credential: CredentialView,
  field: string
) {
  await audit(req, 'credential', 'revealCredential', {
    siteId,
    id: credential.id,
    path: credential.path,
    handle: credential.key,
    field
  })
}

/** Spend one reveal of an account's budget. Shared with the MCP tool, so the two surfaces count as one. */
export function takeReveal(userId: string | null) {
  return revealLimiter.take(`reveal:${userId}`, REVEAL_POLICY)
}

/**
 * Credentials API Routes
 *
 * Records attached to a folder path, with encrypted secret fields. See `dev/specs/credentials.md`.
 *
 * `read:credentials`, `reveal:credentials` and `manage:credentials` are PAGE permissions, asked at the
 * credential's path, so no route here declares route-level `permissions` except the template ones,
 * which are `manage:sites`.
 */
async function routes(app: FastifyInstance) {
  /**
   * LIST CREDENTIALS
   */
  // -> No route-level permissions: `read:credentials` is a page permission, asked per row
  app.get<{
    Params: { siteId: string }
    Querystring: { path?: string; recursive?: boolean }
  }>(
    '/sites/:siteId/credentials',
    {
      config: { scope: 'credentials' },
      schema: {
        summary: 'List credentials',
        description:
          'Metadata only, never a secret. Limited to the credentials the caller holds `read:credentials` on, at each one’s path. `path` limits the list to a folder, and `recursive` takes everything below it too.',
        tags: ['Credentials'],
        params: siteIdParam,
        querystring: {
          type: 'object',
          properties: {
            path: { type: 'string', maxLength: 255 },
            recursive: { type: 'boolean', default: false }
          }
        },
        response: {
          200: { type: 'array', items: { $ref: 'Credential#' } }
        }
      }
    },
    async (req, reply) => {
      const requester = guard(req, reply, 'Listing credentials')
      if (!requester) {
        return
      }
      return WIKI.models.credentials.list(requester, req.params.siteId, req.query)
    }
  )

  /**
   * KEY STATUS
   */
  app.get<{ Params: { siteId: string } }>(
    '/sites/:siteId/credentials/status',
    {
      config: { permissions: ['manage:sites'], scope: 'credentials' },
      schema: {
        summary: 'State of the credentials key',
        description:
          'Whether the instance holds `WIKI_CREDENTIALS_KEY`, the ids of the current and the previous key, and how many credentials are sealed under the previous key and under a key the instance does not hold. Never the key.',
        tags: ['Credentials'],
        params: siteIdParam,
        response: {
          200: {
            type: 'object',
            properties: {
              state: { type: 'string', enum: ['ok', 'missing', 'invalid'] },
              keyId: { type: ['string', 'null'] },
              previousKeyId: { type: ['string', 'null'] },
              previousCount: { type: 'integer' },
              unknownCount: { type: 'integer' }
            }
          }
        }
      }
    },
    async () => {
      const counts = await WIKI.models.credentials.keyCounts()
      return { ...keyState(), previousCount: counts.previous, unknownCount: counts.unknown }
    }
  )

  /**
   * LIST TEMPLATES
   */
  app.get<{ Params: { siteId: string } }>(
    '/sites/:siteId/credentials/templates',
    {
      config: { scope: 'credentials' },
      schema: {
        summary: 'List credential templates',
        description: 'Needs a signed-in account.',
        tags: ['Credentials'],
        params: siteIdParam,
        response: { 200: { type: 'array', items: { $ref: 'CredentialTemplate#' } } }
      }
    },
    async (req, reply) => {
      if (!guard(req, reply, 'Listing credential templates')) {
        return
      }
      return WIKI.models.credentials.listTemplates(req.params.siteId)
    }
  )

  /**
   * CREATE TEMPLATE
   */
  app.post<{ Params: { siteId: string }; Body: TemplateInput }>(
    '/sites/:siteId/credentials/templates',
    {
      config: { permissions: ['manage:sites'], scope: 'credentials' },
      schema: {
        summary: 'Create a credential template',
        tags: ['Credentials'],
        params: siteIdParam,
        body: {
          type: 'object',
          properties: TEMPLATE_INPUT_PROPERTIES,
          required: ['key', 'name', 'fields'],
          additionalProperties: false
        },
        response: { 200: { $ref: 'CredentialTemplate#' } }
      }
    },
    async (req, reply) => {
      if (!guard(req, reply, 'Creating a credential template')) {
        return
      }
      const template = await WIKI.models.credentials.createTemplate(req.params.siteId, req.body)
      await audit(req, 'credential', 'createCredentialTemplate', {
        siteId: req.params.siteId,
        id: template.id,
        handle: template.key
      })
      return template
    }
  )

  /**
   * UPDATE TEMPLATE
   */
  app.put<{ Params: { siteId: string; id: string }; Body: TemplateInput }>(
    '/sites/:siteId/credentials/templates/:id',
    {
      config: { permissions: ['manage:sites'], scope: 'credentials' },
      schema: {
        summary: 'Update a credential template',
        description:
          'A field’s type may not cross the secret line (`secret`/`totp` to anything else, or back) while a credential holds a value for it: refused with 409. A field taken out keeps its stored values, which come back if a field with that id is restored.',
        tags: ['Credentials'],
        params: idParam,
        body: {
          type: 'object',
          properties: TEMPLATE_INPUT_PROPERTIES,
          required: ['key', 'name', 'fields'],
          additionalProperties: false
        },
        response: { 200: { $ref: 'CredentialTemplate#' } }
      }
    },
    async (req, reply) => {
      if (!guard(req, reply, 'Updating a credential template')) {
        return
      }
      const template = await WIKI.models.credentials.updateTemplate(
        req.params.siteId,
        req.params.id,
        req.body
      )
      if (!template) {
        return reply.notFound('This template does not exist.')
      }
      await audit(req, 'credential', 'updateCredentialTemplate', {
        siteId: req.params.siteId,
        id: template.id,
        handle: template.key
      })
      return template
    }
  )

  /**
   * DELETE TEMPLATE
   */
  app.delete<{ Params: { siteId: string; id: string } }>(
    '/sites/:siteId/credentials/templates/:id',
    {
      config: { permissions: ['manage:sites'], scope: 'credentials' },
      schema: {
        summary: 'Delete a credential template',
        description: 'Refused with 409 while any credential uses it.',
        tags: ['Credentials'],
        params: idParam,
        response: { 204: { description: 'Template deleted' } }
      }
    },
    async (req, reply) => {
      if (!guard(req, reply, 'Deleting a credential template')) {
        return
      }
      const template = await WIKI.models.credentials.deleteTemplate(
        req.params.siteId,
        req.params.id
      )
      if (!template) {
        return reply.notFound('This template does not exist.')
      }
      await audit(req, 'credential', 'deleteCredentialTemplate', {
        siteId: req.params.siteId,
        id: template.id,
        handle: template.key
      })
      return reply.code(204).send()
    }
  )

  /**
   * GET CREDENTIAL
   */
  // -> No route-level permissions: `read:credentials` is a page permission, asked at the path
  app.get<{ Params: { siteId: string; id: string } }>(
    '/sites/:siteId/credentials/:id',
    {
      config: { scope: 'credentials' },
      schema: {
        summary: 'Get a credential',
        description: 'Metadata only, and which secret fields hold a value.',
        tags: ['Credentials'],
        params: idParam,
        response: { 200: { $ref: 'Credential#' } }
      }
    },
    async (req, reply) => {
      const requester = guard(req, reply, 'Reading a credential')
      if (!requester) {
        return
      }
      const credential = await WIKI.models.credentials.get(
        requester,
        req.params.siteId,
        req.params.id
      )
      return credential ?? reply.notFound('This credential does not exist.')
    }
  )

  /**
   * UPSERT CREDENTIAL
   */
  // -> No route-level permissions: `manage:credentials` is a page permission, asked at the path
  app.put<{ Params: { siteId: string }; Body: CredentialInput }>(
    '/sites/:siteId/credentials',
    {
      config: { scope: 'credentials' },
      schema: {
        summary: 'Create or update a credential by path and key',
        description:
          'Finds the credential by `(path, key)` and updates it, or creates it, so the same call made twice leaves one credential. Needs `manage:credentials` at the path. Secret values need the instance’s credentials key: without it, 503 `credentialsKeyMissing`; a write that touches no secret still works.',
        tags: ['Credentials'],
        params: siteIdParam,
        body: {
          type: 'object',
          properties: {
            path: { type: 'string', minLength: 1, maxLength: 255 },
            key: { type: 'string', minLength: 1, maxLength: 128 },
            template: {
              type: 'string',
              description: 'The template’s key or id. Needed to create; fixed once created.'
            },
            ...CREDENTIAL_INPUT_PROPERTIES
          },
          required: ['path', 'key'],
          additionalProperties: false
        },
        response: { 200: { $ref: 'Credential#' } }
      }
    },
    async (req, reply) => {
      const requester = guard(req, reply, 'Saving a credential')
      if (!requester) {
        return
      }
      const result = await WIKI.models.credentials.upsert(requester, req.params.siteId, req.body)
      await auditWrite(req, req.params.siteId, result)
      return result.credential
    }
  )

  /**
   * UPDATE CREDENTIAL
   */
  // -> No route-level permissions: `manage:credentials` is a page permission, asked at both paths
  app.put<{
    Params: { siteId: string; id: string }
    Body: Partial<CredentialInput>
  }>(
    '/sites/:siteId/credentials/:id',
    {
      config: { scope: 'credentials' },
      schema: {
        summary: 'Update a credential',
        description:
          'A new `path` moves it, which needs `manage:credentials` at the old path and the new one.',
        tags: ['Credentials'],
        params: idParam,
        body: {
          type: 'object',
          properties: {
            path: { type: 'string', minLength: 1, maxLength: 255 },
            key: { type: 'string', minLength: 1, maxLength: 128 },
            ...CREDENTIAL_INPUT_PROPERTIES
          },
          additionalProperties: false
        },
        response: { 200: { $ref: 'Credential#' } }
      }
    },
    async (req, reply) => {
      const requester = guard(req, reply, 'Saving a credential')
      if (!requester) {
        return
      }
      const result = await WIKI.models.credentials.update(
        requester,
        req.params.siteId,
        req.params.id,
        req.body
      )
      if (!result) {
        return reply.notFound('This credential does not exist.')
      }
      await auditWrite(req, req.params.siteId, result)
      return result.credential
    }
  )

  /**
   * DELETE CREDENTIAL
   */
  // -> No route-level permissions: `manage:credentials` is a page permission, asked at the path
  app.delete<{ Params: { siteId: string; id: string } }>(
    '/sites/:siteId/credentials/:id',
    {
      config: { scope: 'credentials' },
      schema: {
        summary: 'Delete a credential',
        tags: ['Credentials'],
        params: idParam,
        response: { 204: { description: 'Credential deleted' } }
      }
    },
    async (req, reply) => {
      const requester = guard(req, reply, 'Deleting a credential')
      if (!requester) {
        return
      }
      const credential = await WIKI.models.credentials.delete(
        requester,
        req.params.siteId,
        req.params.id
      )
      if (!credential) {
        return reply.notFound('This credential does not exist.')
      }
      await auditDelete(req, req.params.siteId, credential)
      return reply.code(204).send()
    }
  )

  /**
   * REVEAL A FIELD
   */
  // -> No route-level permissions: `reveal:credentials` is a page permission, asked at the path
  app.post<{ Params: { siteId: string; id: string }; Body: { field: string } }>(
    '/sites/:siteId/credentials/:id/reveal',
    {
      config: {
        // -> A POST that changes nothing, which read-only mode treats like a GET, and a read for a
        //    token's scope
        scope: 'credentials:read',
        maintenance: 'read'
      },
      schema: {
        summary: 'Reveal a secret field',
        description:
          'One field per request, so that the audit log says exactly what was seen. Answers `{ value }`, or `{ code, expiresIn }` for a TOTP field, whose seed never leaves the server. Needs `reveal:credentials` at the path and the instance’s credentials key (503 `credentialsKeyMissing` without it, 409 `credentialsKeyMismatch` for a credential sealed under another). Limited to 60 a minute per account. Never cached.',
        tags: ['Credentials'],
        params: idParam,
        body: {
          type: 'object',
          properties: { field: { type: 'string', minLength: 1, maxLength: 64 } },
          required: ['field'],
          additionalProperties: false
        },
        response: {
          200: {
            type: 'object',
            properties: {
              value: { type: 'string' },
              code: { type: 'string' },
              expiresIn: { type: 'integer' }
            }
          }
        }
      }
    },
    async (req, reply) => {
      const requester = guard(req, reply, 'Revealing a credential')
      if (!requester) {
        return
      }
      reply.header('Cache-Control', 'private, no-store')
      const verdict = takeReveal(requester.userId)
      if (!verdict.allowed) {
        reply.header('Retry-After', String(verdict.retryAfter))
        return reply.tooManyRequests('Too many reveals. Try again shortly.')
      }
      const revealed = await WIKI.models.credentials.reveal(
        requester,
        req.params.siteId,
        req.params.id,
        req.body.field
      )
      if (!revealed) {
        return reply.notFound('This credential does not exist.')
      }
      const { credential } = revealed
      await auditReveal(req, req.params.siteId, credential, req.body.field)
      return revealed.result
    }
  )
}

export default routes
