import { v4 as uuid } from 'uuid'
import { alias } from 'drizzle-orm/pg-core'
import { and, asc, desc, eq, isNotNull, notInArray, sql } from 'drizzle-orm'
import {
  credentials as credentialsTable,
  credentialTemplates as templatesTable
} from '../db/schema.ts'
import {
  CredentialCryptoError,
  keyIdOf,
  keyState,
  open,
  seal
} from '../helpers/credentialCrypto.ts'
import { CustomError, pagePathToWrite, SENSITIVE_MASK } from '../helpers/common.ts'
import { toTsQueryText } from '../helpers/searchQuery.ts'
import { currentTotpCode } from '../helpers/totp.ts'
import type { AccessActor } from './groups.ts'

/**
 * Credentials: records attached to a folder path, built from a template, whose secret fields are
 * sealed under the instance key. See `dev/specs/credentials.md` and `.claude/rules/credentials.md`.
 */

export const TEMPLATE_FIELD_TYPES = ['text', 'multiline', 'url', 'email', 'secret', 'totp'] as const
export type TemplateFieldType = (typeof TEMPLATE_FIELD_TYPES)[number]

export const MAX_TEMPLATE_FIELDS = 64
export const MAX_VALUE_BYTES = 16 * 1024
export const MAX_BLOB_BYTES = 64 * 1024

const SLUG = /^[A-Za-z0-9][A-Za-z0-9_-]*$/
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/

export interface TemplateField {
  id: string
  label: string
  type: TemplateFieldType
  required: boolean
  hint: string
}

export interface CredentialTemplate {
  id: string
  siteId: string
  key: string
  name: string
  icon: string | null
  fields: TemplateField[]
  createdAt: Date
  updatedAt: Date
}

export interface TemplateInput {
  key: string
  name: string
  icon?: string | null
  fields: TemplateField[]
}

/** Who is asking: the groups it speaks for, and the account behind it, if any. */
export interface CredentialRequester {
  actor: AccessActor
  userId: string | null
}

/** A credential as it is answered: metadata, and which secret fields hold a value. Never a secret. */
export interface CredentialView {
  id: string
  siteId: string
  path: string
  key: string
  templateId: string
  name: string
  tags: string[]
  fields: Record<string, string>
  secretFields: string[]
  secretsUpdatedAt: Date | null
  createdBy: string | null
  updatedBy: string | null
  createdAt: Date
  updatedAt: Date
}

export interface CredentialInput {
  path: string
  key: string
  /** A template's key, or its id. */
  template?: string
  name?: string
  tags?: string[]
  /** Non-secret values. Omitted is unchanged, `null` clears. */
  fields?: Record<string, string | null>
  /** Secret values. Omitted or `SENSITIVE_MASK` is unchanged, `null` clears, a string sets. */
  secrets?: Record<string, string | null>
}

export interface CredentialWriteResult {
  credential: CredentialView
  created: boolean
  previousPath: string | null
  /** Ids of the non-secret fields that changed, plus `name` and `tags` when they did. */
  changed: string[]
  secretsChanged: boolean
}

type Row = typeof credentialsTable.$inferSelect

const isSecretType = (type: string) => type === 'secret' || type === 'totp'

/** Whether a path is `base` or lies under it, as SQL. */
function atOrUnder(base: string) {
  return sql`(${credentialsTable.path} = ${base} OR starts_with(${credentialsTable.path}, ${base + '/'}))`
}

function cryptoFailure(err: unknown): never {
  if (err instanceof CredentialCryptoError) {
    if (err.code === 'keyMissing') {
      throw new CustomError(
        'credentialsKeyMissing',
        'No credentials key is configured, so secrets cannot be read or written.',
        503
      )
    }
    if (err.code === 'keyMismatch') {
      throw new CustomError(
        'credentialsKeyMismatch',
        'This credential was sealed under a key this instance does not have.',
        409
      )
    }
    throw new CustomError(
      'credentialsCorrupt',
      'The secrets of this credential cannot be opened.',
      500
    )
  }
  throw err
}

function isUniqueViolation(err: any): boolean {
  return (err.cause ?? err).code === '23505'
}

class Credentials {
  // == PERMISSIONS ==================

  /**
   * Whether a requester holds a credential permission at a path, asked in the site's primary locale.
   *
   * Never for a request acting as no account — a guest, or a system API key — regardless of what the
   * rules say: a credential's every act is attributable to somebody.
   */
  may(requester: CredentialRequester, permission: string, siteId: string, path: string): boolean {
    if (requester.userId === null) {
      return false
    }
    return WIKI.models.groups.checkAccess(requester.actor, permission, {
      siteId,
      path,
      locale: WIKI.sites[siteId]?.config?.locales?.primary
    })
  }

  // == TEMPLATES ====================

  async listTemplates(siteId: string): Promise<CredentialTemplate[]> {
    return (await WIKI.db
      .select()
      .from(templatesTable)
      .where(eq(templatesTable.siteId, siteId))
      .orderBy(asc(templatesTable.name))) as CredentialTemplate[]
  }

  async getTemplate(siteId: string, id: string): Promise<CredentialTemplate | null> {
    const [row] = await WIKI.db
      .select()
      .from(templatesTable)
      .where(and(eq(templatesTable.siteId, siteId), eq(templatesTable.id, id)))
    return (row as CredentialTemplate | undefined) ?? null
  }

  #validateTemplate(input: TemplateInput): TemplateInput {
    const bad = (message: string) => new CustomError('credentialTemplateInvalid', message, 400)
    if (!SLUG.test(input.key) || input.key.length > 64) {
      throw bad('A template key is a slug of letters, digits, hyphens and underscores, up to 64.')
    }
    if (!input.name.trim()) {
      throw bad('A template needs a name.')
    }
    if (input.fields.length > MAX_TEMPLATE_FIELDS) {
      throw bad(`A template has at most ${MAX_TEMPLATE_FIELDS} fields.`)
    }
    const seen = new Set<string>()
    for (const field of input.fields) {
      if (!SLUG.test(field.id) || field.id.length > 64) {
        throw bad(`"${field.id}" is not a valid field id.`)
      }
      if (seen.has(field.id)) {
        throw bad(`The field id "${field.id}" is used twice.`)
      }
      seen.add(field.id)
      if (!field.label.trim()) {
        throw bad(`The field "${field.id}" needs a label.`)
      }
    }
    return { ...input, name: input.name.trim() }
  }

  async createTemplate(siteId: string, input: TemplateInput): Promise<CredentialTemplate> {
    const valid = this.#validateTemplate(input)
    try {
      const [row] = await WIKI.db
        .insert(templatesTable)
        .values({
          siteId,
          key: valid.key,
          name: valid.name,
          icon: valid.icon ?? null,
          fields: valid.fields
        })
        .returning()
      return row as CredentialTemplate
    } catch (err: any) {
      if (isUniqueViolation(err)) {
        throw new CustomError('credentialTemplateKeyTaken', 'A template already has this key.', 409)
      }
      throw err
    }
  }

  async updateTemplate(
    siteId: string,
    id: string,
    input: TemplateInput
  ): Promise<CredentialTemplate | null> {
    const existing = await this.getTemplate(siteId, id)
    if (!existing) {
      return null
    }
    const valid = this.#validateTemplate(input)
    // -> A value lives in a different column on each side of the secret line, so a field holding
    //    values may not cross it: that is a migration of the template, not an edit
    for (const field of valid.fields) {
      const before = existing.fields.find((f) => f.id === field.id)
      if (!before || isSecretType(before.type) === isSecretType(field.type)) {
        continue
      }
      const [{ used }] = await WIKI.db
        .select({
          used: sql<number>`count(*)::int`
        })
        .from(credentialsTable)
        .where(
          and(
            eq(credentialsTable.templateId, id),
            isSecretType(before.type)
              ? sql`${field.id} = ANY(${credentialsTable.secretFields})`
              : sql`jsonb_exists(${credentialsTable.fields}, ${field.id})`
          )
        )
      if (used > 0) {
        throw new CustomError(
          'credentialTemplateTypeLocked',
          `The field "${field.id}" holds values, so it cannot change between secret and not secret.`,
          409
        )
      }
    }
    try {
      const [row] = await WIKI.db
        .update(templatesTable)
        .set({
          key: valid.key,
          name: valid.name,
          icon: valid.icon ?? null,
          fields: valid.fields,
          updatedAt: sql`now()`
        })
        .where(eq(templatesTable.id, id))
        .returning()
      return row as CredentialTemplate
    } catch (err: any) {
      if (isUniqueViolation(err)) {
        throw new CustomError('credentialTemplateKeyTaken', 'A template already has this key.', 409)
      }
      throw err
    }
  }

  async deleteTemplate(siteId: string, id: string): Promise<CredentialTemplate | null> {
    const existing = await this.getTemplate(siteId, id)
    if (!existing) {
      return null
    }
    const [{ used }] = await WIKI.db
      .select({ used: sql<number>`count(*)::int` })
      .from(credentialsTable)
      .where(eq(credentialsTable.templateId, id))
    if (used > 0) {
      throw new CustomError(
        'credentialTemplateInUse',
        `${used} credential(s) use this template.`,
        409
      )
    }
    await WIKI.db.delete(templatesTable).where(eq(templatesTable.id, id))
    return existing
  }

  // == READING ======================

  #view(row: Row, template: CredentialTemplate | undefined): CredentialView {
    // -> A field removed from the template keeps its stored value but is no longer shown
    const shown = new Set((template?.fields ?? []).map((f) => f.id))
    const fields: Record<string, string> = {}
    for (const [id, value] of Object.entries((row.fields ?? {}) as Record<string, string>)) {
      if (shown.has(id)) {
        fields[id] = value
      }
    }
    return {
      id: row.id,
      siteId: row.siteId,
      path: row.path,
      key: row.key,
      templateId: row.templateId,
      name: row.name,
      tags: row.tags,
      fields,
      secretFields: row.secretFields.filter((id) => shown.has(id)),
      secretsUpdatedAt: row.secretsUpdatedAt,
      createdBy: row.createdBy,
      updatedBy: row.updatedBy,
      createdAt: row.createdAt,
      updatedAt: row.updatedAt
    }
  }

  async #templateMap(siteId: string): Promise<Map<string, CredentialTemplate>> {
    return new Map((await this.listTemplates(siteId)).map((t) => [t.id, t]))
  }

  /**
   * The credentials at a path (and below it, when `recursive`) that the requester may read. With no
   * path, every one on the site that they may. A `query` (the search box's syntax) keeps those whose
   * `ts` matches it, best first: metadata only, since no secret is ever in `ts`.
   *
   * shortcut: filtered in memory after reading them all, resolving each distinct path once; page it
   * in SQL if a site ever holds many thousands.
   */
  async list(
    requester: CredentialRequester,
    siteId: string,
    options: { path?: string; recursive?: boolean; query?: string } = {}
  ): Promise<CredentialView[]> {
    if (requester.userId === null) {
      return []
    }
    const path = options.path === undefined ? undefined : pagePathToWrite(options.path)
    const tsQuery = options.query
      ? sql`to_tsquery('simple', ${toTsQueryText(options.query)})`
      : null
    const rows = await WIKI.db
      .select()
      .from(credentialsTable)
      .where(
        and(
          eq(credentialsTable.siteId, siteId),
          tsQuery ? sql`${credentialsTable.ts} @@ ${tsQuery}` : undefined,
          path === undefined
            ? undefined
            : options.recursive
              ? atOrUnder(path)
              : eq(credentialsTable.path, path)
        )
      )
      .orderBy(
        ...(tsQuery ? [desc(sql`ts_rank(${credentialsTable.ts}, ${tsQuery})`)] : []),
        asc(credentialsTable.path),
        asc(credentialsTable.name)
      )
    const templates = await this.#templateMap(siteId)
    const allowed = new Map<string, boolean>()
    return rows
      .filter((row) => {
        if (!allowed.has(row.path)) {
          allowed.set(row.path, this.may(requester, 'read:credentials', siteId, row.path))
        }
        return allowed.get(row.path)
      })
      .map((row) => this.#view(row, templates.get(row.templateId)))
  }

  async #row(siteId: string, id: string): Promise<Row | null> {
    const [row] = await WIKI.db
      .select()
      .from(credentialsTable)
      .where(and(eq(credentialsTable.siteId, siteId), eq(credentialsTable.id, id)))
    return row ?? null
  }

  /** One credential, or null when it does not exist or the requester may not read it. */
  async get(
    requester: CredentialRequester,
    siteId: string,
    id: string
  ): Promise<CredentialView | null> {
    const row = await this.#row(siteId, id)
    if (!row || !this.may(requester, 'read:credentials', siteId, row.path)) {
      return null
    }
    const template = await this.getTemplate(siteId, row.templateId)
    return this.#view(row, template ?? undefined)
  }

  /** One credential by its `(path, key)` handle, or null when it does not exist or may not be read. */
  async getByHandle(
    requester: CredentialRequester,
    siteId: string,
    path: string,
    key: string
  ): Promise<CredentialView | null> {
    const row = await this.#byHandle(siteId, pagePathToWrite(path), key)
    return row ? this.get(requester, siteId, row.id) : null
  }

  /** The credential an upsert would act on, whether or not the requester may read it. */
  async #byHandle(siteId: string, path: string, key: string): Promise<Row | null> {
    const [row] = await WIKI.db
      .select()
      .from(credentialsTable)
      .where(
        and(
          eq(credentialsTable.siteId, siteId),
          eq(credentialsTable.path, path),
          eq(credentialsTable.key, key)
        )
      )
    return row ?? null
  }

  // == WRITING ======================

  /** Create or update by `(path, key)`. */
  async upsert(
    requester: CredentialRequester,
    siteId: string,
    input: CredentialInput
  ): Promise<CredentialWriteResult> {
    const path = pagePathToWrite(input.path)
    const existing = await this.#byHandle(siteId, path, input.key)
    return this.#save(requester, siteId, existing, { ...input, path })
  }

  /** Update by id, a new `path` included. Null when it does not exist or may not be read. */
  async update(
    requester: CredentialRequester,
    siteId: string,
    id: string,
    input: Partial<CredentialInput>
  ): Promise<CredentialWriteResult | null> {
    const existing = await this.#row(siteId, id)
    if (!existing || !this.may(requester, 'read:credentials', siteId, existing.path)) {
      return null
    }
    const path =
      input.path === undefined ? existing.path : pagePathToWrite(input.path, existing.path)
    return this.#save(requester, siteId, existing, {
      ...input,
      path,
      key: input.key ?? existing.key
    })
  }

  async #save(
    requester: CredentialRequester,
    siteId: string,
    existing: Row | null,
    input: CredentialInput
  ): Promise<CredentialWriteResult> {
    const bad = (message: string) => new CustomError('credentialInvalid', message, 400)
    const deny = () =>
      new CustomError('credentialForbidden', 'You may not manage credentials here.', 403)

    if (!SLUG.test(input.key) || input.key.length > 128) {
      throw bad(
        'A credential key is a slug of letters, digits, hyphens and underscores, up to 128.'
      )
    }
    if (!this.may(requester, 'manage:credentials', siteId, input.path)) {
      throw deny()
    }
    if (existing && existing.path !== input.path) {
      if (!this.may(requester, 'manage:credentials', siteId, existing.path)) {
        throw deny()
      }
    }

    // -> The template: fixed once a credential exists, since its values are stored by that shape
    let template: CredentialTemplate | null
    if (existing) {
      template = await this.getTemplate(siteId, existing.templateId)
      if (input.template && input.template !== template?.key && input.template !== template?.id) {
        throw new CustomError(
          'credentialTemplateChange',
          'A credential keeps the template it was made from.',
          409
        )
      }
    } else {
      if (!input.template) {
        throw bad('A new credential needs a template.')
      }
      const templates = await this.listTemplates(siteId)
      template = templates.find((t) => t.key === input.template || t.id === input.template) ?? null
    }
    if (!template) {
      throw bad('This template does not exist.')
    }
    const fieldsById = new Map(template.fields.map((f) => [f.id, f]))

    const name = (input.name ?? existing?.name ?? '').trim()
    if (!name || name.length > 255) {
      throw bad('A credential needs a name of up to 255 characters.')
    }
    const tags = input.tags ?? existing?.tags ?? []

    // -> Validation against the template (spec 10.2)
    const checkValue = (id: string, value: unknown, secret: boolean) => {
      const field = fieldsById.get(id)
      if (!field) {
        throw bad(`"${id}" is not a field of this template.`)
      }
      if (isSecretType(field.type) !== secret) {
        throw bad(
          secret
            ? `"${id}" is not a secret field: send it in "fields".`
            : `"${id}" is a secret field: send it in "secrets".`
        )
      }
      if (value === null) {
        return
      }
      if (typeof value !== 'string') {
        throw bad(`The value of "${id}" must be text.`)
      }
      if (Buffer.byteLength(value, 'utf8') > MAX_VALUE_BYTES) {
        throw bad(`The value of "${id}" is over ${MAX_VALUE_BYTES / 1024} KB.`)
      }
      if (field.type === 'url') {
        try {
          const url = new URL(value)
          if (url.protocol !== 'http:' && url.protocol !== 'https:') {
            throw new Error('scheme')
          }
        } catch {
          throw bad(`"${id}" is not an http(s) URL.`)
        }
      }
      if (field.type === 'email' && !EMAIL.test(value)) {
        throw bad(`"${id}" is not an email address.`)
      }
    }

    const plain: Record<string, string> = {
      ...((existing?.fields ?? {}) as Record<string, string>)
    }
    const changed: string[] = []
    for (const [id, value] of Object.entries(input.fields ?? {})) {
      checkValue(id, value, false)
      if (value === null || value === '') {
        if (id in plain) {
          delete plain[id]
          changed.push(id)
        }
      } else if (plain[id] !== value) {
        plain[id] = value
        changed.push(id)
      }
    }
    if (name !== existing?.name) {
      changed.push('name')
    }
    if (JSON.stringify(tags) !== JSON.stringify(existing?.tags ?? [])) {
      changed.push('tags')
    }

    // -> Secret write semantics: omitted or the mask is unchanged, null clears, a string sets
    const secretWrites: Record<string, string | null> = {}
    for (const [id, value] of Object.entries(input.secrets ?? {})) {
      checkValue(id, value, true)
      if (value !== SENSITIVE_MASK) {
        secretWrites[id] = value === '' ? null : value
      }
    }
    // -> The values already held are only opened when something may change them, so a write that
    //    touches metadata alone needs no key
    const held = new Set(existing?.secretFields ?? [])
    const secretIds = Object.keys(secretWrites).filter(
      (fieldId) => secretWrites[fieldId] !== null || held.has(fieldId)
    )
    // -> Dropped on a save that re-seals anyway: values of fields the template no longer has
    const stale = [...held].filter((fieldId) => !fieldsById.has(fieldId))
    const id = existing?.id ?? uuid()
    let secrets: Buffer | null = existing?.secrets ?? null
    let keyId: string | null = existing?.keyId ?? null
    let secretFields = existing?.secretFields ?? []
    let secretsUpdatedAt = existing?.secretsUpdatedAt ?? null
    const changedSecrets: string[] = []

    if (secretIds.length > 0 || (stale.length > 0 && existing?.secrets)) {
      try {
        const values: Record<string, string> = existing?.secrets
          ? open(siteId, id, existing.secrets)
          : {}
        for (const [fieldId, value] of Object.entries(secretWrites)) {
          if (value === null ? fieldId in values : values[fieldId] !== value) {
            changedSecrets.push(fieldId)
            if (value === null) {
              delete values[fieldId]
            } else {
              values[fieldId] = value
            }
          }
        }
        const dropped = stale.filter((fieldId) => fieldId in values)
        for (const fieldId of dropped) {
          delete values[fieldId]
        }
        // -> Only on a change: an unchanged value is not sealed again under a fresh nonce
        if (changedSecrets.length > 0 || dropped.length > 0) {
          if (Object.keys(values).length === 0) {
            secrets = null
            keyId = null
          } else {
            secrets = seal(siteId, id, values)
            if (secrets.length > MAX_BLOB_BYTES) {
              throw bad(`The secrets of a credential are limited to ${MAX_BLOB_BYTES / 1024} KB.`)
            }
            keyId = keyIdOf(secrets)
          }
          secretFields = Object.keys(values)
          if (changedSecrets.length > 0) {
            secretsUpdatedAt = new Date()
          }
        }
      } catch (err) {
        cryptoFailure(err)
      }
    }
    if (!existing) {
      for (const field of template.fields) {
        const provided = isSecretType(field.type)
          ? secretFields.includes(field.id)
          : field.id in plain
        if (field.required && !provided) {
          throw bad(`The field "${field.id}" is required.`)
        }
      }
    } else {
      for (const field of template.fields) {
        const touched = isSecretType(field.type)
          ? changedSecrets.includes(field.id)
          : changed.includes(field.id)
        const provided = isSecretType(field.type)
          ? secretFields.includes(field.id)
          : field.id in plain
        if (field.required && touched && !provided) {
          throw bad(`The field "${field.id}" is required and cannot be cleared.`)
        }
      }
    }
    // -> Dropped on every save, as the non-secret half of the same cleanup
    for (const plainId of Object.keys(plain)) {
      if (!fieldsById.has(plainId)) {
        delete plain[plainId]
      }
    }

    // -> What the search index is built from: never a secret
    const searchText = [
      name,
      tags.join(' '),
      template.name,
      ...template.fields.filter((f) => !isSecretType(f.type)).map((f) => plain[f.id] ?? '')
    ].join(' ')
    const ts = sql`to_tsvector('simple', ${searchText})`

    const base = {
      path: input.path,
      name,
      tags,
      fields: plain,
      secrets,
      keyId,
      secretFields,
      secretsUpdatedAt,
      ts,
      updatedBy: requester.userId,
      updatedAt: sql`now()`
    }
    let row: Row
    try {
      if (existing) {
        ;[row] = await WIKI.db
          .update(credentialsTable)
          .set({ ...base, key: input.key })
          .where(eq(credentialsTable.id, existing.id))
          .returning()
      } else {
        ;[row] = await WIKI.db
          .insert(credentialsTable)
          .values({
            ...base,
            id,
            siteId,
            key: input.key,
            templateId: template.id,
            createdBy: requester.userId
          })
          .returning()
      }
    } catch (err: any) {
      if (isUniqueViolation(err)) {
        throw new CustomError(
          'credentialKeyTaken',
          'A credential with this key already exists at this path.',
          409
        )
      }
      throw err
    }
    return {
      credential: this.#view(row, template),
      created: !existing,
      previousPath: existing && existing.path !== input.path ? existing.path : null,
      changed: [...changed, ...changedSecrets],
      secretsChanged: changedSecrets.length > 0
    }
  }

  /** Delete one. Null when it does not exist or may not be read. */
  async delete(
    requester: CredentialRequester,
    siteId: string,
    id: string
  ): Promise<CredentialView | null> {
    const row = await this.#row(siteId, id)
    if (!row || !this.may(requester, 'read:credentials', siteId, row.path)) {
      return null
    }
    if (!this.may(requester, 'manage:credentials', siteId, row.path)) {
      throw new CustomError('credentialForbidden', 'You may not manage credentials here.', 403)
    }
    await WIKI.db.delete(credentialsTable).where(eq(credentialsTable.id, id))
    return this.#view(row, undefined)
  }

  // == REVEALING ====================

  /**
   * One secret field's value, or a TOTP field's current code. Null when the credential does not exist
   * or may not be read.
   */
  async reveal(
    requester: CredentialRequester,
    siteId: string,
    id: string,
    field: string
  ): Promise<{
    credential: CredentialView
    result: { value: string } | { code: string; expiresIn: number }
  } | null> {
    const row = await this.#row(siteId, id)
    if (!row || !this.may(requester, 'read:credentials', siteId, row.path)) {
      return null
    }
    if (!this.may(requester, 'reveal:credentials', siteId, row.path)) {
      throw new CustomError('credentialForbidden', 'You may not reveal credentials here.', 403)
    }
    const template = await this.getTemplate(siteId, row.templateId)
    const def = template?.fields.find((f) => f.id === field)
    if (!def || !isSecretType(def.type)) {
      throw new CustomError('credentialInvalid', `"${field}" is not a secret field.`, 400)
    }
    if (!row.secrets || !row.secretFields.includes(field)) {
      throw new CustomError('credentialFieldNotSet', 'This field holds no value.', 404)
    }
    let value: string | undefined
    try {
      value = open(siteId, row.id, row.secrets)[field]
    } catch (err) {
      cryptoFailure(err)
    }
    if (value === undefined) {
      throw new CustomError('credentialFieldNotSet', 'This field holds no value.', 404)
    }
    const credential = this.#view(row, template ?? undefined)
    if (def.type === 'totp') {
      try {
        return { credential, result: currentTotpCode(value) }
      } catch {
        throw new CustomError('credentialInvalidTotp', 'The stored TOTP secret is not valid.', 409)
      }
    }
    return { credential, result: { value } }
  }

  // == KEY STATE ====================

  /** Rows by the key that sealed them: how many are under the previous key, and under none we hold. */
  async keyCounts(): Promise<{ previous: number; unknown: number }> {
    const { keyId, previousKeyId } = keyState()
    const known = [keyId, previousKeyId].filter((id): id is string => id !== null)
    const count = async (where: ReturnType<typeof and>) => {
      const [row] = await WIKI.db
        .select({ n: sql<number>`count(*)::int` })
        .from(credentialsTable)
        .where(where)
      return row?.n ?? 0
    }
    return {
      previous: previousKeyId ? await count(eq(credentialsTable.keyId, previousKeyId)) : 0,
      unknown: await count(
        and(
          isNotNull(credentialsTable.keyId),
          known.length > 0 ? notInArray(credentialsTable.keyId, known) : undefined
        )
      )
    }
  }

  /** At boot: report rows sealed under a key this instance does not have. */
  async logKeyState(): Promise<void> {
    const { unknown } = await this.keyCounts()
    if (unknown > 0) {
      WIKI.logger.warn(
        `${unknown} credential(s) are sealed under a key this instance does not hold; they cannot be revealed.`
      )
    }
  }

  // == TREE =========================

  /** How many credentials sit at a folder path or below it. */
  async countUnder(siteId: string, path: string): Promise<number> {
    const [row] = await WIKI.db
      .select({ n: sql<number>`count(*)::int` })
      .from(credentialsTable)
      .where(and(eq(credentialsTable.siteId, siteId), atOrUnder(path)))
    return row?.n ?? 0
  }

  /** Follow a folder that moved: every credential at or under `from` goes to the same place under `to`. */
  async relocate(siteId: string, from: string, to: string): Promise<void> {
    await WIKI.db
      .update(credentialsTable)
      .set({ path: sql`${to} || substring(${credentialsTable.path} FROM ${from.length + 1})` })
      .where(and(eq(credentialsTable.siteId, siteId), atOrUnder(from)))
  }

  /**
   * Refuse a folder move that would put a credential where one with the same key already is. Asked
   * before anything moves, so a refusal leaves nothing half-applied.
   *
   * @throws 409 `credentialPathConflict`
   */
  async assertRelocatable(siteId: string, from: string, to: string): Promise<void> {
    const moving = alias(credentialsTable, 'moving')
    const [clash] = await WIKI.db
      .select({ path: credentialsTable.path, key: credentialsTable.key })
      .from(moving)
      .innerJoin(
        credentialsTable,
        and(
          eq(credentialsTable.siteId, moving.siteId),
          eq(credentialsTable.key, moving.key),
          sql`${credentialsTable.path} = ${to} || substring(${moving.path} FROM ${from.length + 1})`
        )
      )
      .where(
        and(
          eq(moving.siteId, siteId),
          sql`(${moving.path} = ${from} OR starts_with(${moving.path}, ${from + '/'}))`
        )
      )
      .limit(1)
    if (clash) {
      throw new CustomError(
        'credentialPathConflict',
        `Moving this folder would put a credential on "${clash.path}" with the key "${clash.key}", which another credential already has.`,
        409
      )
    }
  }

  /** A folder was deleted: so are the credentials at or under it. */
  async deleteUnder(siteId: string, path: string): Promise<number> {
    const rows = await WIKI.db
      .delete(credentialsTable)
      .where(and(eq(credentialsTable.siteId, siteId), atOrUnder(path)))
      .returning({ id: credentialsTable.id })
    return rows.length
  }
}

export const credentials = new Credentials()
