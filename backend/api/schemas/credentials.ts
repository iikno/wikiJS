import {
  MAX_TEMPLATE_FIELDS,
  MAX_VALUE_BYTES,
  TEMPLATE_FIELD_TYPES
} from '../../models/credentials.ts'
import type { FastifyInstance } from 'fastify'

const dateTime = { type: 'string', format: 'date-time' }

/** A template's field, as it is sent and answered. */
const templateField = {
  type: 'object',
  properties: {
    id: { type: 'string', minLength: 1, maxLength: 64 },
    label: { type: 'string', minLength: 1, maxLength: 255 },
    type: { type: 'string', enum: TEMPLATE_FIELD_TYPES },
    required: { type: 'boolean', default: false },
    hint: { type: 'string', maxLength: 1000, default: '' }
  },
  required: ['id', 'label', 'type']
}

/** The properties of a template a create or a save carries. */
export const TEMPLATE_INPUT_PROPERTIES = {
  key: { type: 'string', minLength: 1, maxLength: 64 },
  name: { type: 'string', minLength: 1, maxLength: 255 },
  icon: { type: ['string', 'null'], maxLength: 255 },
  fields: { type: 'array', maxItems: MAX_TEMPLATE_FIELDS, items: templateField }
}

const valueMap = (description: string) => ({
  type: 'object',
  description,
  additionalProperties: { type: ['string', 'null'], maxLength: MAX_VALUE_BYTES }
})

/** The properties of a credential a write carries. */
export const CREDENTIAL_INPUT_PROPERTIES = {
  name: { type: 'string', minLength: 1, maxLength: 255 },
  tags: { type: 'array', maxItems: 50, items: { type: 'string', minLength: 1, maxLength: 64 } },
  fields: valueMap(
    'Values of the template’s fields that are not secret. A field left out is unchanged, `null` clears it.'
  ),
  secrets: valueMap(
    'Values of the template’s secret and TOTP fields. A field left out, or sent as the mask `••••••••`, is unchanged; `null` clears it; a string sets it. Never answered by any route except `reveal`.'
  )
}

export async function registerSchemas(app: FastifyInstance): Promise<void> {
  app.addSchema({
    $id: 'CredentialTemplate',
    type: 'object',
    properties: {
      id: { type: 'string', format: 'uuid' },
      siteId: { type: 'string', format: 'uuid' },
      ...TEMPLATE_INPUT_PROPERTIES,
      createdAt: dateTime,
      updatedAt: dateTime
    }
  })

  /**
   * CREDENTIAL - Metadata only, and which secret fields hold a value
   */
  app.addSchema({
    $id: 'Credential',
    type: 'object',
    properties: {
      id: { type: 'string', format: 'uuid' },
      siteId: { type: 'string', format: 'uuid' },
      path: { type: 'string' },
      key: { type: 'string' },
      templateId: { type: 'string', format: 'uuid' },
      name: { type: 'string' },
      tags: { type: 'array', items: { type: 'string' } },
      fields: { type: 'object', additionalProperties: { type: 'string' } },
      secretFields: {
        type: 'array',
        items: { type: 'string' },
        description: 'Ids of the secret fields that hold a value. The values are never listed.'
      },
      secretsUpdatedAt: { ...dateTime, type: ['string', 'null'] },
      createdBy: { type: ['string', 'null'], format: 'uuid' },
      updatedBy: { type: ['string', 'null'], format: 'uuid' },
      createdAt: dateTime,
      updatedAt: dateTime
    }
  })
}
