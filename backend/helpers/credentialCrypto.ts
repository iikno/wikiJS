import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto'

/**
 * The seal on a credential's secret fields. See `dev/specs/credentials.md` §4 and §5.3.
 *
 * Nothing else touches `node:crypto` for this feature, and nothing else holds the key: it is read from
 * `WIKI_CREDENTIALS_KEY` once, into a `Buffer` kept in this module, and is never logged, published or
 * returned. `WIKI_CREDENTIALS_KEY_PREVIOUS` is read too and only ever used to open.
 *
 * The blob is `"WKC1" | keyId (8) | nonce (12) | ciphertext | GCM tag (16)`. The AAD binds it to its
 * site and its row, so a blob copied under another credential's id fails to open; the path is not in
 * it, so a folder move re-encrypts nothing.
 */

const MAGIC = Buffer.from('WKC1', 'ascii')
const KEY_ID_LENGTH = 8
const NONCE_LENGTH = 12
const TAG_LENGTH = 16
const HEADER_LENGTH = MAGIC.length + KEY_ID_LENGTH + NONCE_LENGTH
const KEY_LENGTH = 32

/** Why a blob could not be sealed or opened. `code` is what the caller maps to a status. */
export class CredentialCryptoError extends Error {
  code: 'keyMissing' | 'keyMismatch' | 'corrupt'

  constructor(code: CredentialCryptoError['code'], message: string) {
    super(message)
    this.name = 'CredentialCryptoError'
    this.code = code
  }
}

interface Key {
  key: Buffer
  /** First 8 bytes of SHA-256 of the key. */
  id: Buffer
}

let current: Key | null = null
let previous: Key | null = null
let invalid = false

function log(level: 'error' | 'warn', message: string): void {
  // -> Absent when the test script loads this on its own
  if (typeof WIKI !== 'undefined' && WIKI.logger) {
    WIKI.logger[level](message)
  }
}

/** A key from its base64 form, or null when it is absent or is not exactly 32 bytes. */
function parseKey(name: string, raw: string | undefined): Key | null | undefined {
  if (!raw) {
    return undefined
  }
  const text = raw.trim()
  const key = /^[A-Za-z0-9+/]+={0,2}$/.test(text) ? Buffer.from(text, 'base64') : Buffer.alloc(0)
  if (key.length !== KEY_LENGTH) {
    log('error', `${name} is not base64 for exactly ${KEY_LENGTH} bytes. Ignoring it.`)
    return null
  }
  return { key, id: createHash('sha256').update(key).digest().subarray(0, KEY_ID_LENGTH) }
}

/**
 * Read the keys from the environment. Runs once when this module loads; it takes the environment as
 * an argument so that the test can stand in for one.
 */
export function loadCredentialKeys(env: Record<string, string | undefined> = process.env): void {
  const parsedCurrent = parseKey('WIKI_CREDENTIALS_KEY', env.WIKI_CREDENTIALS_KEY)
  const parsedPrevious = parseKey(
    'WIKI_CREDENTIALS_KEY_PREVIOUS',
    env.WIKI_CREDENTIALS_KEY_PREVIOUS
  )
  // -> An invalid key behaves as a missing one
  invalid = parsedCurrent === null
  current = parsedCurrent ?? null
  previous = parsedPrevious ?? null
}

loadCredentialKeys()

/** What the admin screen shows: whether the feature can seal and open, and which keys, by id. */
export function keyState(): {
  state: 'ok' | 'missing' | 'invalid'
  keyId: string | null
  previousKeyId: string | null
} {
  return {
    state: current ? 'ok' : invalid ? 'invalid' : 'missing',
    keyId: current?.id.toString('hex') ?? null,
    previousKeyId: previous?.id.toString('hex') ?? null
  }
}

function aad(siteId: string, id: string): Buffer {
  return Buffer.from(`${siteId}|${id}|secrets`, 'utf8')
}

/** Seal `{ fieldId: value }` under the current key. */
export function seal(siteId: string, id: string, values: Record<string, string>): Buffer {
  if (!current) {
    throw new CredentialCryptoError('keyMissing', 'WIKI_CREDENTIALS_KEY is not set.')
  }
  const nonce = randomBytes(NONCE_LENGTH)
  const cipher = createCipheriv('aes-256-gcm', current.key, nonce, { authTagLength: TAG_LENGTH })
  cipher.setAAD(aad(siteId, id))
  const ciphertext = Buffer.concat([cipher.update(JSON.stringify(values), 'utf8'), cipher.final()])
  return Buffer.concat([MAGIC, current.id, nonce, ciphertext, cipher.getAuthTag()])
}

/** The id, in hex, of the key that sealed a blob. */
export function keyIdOf(blob: Buffer): string {
  if (blob.length < HEADER_LENGTH + TAG_LENGTH || !blob.subarray(0, MAGIC.length).equals(MAGIC)) {
    throw new CredentialCryptoError('corrupt', 'Not a sealed credential.')
  }
  return blob.subarray(MAGIC.length, MAGIC.length + KEY_ID_LENGTH).toString('hex')
}

/**
 * Open a blob with the current key or, failing that, the previous one.
 *
 * @throws `keyMissing` with no key configured, `keyMismatch` when neither key's id is the blob's, and
 *   `corrupt` for a blob that is truncated, was sealed for another row, or has been altered
 */
export function open(siteId: string, id: string, blob: Buffer): Record<string, string> {
  const blobKeyId = keyIdOf(blob)
  if (!current) {
    throw new CredentialCryptoError('keyMissing', 'WIKI_CREDENTIALS_KEY is not set.')
  }
  const key = [current, previous].find((candidate) => candidate?.id.toString('hex') === blobKeyId)
  if (!key) {
    throw new CredentialCryptoError('keyMismatch', 'This credential was sealed under another key.')
  }
  const nonce = blob.subarray(MAGIC.length + KEY_ID_LENGTH, HEADER_LENGTH)
  const ciphertext = blob.subarray(HEADER_LENGTH, blob.length - TAG_LENGTH)
  try {
    const decipher = createDecipheriv('aes-256-gcm', key.key, nonce, { authTagLength: TAG_LENGTH })
    decipher.setAAD(aad(siteId, id))
    decipher.setAuthTag(blob.subarray(blob.length - TAG_LENGTH))
    const plain = Buffer.concat([decipher.update(ciphertext), decipher.final()])
    return JSON.parse(plain.toString('utf8'))
  } catch {
    throw new CredentialCryptoError('corrupt', 'The sealed credential could not be opened.')
  }
}
