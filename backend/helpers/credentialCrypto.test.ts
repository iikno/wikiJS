import assert from 'node:assert/strict'
import { randomBytes } from 'node:crypto'
import { test } from 'node:test'
import {
  CredentialCryptoError,
  keyIdOf,
  keyState,
  loadCredentialKeys,
  open,
  seal
} from './credentialCrypto.ts'

const keyA = randomBytes(32).toString('base64')
const keyB = randomBytes(32).toString('base64')
const siteId = 'site-1'
const id = 'cred-1'
const values = { password: 'hunter2', apiKey: 'k-123' }

function codeOf(fn: () => unknown): string | undefined {
  try {
    fn()
  } catch (err) {
    return err instanceof CredentialCryptoError ? err.code : 'other'
  }
  return undefined
}

test('round trip', () => {
  loadCredentialKeys({ WIKI_CREDENTIALS_KEY: keyA })
  const blob = seal(siteId, id, values)
  assert.equal(blob.subarray(0, 4).toString(), 'WKC1')
  assert.equal(keyIdOf(blob), keyState().keyId)
  assert.deepEqual(open(siteId, id, blob), values)
})

test('wrong AAD fails', () => {
  loadCredentialKeys({ WIKI_CREDENTIALS_KEY: keyA })
  const blob = seal(siteId, id, values)
  assert.equal(
    codeOf(() => open(siteId, 'cred-2', blob)),
    'corrupt'
  )
  assert.equal(
    codeOf(() => open('site-2', id, blob)),
    'corrupt'
  )
})

test('wrong key fails, and the previous key opens', () => {
  loadCredentialKeys({ WIKI_CREDENTIALS_KEY: keyA })
  const blob = seal(siteId, id, values)
  loadCredentialKeys({ WIKI_CREDENTIALS_KEY: keyB })
  assert.equal(
    codeOf(() => open(siteId, id, blob)),
    'keyMismatch'
  )
  loadCredentialKeys({ WIKI_CREDENTIALS_KEY: keyB, WIKI_CREDENTIALS_KEY_PREVIOUS: keyA })
  assert.deepEqual(open(siteId, id, blob), values)
})

test('truncated or altered blob fails', () => {
  loadCredentialKeys({ WIKI_CREDENTIALS_KEY: keyA })
  const blob = seal(siteId, id, values)
  assert.equal(
    codeOf(() => open(siteId, id, blob.subarray(0, blob.length - 1))),
    'corrupt'
  )
  assert.equal(
    codeOf(() => open(siteId, id, blob.subarray(0, 10))),
    'corrupt'
  )
  const altered = Buffer.from(blob)
  altered[altered.length - 20] ^= 1
  assert.equal(
    codeOf(() => open(siteId, id, altered)),
    'corrupt'
  )
})

test('a key that is not 32 bytes behaves as missing', () => {
  loadCredentialKeys({ WIKI_CREDENTIALS_KEY: randomBytes(16).toString('base64') })
  assert.equal(keyState().state, 'invalid')
  assert.equal(
    codeOf(() => seal(siteId, id, values)),
    'keyMissing'
  )
})
