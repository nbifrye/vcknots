import assert from 'node:assert/strict'
import { afterEach, beforeEach, describe, it } from 'node:test'
import { AuthorizationServerIssuer } from '../src/authorization-server.types'

const HTTP_ALLOWED_ENV = 'VCKNOTS_AUTHZ_HTTP_ALLOWED'
const originalHttpAllowed = process.env[HTTP_ALLOWED_ENV]

beforeEach(() => {
  delete process.env[HTTP_ALLOWED_ENV]
})

afterEach(() => {
  if (originalHttpAllowed === undefined) {
    delete process.env[HTTP_ALLOWED_ENV]
  } else {
    process.env[HTTP_ALLOWED_ENV] = originalHttpAllowed
  }
})

describe('AuthorizationServerIssuer', () => {
  it('accepts https issuers with or without a path', () => {
    assert.equal(AuthorizationServerIssuer('https://auth.example.com'), 'https://auth.example.com')
    assert.equal(
      AuthorizationServerIssuer('https://auth.example.com/tenant-a'),
      'https://auth.example.com/tenant-a'
    )
  })

  it('rejects http issuers by default', () => {
    assert.throws(() => AuthorizationServerIssuer('http://auth.example.com'))

    process.env[HTTP_ALLOWED_ENV] = ''
    assert.throws(() => AuthorizationServerIssuer('http://auth.example.com'))

    process.env[HTTP_ALLOWED_ENV] = 'false'
    assert.throws(() => AuthorizationServerIssuer('http://auth.example.com'))
  })

  it('accepts http issuers when explicitly allowed', () => {
    process.env[HTTP_ALLOWED_ENV] = 'true'
    assert.equal(AuthorizationServerIssuer('http://localhost:8080'), 'http://localhost:8080')

    process.env[HTTP_ALLOWED_ENV] = 'TRUE'
    assert.equal(
      AuthorizationServerIssuer('http://localhost:8080/authz'),
      'http://localhost:8080/authz'
    )
  })

  it('rejects non-http schemes even when http is allowed', () => {
    process.env[HTTP_ALLOWED_ENV] = 'true'

    assert.throws(() => AuthorizationServerIssuer('ftp://auth.example.com'))
  })

  it('rejects query and fragment components', () => {
    for (const issuer of [
      'https://auth.example.com?tenant=1',
      'https://auth.example.com?',
      'https://auth.example.com#section',
      'https://auth.example.com#',
    ]) {
      assert.throws(() => AuthorizationServerIssuer(issuer))
    }

    process.env[HTTP_ALLOWED_ENV] = 'true'
    assert.throws(() => AuthorizationServerIssuer('http://localhost:8080?tenant=1'))
    assert.throws(() => AuthorizationServerIssuer('http://localhost:8080#section'))
  })
})
