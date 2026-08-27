import assert from 'node:assert/strict'
import { afterEach, beforeEach, describe, it } from 'node:test'
import { ZodError } from 'zod'
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
  it('validates issuer URLs', () => {
    const cases: [string | undefined, string, boolean][] = [
      [undefined, 'https://auth.example.com', true],
      [undefined, 'https://auth.example.com/tenant-a', true],
      [undefined, 'http://auth.example.com', false],
      ['', 'http://auth.example.com', false],
      ['false', 'http://auth.example.com', false],
      ['true', 'http://localhost:8080', true],
      ['TRUE', 'http://localhost:8080/authz', true],
      ['true', 'ftp://auth.example.com', false],
      [undefined, 'https://auth.example.com?tenant=1', false],
      [undefined, 'https://auth.example.com?', false],
      [undefined, 'https://auth.example.com#section', false],
      [undefined, 'https://auth.example.com#', false],
      ['true', 'http://localhost:8080?tenant=1', false],
      ['true', 'http://localhost:8080#section', false],
    ]

    for (const [httpAllowed, issuer, accepted] of cases) {
      if (httpAllowed === undefined) delete process.env[HTTP_ALLOWED_ENV]
      else process.env[HTTP_ALLOWED_ENV] = httpAllowed

      const parse = () => AuthorizationServerIssuer(issuer)
      if (accepted) assert.equal(parse(), issuer, issuer)
      else assert.throws(parse, issuer)
    }
  })

  it('reports malformed URLs as validation failures', () => {
    assert.throws(() => AuthorizationServerIssuer('not a url'), ZodError)
    assert.equal(AuthorizationServerIssuer.schema.safeParse('not a url').success, false)
  })
})
