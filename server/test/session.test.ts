import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'
import crypto from 'node:crypto'
import Fastify from 'fastify'
import cookie from '@fastify/cookie'

test('password sessions expire after 30 idle minutes and renew with their cookies', async (t) => {
  const directory = await mkdtemp(path.join(tmpdir(), 'wealth-session-test-'))
  process.env.SQLITE_DB_PATH = path.join(directory, 'test.sqlite')
  process.env.ALLOW_PASSWORD = 'true'
  const { sequelize } = await import('../src/models')
  const { default: Session } = await import('../src/models/session')
  const { default: routes } = await import('../src/routes/password')
  const { default: auth } = await import('../src/middleware/auth')
  sequelize.options.logging = false
  await sequelize.sync()

  const app = Fastify()
  await app.register(cookie)
  await app.register(auth)
  routes.forEach((route: any) => app.route(route))
  app.get('/api/protected', async () => ({ success: true }))
  app.get('/api/heart', async () => ({ success: true }))
  app.get('/api/user-settings', async () => ({}))
  await app.ready()
  t.after(async () => {
    await app.close()
    await sequelize.close()
  })

  let now = Date.now()
  t.mock.method(Date, 'now', () => now)
  const minute = 60 * 1000
  const password = crypto.randomBytes(24).toString('hex')
  const sessionCookie = (response: any) => {
    const header = response.headers['set-cookie'] as string
    assert.match(header, /Max-Age=1800/)
    assert.match(header, /HttpOnly/)
    assert.match(header, /SameSite=Strict/)
    assert.match(header, /Path=\//)
    return header.split(';')[0]
  }
  const expiresAt = async (value: string) => {
    const session = await Session.findByPk(value.split('=')[1])
    assert.ok(session)
    return session.expiresAt.getTime()
  }
  const login = async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/api/password/verify',
      payload: { password },
    })
    assert.equal(response.statusCode, 200, response.body)
    return sessionCookie(response)
  }

  await t.test('setting a password creates a 30-minute session', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/api/password/set',
      payload: { password },
    })
    assert.equal(response.statusCode, 200, response.body)
    assert.equal(await expiresAt(sessionCookie(response)), now + 30 * minute)
  })

  await t.test('activity extends both deadlines beyond the original login lifetime', async () => {
    const value = await login()
    for (let i = 0; i < 2; i++) {
      now += 20 * minute
      const response = await app.inject({ url: '/api/protected', headers: { cookie: value } })
      assert.equal(response.statusCode, 200, response.body)
      assert.equal(sessionCookie(response), value)
      assert.equal(await expiresAt(value), now + 30 * minute)
    }

    now += 30 * minute
    const response = await app.inject({ url: '/api/protected', headers: { cookie: value } })
    assert.equal(response.statusCode, 401)
    assert.equal(response.headers['set-cookie'], undefined)
    assert.equal(await Session.findByPk(value.split('=')[1]), null)
    const check = await app.inject({ url: '/api/password/check', headers: { cookie: value } })
    assert.equal(check.json().needPassword, true)
    assert.equal(check.headers['set-cookie'], undefined)
  })

  await t.test('checking auth on page reload also renews the session', async () => {
    const value = await login()
    now += 29 * minute
    const response = await app.inject({ url: '/api/password/check', headers: { cookie: value } })
    assert.equal(response.json().needPassword, false)
    assert.equal(sessionCookie(response), value)
    assert.equal(await expiresAt(value), now + 30 * minute)
  })

  await t.test('public requests do not extend the idle timeout', async () => {
    const value = await login()
    const deadline = await expiresAt(value)
    now += 20 * minute
    for (const url of ['/api/heart', '/api/user-settings']) {
      const response = await app.inject({ url, headers: { cookie: value } })
      assert.equal(response.statusCode, 200)
      assert.equal(response.headers['set-cookie'], undefined)
      assert.equal(await expiresAt(value), deadline)
    }
    now += 11 * minute
    const response = await app.inject({ url: '/api/password/check', headers: { cookie: value } })
    assert.equal(response.json().needPassword, true)
    assert.equal(response.headers['set-cookie'], undefined)
  })

  await t.test('invalid sessions stay unauthorized', async () => {
    for (const headers of [{}, { cookie: 'sessionId=unknown' }]) {
      const response = await app.inject({ url: '/api/protected', headers })
      assert.equal(response.statusCode, 401)
      assert.equal(response.headers['set-cookie'], undefined)
    }
  })

  await t.test('HTTPS cookies retain Secure when renewed', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/api/password/verify',
      headers: { 'x-forwarded-proto': 'https' },
      payload: { password },
    })
    assert.equal(response.statusCode, 200, response.body)
    assert.match(response.headers['set-cookie'] as string, /; Secure/)
    const renewed = await app.inject({
      url: '/api/protected',
      headers: { cookie: sessionCookie(response), 'x-forwarded-proto': 'https' },
    })
    assert.equal(renewed.statusCode, 200)
    sessionCookie(renewed)
    assert.match(renewed.headers['set-cookie'] as string, /; Secure/)
  })
})
