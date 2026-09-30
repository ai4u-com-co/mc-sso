import { existsSync } from "node:fs"
import { resolve } from "node:path"
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest"
import { createMcToken } from "../src/token"
import { createSession, verifySession } from "../src/session"
import {
  MC_SESSION_COOKIE,
  DEFAULT_SESSION_TTL_MS,
  createMcAuthHandler,
  readMcSession,
  mcSessionGuard,
} from "../src/index"

// Valores construidos en runtime (gitleaks): nunca un literal con forma de secreto.
const SECRET  = ["test", "mc", "handler", String(Date.now())].join("-")
const SERVICE = "kpis"
const TENANT  = "flexoimpresos"
const ORIGIN  = "https://app.example.test"

function postToken(token: string | null, path = "/api/mc-auth"): Request {
  const body = new URLSearchParams()
  if (token !== null) body.set("token", token)
  return new Request(`${ORIGIN}${path}`, { method: "POST", body })
}

function cookieValue(setCookie: string): string {
  return setCookie.split(";")[0].split("=").slice(1).join("=")
}

function validToken(serviceId = SERVICE): string {
  return createMcToken(TENANT, serviceId, "Ana Pérez", SECRET, {
    userId: "u-1",
    roles: ["admin"],
    allowedModules: ["ventas", "finanzas"],
  })
}

describe("createMcAuthHandler", () => {
  beforeEach(() => {
    vi.useFakeTimers()
    vi.setSystemTime(new Date("2026-01-01T00:00:00Z"))
  })
  afterEach(() => { vi.useRealTimers() })

  it("constantes: cookie mc_session y TTL 8 h", () => {
    expect(MC_SESSION_COOKIE).toBe("mc_session")
    expect(DEFAULT_SESSION_TTL_MS).toBe(8 * 60 * 60 * 1000)
  })

  it("token válido ⇒ 303 a / + cookie HttpOnly/Lax/Path=/ con Max-Age 8 h y campos copiados", async () => {
    const POST = createMcAuthHandler({ serviceId: SERVICE, getSecret: () => SECRET })
    const res  = await POST(postToken(validToken()))

    expect(res.status).toBe(303)
    expect(res.headers.get("location")).toBe(`${ORIGIN}/`)
    const setCookie = res.headers.get("set-cookie")!
    expect(setCookie).toMatch(/^mc_session=/)
    expect(setCookie).toContain("Max-Age=28800")
    expect(setCookie).toContain("HttpOnly")
    expect(setCookie).toContain("SameSite=Lax")
    expect(setCookie).toContain("Path=/")
    expect(setCookie).not.toContain("Secure") // NODE_ENV=test

    const session = verifySession(cookieValue(setCookie), SECRET)!
    expect(session).toMatchObject({
      tenantId: TENANT,
      userId: "u-1",
      roles: ["admin"],
      allowedModules: ["ventas", "finanzas"],
      displayName: "Ana Pérez",
    })
    expect(session.exp - session.iat).toBe(DEFAULT_SESSION_TTL_MS)
  })

  it("secure: true fuerza el flag Secure; ttlMs y cookieName custom", async () => {
    const POST = createMcAuthHandler({
      serviceId: SERVICE, secret: SECRET, secure: true, ttlMs: 60 * 60 * 1000, cookieName: "otra",
    })
    const setCookie = (await POST(postToken(validToken()))).headers.get("set-cookie")!
    expect(setCookie).toMatch(/^otra=/)
    expect(setCookie).toContain("Max-Age=3600")
    expect(setCookie).toContain("Secure")
  })

  it("Secure por defecto en NODE_ENV=production", async () => {
    vi.stubEnv("NODE_ENV", "production")
    try {
      const POST = createMcAuthHandler({ serviceId: SERVICE, secret: SECRET })
      expect((await POST(postToken(validToken()))).headers.get("set-cookie")).toContain("Secure")
    } finally { vi.unstubAllEnvs() }
  })

  it("token inválido ⇒ 401 genérico, sin cookie", async () => {
    const onError = vi.fn()
    const POST = createMcAuthHandler({ serviceId: SERVICE, secret: SECRET, onError })
    const res  = await POST(postToken(validToken() + "x"))
    expect(res.status).toBe(401)
    expect(res.headers.get("set-cookie")).toBeNull()
    expect(await res.json()).toEqual({ error: "Token inválido o expirado" })
    expect(onError).toHaveBeenCalledWith({ reason: "invalid_token", serviceId: SERVICE })
  })

  it("token ausente o body no-form ⇒ 401", async () => {
    const POST = createMcAuthHandler({ serviceId: SERVICE, secret: SECRET })
    expect((await POST(postToken(null))).status).toBe(401)
    const json = new Request(`${ORIGIN}/api/mc-auth`, {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ token: validToken() }),
    })
    expect((await POST(json)).status).toBe(401)
  })

  it("token vencido ⇒ 401", async () => {
    const token = validToken()
    vi.advanceTimersByTime(5 * 60 * 1000 + 1)
    const POST = createMcAuthHandler({ serviceId: SERVICE, secret: SECRET })
    expect((await POST(postToken(token))).status).toBe(401)
  })

  it("serviceId distinto ⇒ 401", async () => {
    const POST = createMcAuthHandler({ serviceId: SERVICE, secret: SECRET })
    expect((await POST(postToken(validToken("otroservicio")))).status).toBe(401)
  })

  it("firmado con otro secreto ⇒ 401", async () => {
    const POST  = createMcAuthHandler({ serviceId: SERVICE, secret: SECRET })
    const other = createMcToken(TENANT, SERVICE, "x", SECRET + "-otro")
    expect((await POST(postToken(other))).status).toBe(401)
  })

  it("secreto ausente ⇒ 500 genérico que no filtra nada", async () => {
    const onError = vi.fn()
    for (const opts of [
      { serviceId: SERVICE, onError },
      { serviceId: SERVICE, secret: "", onError },
      { serviceId: SERVICE, getSecret: () => undefined, onError },
      { serviceId: SERVICE, getSecret: (): string => { throw new Error("boom") }, onError },
    ]) {
      const res = await createMcAuthHandler(opts)(postToken(validToken()))
      expect(res.status).toBe(500)
      expect(res.headers.get("set-cookie")).toBeNull()
      expect(await res.json()).toEqual({ error: "Configuración de servidor incompleta" })
    }
    expect(onError).toHaveBeenCalledTimes(4)
    expect(onError.mock.calls[0][0]).toMatchObject({ reason: "missing_secret", serviceId: SERVICE })
  })

  it("onError que lanza no rompe la respuesta", async () => {
    const POST = createMcAuthHandler({ serviceId: SERVICE, onError: () => { throw new Error("x") } })
    expect((await POST(postToken(validToken()))).status).toBe(500)
  })

  it("redirectTo string y función (recibe el payload)", async () => {
    const a = createMcAuthHandler({ serviceId: SERVICE, secret: SECRET, redirectTo: "/admin/links" })
    expect((await a(postToken(validToken()))).headers.get("location")).toBe(`${ORIGIN}/admin/links`)

    const fn = vi.fn((p: { tenantId: string }) => `/t/${p.tenantId}`)
    const b  = createMcAuthHandler({ serviceId: SERVICE, secret: SECRET, redirectTo: fn })
    expect((await b(postToken(validToken()))).headers.get("location")).toBe(`${ORIGIN}/t/${TENANT}`)
    expect(fn.mock.calls[0][0]).toMatchObject({ tenantId: TENANT, serviceId: SERVICE })
  })

  it("redirectTo a otro origen cae a / (sin open redirect)", async () => {
    const POST = createMcAuthHandler({ serviceId: SERVICE, secret: SECRET, redirectTo: "https://evil.example/" })
    expect((await POST(postToken(validToken()))).headers.get("location")).toBe(`${ORIGIN}/`)
  })

  it("configuración inválida falla al construir", () => {
    expect(() => createMcAuthHandler({ serviceId: "" })).toThrow(TypeError)
    expect(() => createMcAuthHandler({ serviceId: SERVICE, ttlMs: 0 })).toThrow(TypeError)
  })
})

describe("readMcSession", () => {
  it("lee desde Request o desde el header Cookie", () => {
    const token = createSession(TENANT, SECRET, undefined, { userId: "u-1" })
    const cookie = `foo=bar; ${MC_SESSION_COOKIE}=${token}; baz=1`
    const req = new Request(ORIGIN, { headers: { cookie } })
    expect(readMcSession(req, SECRET)?.userId).toBe("u-1")
    expect(readMcSession(cookie, SECRET)?.tenantId).toBe(TENANT)
  })

  it("null si no hay cookie, secreto vacío, firma mala, vencida o nombre distinto", () => {
    const token = createSession(TENANT, SECRET, 1000)
    expect(readMcSession(null, SECRET)).toBeNull()
    expect(readMcSession(`${MC_SESSION_COOKIE}=${token}`, "")).toBeNull()
    expect(readMcSession(`${MC_SESSION_COOKIE}=${token}`, SECRET + "x")).toBeNull()
    expect(readMcSession(`otra=${token}`, SECRET)).toBeNull()
    expect(readMcSession(`otra=${token}`, SECRET, "otra")).not.toBeNull()
    vi.useFakeTimers()
    vi.setSystemTime(Date.now() + 2000)
    expect(readMcSession(`${MC_SESSION_COOKIE}=${token}`, SECRET)).toBeNull()
    vi.useRealTimers()
  })
})

describe("mcSessionGuard", () => {
  const withSession = (path: string) =>
    new Request(`${ORIGIN}${path}`, { headers: { cookie: `${MC_SESSION_COOKIE}=${createSession(TENANT, SECRET)}` } })
  const anon = (path: string) => new Request(`${ORIGIN}${path}`)

  it("deja pasar con sesión válida y en rutas públicas (incluida /api/mc-auth siempre)", () => {
    const guard = mcSessionGuard({ secret: SECRET, publicPaths: ["/health", /^\/_next\//] })
    expect(guard(withSession("/"))).toBeUndefined()
    expect(guard(anon("/api/mc-auth"))).toBeUndefined()
    expect(guard(anon("/health"))).toBeUndefined()
    expect(guard(anon("/health/deep"))).toBeUndefined()
    expect(guard(anon("/_next/static/x.js"))).toBeUndefined()
    expect(guard(anon("/healthz"))?.status).toBe(401)
  })

  it("sin sesión ⇒ 401, o 307 a loginRedirect (acepta URL externa de MC)", () => {
    expect(mcSessionGuard({ secret: SECRET })(anon("/ventas"))?.status).toBe(401)
    const res = mcSessionGuard({ secret: SECRET, loginRedirect: "https://mc.example.test/" })(anon("/ventas"))!
    expect(res.status).toBe(307)
    expect(res.headers.get("location")).toBe("https://mc.example.test/")
  })

  it("loginRedirect del mismo origen no se protege a sí mismo (sin loop)", () => {
    const guard = mcSessionGuard({ secret: SECRET, loginRedirect: "/login" })
    expect(guard(anon("/login"))).toBeUndefined()
    expect(guard(anon("/ventas"))?.headers.get("location")).toBe(`${ORIGIN}/login`)
  })

  it("secreto ausente ⇒ 500 (fail-closed)", () => {
    expect(mcSessionGuard({ getSecret: () => undefined })(withSession("/"))?.status).toBe(500)
  })
})

// Interoperabilidad real con @ai4u/platform `readIdentity`. Solo corre dentro del
// monorepo kernel (en el repo espejo ai4u-com-co/mc-sso no existe packages/platform).
const PLATFORM_AUTH = resolve(__dirname, "../../platform/src/auth/index.ts")

describe.skipIf(!existsSync(PLATFORM_AUTH))("interop con @ai4u/platform readIdentity", () => {
  it("la cookie que emite el handler la lee readIdentity con su config por defecto", async () => {
    const { readIdentity } = await import(PLATFORM_AUTH)
    const POST = createMcAuthHandler({ serviceId: SERVICE, secret: SECRET })
    const setCookie = (await POST(postToken(validToken()))).headers.get("set-cookie")!
    // El navegador reenvía solo "nombre=valor".
    const req = new Request(`${ORIGIN}/`, { headers: { cookie: setCookie.split(";")[0] } })

    expect(readIdentity(req, { secret: SECRET })).toEqual({
      tenantId: TENANT,
      userId: "u-1",
      roles: ["admin"],
      allowedModules: ["ventas", "finanzas"],
      displayName: "Ana Pérez",
    })
    expect(readIdentity(req, { secret: SECRET + "x" })).toBeNull()
  })
})
