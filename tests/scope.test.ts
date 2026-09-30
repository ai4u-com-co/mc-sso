import { existsSync } from "node:fs"
import { resolve } from "node:path"
import { describe, it, expect } from "vitest"
import { createMcToken } from "../src/token"
import { createSession, verifySession } from "../src/session"
import { MC_SESSION_COOKIE, createMcAuthHandler, readMcSession, mcSessionGuard } from "../src/index"

// Valores construidos en runtime (gitleaks): nunca un literal con forma de secreto.
const SECRET = ["test", "mc", "scope", String(Date.now())].join("-")
const ORIGIN = "https://app.example.test"
const FLEXO  = "flexoimpresos"
const TAMA   = "tamaprint"

/** Sesión 1.3.0 (con serviceId) tal como la emitiría el handler de `serviceId`. */
const session13 = (tenantId: string, serviceId: string) =>
  createSession(tenantId, SECRET, undefined, { userId: "u-1", roles: ["admin"], serviceId })
/** Sesión legacy (≤ 1.2.0): mismo formato, sin serviceId. */
const legacy = (tenantId: string) => createSession(tenantId, SECRET, undefined, { userId: "u-1" })

const cookie = (token: string) => `${MC_SESSION_COOKIE}=${token}`
const reqWith = (token: string, path = "/") =>
  new Request(`${ORIGIN}${path}`, { headers: { cookie: cookie(token) } })

// Alias estilo @ai4u/config normalizeTenant (sin importarlo: el espejo corre standalone).
const ALIASES: Record<string, string> = { FLEXO: "FLEXOIMPRESOS" }
const normalizeTenant = (id: string) => {
  const base = id.toUpperCase().replace(/[^A-Z0-9]/g, "")
  if (!base) throw new Error("tenant vacío")
  return ALIASES[base] ?? base
}

describe("createMcAuthHandler guarda el serviceId en la sesión", () => {
  it("la cookie emitida lleva serviceId = el del receptor", async () => {
    const POST = createMcAuthHandler({ serviceId: "cotizadorflexo", secret: SECRET })
    const body = new URLSearchParams({ token: createMcToken(FLEXO, "cotizadorflexo", "Flexo", SECRET) })
    const res  = await POST(new Request(`${ORIGIN}/api/mc-auth`, { method: "POST", body }))
    expect(res.status).toBe(303)
    const value = res.headers.get("set-cookie")!.split(";")[0].split("=").slice(1).join("=")
    expect(verifySession(value, SECRET)).toMatchObject({ tenantId: FLEXO, serviceId: "cotizadorflexo" })
  })
})

describe("readMcSession con opciones de alcance (app/tenant)", () => {
  it("sesión de OTRA app (misma firma) ⇒ null", () => {
    const c = cookie(session13(FLEXO, "kpis"))
    expect(readMcSession(c, SECRET, { serviceId: "cotizadorflexo" })).toBeNull()
    expect(readMcSession(c, SECRET, { serviceId: "kpis" })?.serviceId).toBe("kpis")
  })

  it("tenant fuera de allowedTenants ⇒ null; dentro ⇒ sesión", () => {
    expect(readMcSession(cookie(session13(TAMA, "x")), SECRET, { allowedTenants: [FLEXO] })).toBeNull()
    expect(readMcSession(cookie(session13(FLEXO, "x")), SECRET, { allowedTenants: [FLEXO] })).not.toBeNull()
  })

  it("comparación de tenant: sin normalizador ignora mayúsculas/espacios; con normalizador resuelve alias", () => {
    const flexoAlias = cookie(session13("flexo", "x"))
    expect(readMcSession(cookie(session13(" FlexoImpresos ", "x")), SECRET, { allowedTenants: [FLEXO] })).not.toBeNull()
    expect(readMcSession(flexoAlias, SECRET, { allowedTenants: [FLEXO] })).toBeNull()
    expect(readMcSession(flexoAlias, SECRET, { allowedTenants: [FLEXO], normalizeTenant })).not.toBeNull()
  })

  it("fail-closed: allowedTenants vacío o normalizador que lanza ⇒ null", () => {
    const c = cookie(session13(FLEXO, "x"))
    expect(readMcSession(c, SECRET, { allowedTenants: [] })).toBeNull()
    expect(readMcSession(cookie(session13("  ", "x")), SECRET, { allowedTenants: [FLEXO], normalizeTenant })).toBeNull()
  })

  it("legacy sin serviceId: acceptLegacy por defecto (true) ⇒ pasa; false ⇒ null", () => {
    const c = cookie(legacy(FLEXO))
    expect(readMcSession(c, SECRET, { serviceId: "cotizadorflexo" })?.tenantId).toBe(FLEXO)
    expect(readMcSession(c, SECRET, { serviceId: "cotizadorflexo", acceptLegacy: true })).not.toBeNull()
    expect(readMcSession(c, SECRET, { serviceId: "cotizadorflexo", acceptLegacy: false })).toBeNull()
    expect(readMcSession(c, SECRET, { acceptLegacy: false })).toBeNull()
    // Legacy igual debe cumplir allowedTenants.
    expect(readMcSession(cookie(legacy(TAMA)), SECRET, { allowedTenants: [FLEXO] })).toBeNull()
  })

  it("compat 1.2.0: el 3er parámetro string sigue siendo el nombre de la cookie", () => {
    const t = session13(FLEXO, "x")
    expect(readMcSession(`otra=${t}`, SECRET, "otra")?.tenantId).toBe(FLEXO)
    expect(readMcSession(`otra=${t}`, SECRET, { cookieName: "otra", serviceId: "x" })).not.toBeNull()
    expect(readMcSession(`otra=${t}`, SECRET)).toBeNull()
    // Sin opciones no se valida app ni tenant (comportamiento 1.2.0).
    expect(readMcSession(cookie(session13(TAMA, "otra-app")), SECRET)?.tenantId).toBe(TAMA)
  })
})

describe("mcSessionGuard con serviceId/allowedTenants", () => {
  const guard = mcSessionGuard({
    secret: SECRET, serviceId: "cotizadorflexo", allowedTenants: [FLEXO], normalizeTenant,
  })

  it("sesión propia (o alias del tenant) ⇒ pasa", () => {
    expect(guard(reqWith(session13(FLEXO, "cotizadorflexo")))).toBeUndefined()
    expect(guard(reqWith(session13("flexo", "cotizadorflexo")))).toBeUndefined()
  })

  it("sesión de otra app ⇒ 401 (o 307 a loginRedirect: un handoff nuevo emite la correcta)", () => {
    expect(guard(reqWith(session13(FLEXO, "kpis")))?.status).toBe(401)
    const withLogin = mcSessionGuard({ secret: SECRET, serviceId: "cotizadorflexo", loginRedirect: "https://mc.example.test/" })
    expect(withLogin(reqWith(session13(FLEXO, "kpis")))?.status).toBe(307)
  })

  it("tenant no permitido ⇒ 403 genérico (aunque haya loginRedirect)", async () => {
    const res = guard(reqWith(session13(TAMA, "cotizadorflexo")))!
    expect(res.status).toBe(403)
    expect(await res.json()).toEqual({ error: "Acceso denegado" })
    const withLogin = mcSessionGuard({ secret: SECRET, allowedTenants: [FLEXO], loginRedirect: "https://mc.example.test/" })
    expect(withLogin(reqWith(legacy(TAMA)))?.status).toBe(403)
  })

  it("legacy: pasa por defecto; con acceptLegacy false ⇒ 401", () => {
    expect(guard(reqWith(legacy(FLEXO)))).toBeUndefined()
    const strict = mcSessionGuard({ secret: SECRET, serviceId: "cotizadorflexo", acceptLegacy: false })
    expect(strict(reqWith(legacy(FLEXO)))?.status).toBe(401)
  })

  it("rutas públicas siguen sin exigir sesión", () => {
    expect(guard(new Request(`${ORIGIN}/api/mc-auth`))).toBeUndefined()
  })
})

// Compat hacia atrás real: un verificador 1.2.0 (la copia que instala @ai4u/platform en
// el monorepo) acepta la sesión 1.3.0 con serviceId. Solo corre dentro de kernel.
const MC_SSO_120 = resolve(__dirname, "../../platform/node_modules/@ai4u/mc-sso/dist/index.js")

describe.skipIf(!existsSync(MC_SSO_120))("compat con mc-sso 1.2.0 instalado", () => {
  it("verifySession/readMcSession de 1.2.0 leen una sesión emitida por 1.3.0", async () => {
    const v120 = await import(MC_SSO_120)
    const t = session13(FLEXO, "cotizadorflexo")
    expect(v120.verifySession(t, SECRET)).toMatchObject({ tenantId: FLEXO, userId: "u-1" })
    expect(v120.readMcSession(cookie(t), SECRET)?.tenantId).toBe(FLEXO)
  })
})
