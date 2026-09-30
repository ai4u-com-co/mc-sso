import { timingSafeEqual } from "node:crypto"
import { sign } from "./crypto"

/** TTL por defecto de la sesión local tras el handoff SSO: 8 h (ver FLX-091). */
export const DEFAULT_SESSION_TTL_MS = 8 * 60 * 60 * 1000

/** Identidad+permisos opcionales que la sesión conserva tras el handoff SSO. */
export interface SessionExtra {
  userId?:         string
  roles?:          string[]
  allowedModules?: string[] | null
  displayName?:    string
  /**
   * Servicio (app) para el que se emitió la sesión — el `serviceId` del mc-token que
   * canjeó `createMcAuthHandler` (desde 1.3.0). Ata la cookie a esa app: como el secreto
   * de firma se comparte entre apps, sin este campo una sesión de una app sirve en otra.
   * Opcional: las sesiones emitidas por 1.2.0 o antes no lo traen ("legacy").
   */
  serviceId?:      string
}

export interface SessionPayload extends SessionExtra {
  tenantId: string
  iat:      number
  exp:      number
}

export function createSession(
  tenantId: string,
  secret:   string,
  ttlMs     = DEFAULT_SESSION_TTL_MS,
  extra:    SessionExtra = {},
): string {
  const now  = Date.now()
  const data: SessionPayload = { tenantId, ...extra, iat: now, exp: now + ttlMs }
  const payload = Buffer.from(JSON.stringify(data)).toString("base64url")
  return `${payload}.${sign(payload, secret)}`
}

export function verifySession(
  token:  string,
  secret: string,
): SessionPayload | null {
  if (!token || !secret) return null
  const dot = token.lastIndexOf(".")
  if (dot === -1) return null
  const payload  = token.slice(0, dot)
  const sig      = token.slice(dot + 1)
  const expected = sign(payload, secret)
  try {
    const a = Buffer.from(sig,      "base64url")
    const b = Buffer.from(expected, "base64url")
    if (a.length !== b.length || !timingSafeEqual(a, b)) return null
  } catch { return null }
  try {
    const data = JSON.parse(Buffer.from(payload, "base64url").toString()) as SessionPayload
    if (
      typeof data.tenantId !== "string" ||
      typeof data.iat      !== "number" ||
      typeof data.exp      !== "number"
    ) return null
    if (data.exp < Date.now()) return null
    return data
  } catch { return null }
}
