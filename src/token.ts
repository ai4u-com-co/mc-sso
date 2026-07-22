import { timingSafeEqual } from "node:crypto"
import { sign } from "./crypto"
import { isImpersonationInfo, type ImpersonationInfo } from "./impersonation"

/**
 * Datos de identidad+permisos que Mission Control embebe en el token durante el
 * handoff, para que la app receptora conozca al usuario sin tocar la BD.
 * Todos opcionales ⇒ retrocompatible con los verificadores existentes.
 */
export interface McTokenExtra {
  userId?:         string
  roles?:          string[]
  allowedModules?: string[] | null
  impersonation?:  ImpersonationInfo
}

export interface McTokenPayload extends McTokenExtra {
  tenantId:    string
  serviceId:   string
  displayName: string
  exp:         number
}

export function createMcToken(
  tenantId:    string,
  serviceId:   string,
  displayName: string,
  secret:      string,
  extra:       McTokenExtra = {},
): string {
  const data: McTokenPayload = {
    tenantId,
    serviceId,
    displayName,
    ...extra,
    exp: Date.now() + 5 * 60 * 1000,
  }
  const payload = Buffer.from(JSON.stringify(data)).toString("base64url")
  return `${payload}.${sign(payload, secret)}`
}

export function verifyMcToken(
  token:     string,
  serviceId: string,
  secret:    string,
): McTokenPayload | null {
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
    const data = JSON.parse(Buffer.from(payload, "base64url").toString()) as McTokenPayload
    if (
      typeof data.tenantId    !== "string" ||
      typeof data.serviceId   !== "string" ||
      typeof data.displayName !== "string" ||
      typeof data.exp         !== "number"
    ) return null
    if (data.exp < Date.now()) return null
    if (data.serviceId !== serviceId) return null
    if (data.impersonation !== undefined && !isImpersonationInfo(data.impersonation)) return null
    return data
  } catch { return null }
}
