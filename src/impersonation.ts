/**
 * Rastro de "quién está viendo como quién" cuando un superadmin de Mission
 * Control impersona a un usuario de un tenant. Viaja dentro de `extra` en
 * McTokenPayload/SessionPayload — nunca reemplaza al userId impersonado,
 * solo lo acompaña para que la app destino pueda auditar y mostrar el banner.
 */
export interface ImpersonationInfo {
  byAdminId:    string
  byAdminEmail: string
  startedAt:    number
}

export function isImpersonationInfo(value: unknown): value is ImpersonationInfo {
  if (typeof value !== "object" || value === null) return false
  const v = value as Record<string, unknown>
  return (
    typeof v.byAdminId    === "string" &&
    typeof v.byAdminEmail === "string" &&
    typeof v.startedAt    === "number"
  )
}
