import { verifyMcToken } from "./token"
import type { McTokenPayload } from "./token"
import { createSession, verifySession, DEFAULT_SESSION_TTL_MS } from "./session"
import type { SessionPayload } from "./session"

/**
 * Nombre canónico de la cookie de sesión local tras el handoff SSO. Es el default
 * que lee `readIdentity` de @ai4u/platform.
 */
export const MC_SESSION_COOKIE = "mc_session"



/** Motivo por el que el receptor rechazó el handoff (para logging, nunca para el cliente). */
export type McAuthErrorReason = "missing_secret" | "invalid_token"

export interface McAuthErrorEvent {
  reason:    McAuthErrorReason
  serviceId: string
  /** Excepción original, si la hubo (p. ej. getSecret() lanzó). Nunca contiene el secreto. */
  error?:    unknown
}

export interface McAuthHandlerOptions {
  /** Id del servicio tal como lo firma Mission Control en el mc-token. */
  serviceId: string
  /** Secreto compartido con MC. Si se pasa `getSecret`, tiene prioridad. */
  secret?: string
  /** Lee el secreto en cada request (útil para env vars leídas en runtime). */
  getSecret?: () => string | null | undefined
  /** TTL de la sesión local (default 8 h). Max-Age de la cookie = ttlMs / 1000. */
  ttlMs?: number
  /**
   * A dónde redirigir tras el canje (default "/"). Se resuelve contra la URL del
   * request y solo se aceptan destinos del mismo origen; si no, cae a "/".
   */
  redirectTo?: string | ((payload: McTokenPayload) => string)
  /** Nombre de la cookie (default `MC_SESSION_COOKIE`). */
  cookieName?: string
  /** Fuerza el flag Secure (default: NODE_ENV === "production"). */
  secure?: boolean
  /** Hook de observabilidad para rechazos (401/500). No debe lanzar. */
  onError?: (event: McAuthErrorEvent) => void
}

const GENERIC_CONFIG_ERROR = "Configuración de servidor incompleta"
const GENERIC_TOKEN_ERROR  = "Token inválido o expirado"

function jsonError(message: string, status: number): Response {
  return new Response(JSON.stringify({ error: message }), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" },
  })
}

function resolveSecret(opts: Pick<McAuthHandlerOptions, "secret" | "getSecret">): {
  secret?: string
  error?:  unknown
} {
  try {
    const value = opts.getSecret ? opts.getSecret() : opts.secret
    return { secret: typeof value === "string" && value.length > 0 ? value : undefined }
  } catch (error) {
    return { error }
  }
}

function safeOnError(onError: McAuthHandlerOptions["onError"], event: McAuthErrorEvent): void {
  if (!onError) return
  try { onError(event) } catch { /* el hook de logging nunca rompe la respuesta */ }
}

function resolveRedirect(target: string, requestUrl: string): string {
  const base = new URL(requestUrl)
  try {
    const url = new URL(target, base)
    if (url.origin === base.origin) return url.toString()
  } catch { /* destino inválido ⇒ fallback */ }
  return new URL("/", base).toString()
}

function isSecureDefault(): boolean {
  return typeof process !== "undefined" && process.env?.NODE_ENV === "production"
}

function serializeCookie(name: string, value: string, maxAgeS: number, secure: boolean): string {
  const parts = [
    `${name}=${value}`,
    "Path=/",
    `Max-Age=${maxAgeS}`,
    "HttpOnly",
    "SameSite=Lax",
  ]
  if (secure) parts.push("Secure")
  return parts.join("; ")
}

async function readFormToken(req: Request): Promise<string> {
  // Solo form (urlencoded/multipart): es lo que envía /api/handoff de Mission Control
  // y lo único que aceptan hoy los receptores. Body ilegible ⇒ token vacío ⇒ 401.
  try {
    const form  = await req.formData()
    const value = form.get("token")
    return typeof value === "string" ? value : ""
  } catch {
    return ""
  }
}

/**
 * Receptor estándar del handoff SSO de Mission Control (`/api/mc-auth`).
 *
 * Devuelve `(req: Request) => Promise<Response>` con Request/Response estándar, así
 * sirve directo como `export const POST` en Next App Router (y se puede envolver en
 * `withApiHandler` de @ai4u/platform).
 *
 * - 303 + `Set-Cookie` (HttpOnly, SameSite=Lax, Path=/, Max-Age = ttl, Secure en prod)
 *   cuando el mc-token es válido para `serviceId`.
 * - 401 genérico si el token falta, es inválido, venció o es de otro servicio.
 * - 500 genérico si no hay secreto configurado (fail-closed; nunca se imprime).
 */
export function createMcAuthHandler(opts: McAuthHandlerOptions): (req: Request) => Promise<Response> {
  if (!opts || typeof opts.serviceId !== "string" || opts.serviceId.length === 0) {
    throw new TypeError("createMcAuthHandler: serviceId es obligatorio")
  }
  const ttlMs      = opts.ttlMs ?? DEFAULT_SESSION_TTL_MS
  if (!Number.isFinite(ttlMs) || ttlMs <= 0) {
    throw new TypeError("createMcAuthHandler: ttlMs debe ser un número positivo")
  }
  const cookieName = opts.cookieName ?? MC_SESSION_COOKIE
  const serviceId  = opts.serviceId

  return async function mcAuthHandler(req: Request): Promise<Response> {
    const { secret, error } = resolveSecret(opts)
    if (!secret) {
      safeOnError(opts.onError, { reason: "missing_secret", serviceId, error })
      return jsonError(GENERIC_CONFIG_ERROR, 500)
    }

    const token = await readFormToken(req)
    // verifyMcToken compara la firma en tiempo constante (timingSafeEqual) y valida
    // exp + serviceId.
    const data = verifyMcToken(token, serviceId, secret)
    if (!data) {
      safeOnError(opts.onError, { reason: "invalid_token", serviceId })
      return jsonError(GENERIC_TOKEN_ERROR, 401)
    }

    // Mismos campos que copian hoy los 12 receptores manuales + el serviceId (1.3.0),
    // que ata la sesión a esta app (ver readMcSession({ serviceId })).
    const sessionToken = createSession(data.tenantId, secret, ttlMs, {
      userId:         data.userId,
      roles:          data.roles,
      allowedModules: data.allowedModules,
      displayName:    data.displayName,
      serviceId,
    })

    const target = typeof opts.redirectTo === "function"
      ? opts.redirectTo(data)
      : (opts.redirectTo ?? "/")

    const headers = new Headers()
    headers.set("location", resolveRedirect(target, req.url))
    headers.set("cache-control", "no-store")
    headers.append(
      "set-cookie",
      serializeCookie(cookieName, sessionToken, Math.floor(ttlMs / 1000), opts.secure ?? isSecureDefault()),
    )
    // 303 para que el navegador siga el redirect como GET (no re-POST).
    return new Response(null, { status: 303, headers })
  }
}

type HeaderCarrier = { headers: { get(name: string): string | null } }

function readCookie(header: string | null | undefined, name: string): string | undefined {
  if (!header) return undefined
  for (const part of header.split(";")) {
    const i = part.indexOf("=")
    if (i === -1) continue
    if (part.slice(0, i).trim() !== name) continue
    const raw = part.slice(i + 1).trim()
    try { return decodeURIComponent(raw) } catch { return raw }
  }
  return undefined
}

/**
 * Restricciones de app/tenant sobre la sesión. El secreto de firma
 * (`MISSION_CONTROL_SECRET`) se comparte entre apps, así que una firma válida NO
 * basta: sin estas opciones, una sesión emitida para otra app u otro tenant pasa.
 */
export interface McSessionScope {
  /**
   * `serviceId` de ESTA app (el mismo que se pasa a `createMcAuthHandler`). Una sesión
   * emitida para otro servicio ⇒ rechazada. Sin esta opción no se valida la app.
   */
  serviceId?: string
  /**
   * Tenants aceptados (apps de un solo tenant, p. ej. `["flexoimpresos"]`). Tenant fuera
   * de la lista ⇒ rechazada. Lista vacía ⇒ se rechaza todo (fail-closed). Sin esta
   * opción no se valida el tenant. Se compara con `normalizeTenant` si se pasa; si no,
   * sin mayúsculas/espacios (`"Flexoimpresos"` == `"flexoimpresos"`, pero `"flexo"` NO).
   */
  allowedTenants?: readonly string[]
  /**
   * Normalizador de ids de tenant para comparar `allowedTenants` (p. ej. `normalizeTenant`
   * de `@ai4u/config/env`, que resuelve alias como `"flexo"` → `"FLEXOIMPRESOS"`). Si lanza
   * o devuelve vacío para el tenant de la sesión ⇒ rechazada.
   */
  normalizeTenant?: (tenantId: string) => string
  /**
   * Aceptar sesiones "legacy" sin `serviceId` (emitidas por mc-sso ≤ 1.2.0). Default
   * `true` en 1.3.0 para no desloguear a todos al desplegar; pasa a `false` en 1.4.0
   * (las sesiones duran 8 h, así que expiran solas). Con `false` se rechaza toda sesión
   * sin `serviceId`, se pase o no la opción `serviceId`.
   */
  acceptLegacy?: boolean
}

export interface ReadMcSessionOptions extends McSessionScope {
  /** Nombre de la cookie (default `MC_SESSION_COOKIE`). */
  cookieName?: string
}

/** Motivo de rechazo de una sesión con firma válida (o `"none"` si no hay sesión válida). */
type SessionRejection = "none" | "service" | "legacy" | "tenant"

function normalizeWith(fn: ((id: string) => string) | undefined, id: string): string | null {
  try {
    const out = fn ? fn(id) : id.trim().toLowerCase()
    return typeof out === "string" && out.length > 0 ? out : null
  } catch {
    return null
  }
}

function tenantAllowed(tenantId: string, scope: McSessionScope): boolean {
  if (!scope.allowedTenants) return true
  const t = normalizeWith(scope.normalizeTenant, tenantId)
  if (t === null) return false
  return scope.allowedTenants.some((a) => normalizeWith(scope.normalizeTenant, a) === t)
}

function evaluateSession(
  source: HeaderCarrier | string | null | undefined,
  secret: string,
  cookieName: string,
  scope: McSessionScope,
): { session: SessionPayload } | { rejected: SessionRejection } {
  const header = typeof source === "string" ? source : source?.headers.get("cookie")
  const token  = readCookie(header, cookieName)
  const session = token ? verifySession(token, secret) : null
  if (!session) return { rejected: "none" }

  const hasService = session.serviceId !== undefined
  if (!hasService) {
    if (scope.acceptLegacy === false) return { rejected: "legacy" }
  } else if (scope.serviceId !== undefined && session.serviceId !== scope.serviceId) {
    return { rejected: "service" }
  }
  if (!tenantAllowed(session.tenantId, scope)) return { rejected: "tenant" }
  return { session }
}

/**
 * Lee y verifica la sesión local (`mc_session`) desde un Request (o cualquier objeto
 * con `headers.get`) o directamente desde el valor del header `Cookie`.
 * Devuelve el payload o `null` si no hay cookie, la firma no cuadra, venció, o no cumple
 * las restricciones de `opts` (`serviceId`, `allowedTenants`, `acceptLegacy`).
 *
 * El 3er parámetro acepta un string (nombre de la cookie, firma de 1.2.0) o un objeto
 * de opciones.
 */
export function readMcSession(
  source: HeaderCarrier | string | null | undefined,
  secret: string | null | undefined,
  opts:   string | ReadMcSessionOptions = {},
): SessionPayload | null {
  if (!secret) return null
  const { cookieName = MC_SESSION_COOKIE, ...scope } = typeof opts === "string" ? { cookieName: opts } : opts
  const result = evaluateSession(source, secret, cookieName, scope)
  return "session" in result ? result.session : null
}

export interface McSessionGuardOptions extends McSessionScope {
  secret?:    string
  getSecret?: () => string | null | undefined
  /**
   * Rutas que no exigen sesión. Un string matchea la ruta exacta y todo lo que cuelga
   * de ella (`"/api/public"` cubre `"/api/public/x"`); un RegExp se prueba contra el
   * pathname. `"/api/mc-auth"` siempre es pública (si no, nadie podría entrar).
   */
  publicPaths?: (string | RegExp)[]
  /** Si se define (ruta o URL absoluta, p. ej. Mission Control), sin sesión ⇒ 307 acá; si no, 401. */
  loginRedirect?: string
  cookieName?: string
}

const ALWAYS_PUBLIC = "/api/mc-auth"

function matchesPath(pathname: string, rule: string | RegExp): boolean {
  if (typeof rule !== "string") return rule.test(pathname)
  const base = rule.length > 1 && rule.endsWith("/") ? rule.slice(0, -1) : rule
  return pathname === base || pathname.startsWith(base === "/" ? "/" : `${base}/`)
}

/**
 * Guard de páginas para `proxy.ts`/middleware. Devuelve `undefined` si el request
 * puede seguir (ruta pública o sesión válida) o un `Response` de rechazo:
 * 500 si falta el secreto (fail-closed), 403 si la sesión es de un tenant fuera de
 * `allowedTenants`, 307 a `loginRedirect` o 401 sin sesión (incluye sesión de otro
 * `serviceId` o legacy con `acceptLegacy: false`: se tratan como "sin sesión", así un
 * nuevo handoff desde MC emite la cookie correcta).
 *
 * Usa node:crypto (vía verifySession): en Next 16 `proxy.ts` corre en runtime Node.
 */
export function mcSessionGuard(opts: McSessionGuardOptions): (req: Request) => Response | undefined {
  const publicPaths = [ALWAYS_PUBLIC, ...(opts.publicPaths ?? [])]
  const cookieName  = opts.cookieName ?? MC_SESSION_COOKIE
  const scope: McSessionScope = {
    serviceId:       opts.serviceId,
    allowedTenants:  opts.allowedTenants,
    normalizeTenant: opts.normalizeTenant,
    acceptLegacy:    opts.acceptLegacy,
  }
  return function guard(req: Request): Response | undefined {
    const url = new URL(req.url)
    if (publicPaths.some((rule) => matchesPath(url.pathname, rule))) return undefined

    // loginRedirect es configuración del desarrollador (suele ser la URL de Mission
    // Control, otro origen): se respeta tal cual. Si es del mismo origen, esa ruta no
    // se protege, para no generar un loop de redirects.
    const login = opts.loginRedirect ? new URL(opts.loginRedirect, url) : undefined
    if (login && login.origin === url.origin && login.pathname === url.pathname) return undefined

    const { secret } = resolveSecret(opts)
    if (!secret) return jsonError(GENERIC_CONFIG_ERROR, 500)

    const result = evaluateSession(req, secret, cookieName, scope)
    if ("session" in result) return undefined
    if (result.rejected === "tenant") return jsonError("Acceso denegado", 403)

    if (login) {
      return new Response(null, {
        status:  307,
        headers: { location: login.toString(), "cache-control": "no-store" },
      })
    }
    return jsonError("No autenticado", 401)
  }
}
