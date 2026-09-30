import type { McTokenPayload } from "./token";
import type { SessionPayload } from "./session";
/**
 * Nombre canónico de la cookie de sesión local tras el handoff SSO. Es el default
 * que lee `readIdentity` de @ai4u/platform.
 */
export declare const MC_SESSION_COOKIE = "mc_session";
/** Motivo por el que el receptor rechazó el handoff (para logging, nunca para el cliente). */
export type McAuthErrorReason = "missing_secret" | "invalid_token";
export interface McAuthErrorEvent {
    reason: McAuthErrorReason;
    serviceId: string;
    /** Excepción original, si la hubo (p. ej. getSecret() lanzó). Nunca contiene el secreto. */
    error?: unknown;
}
export interface McAuthHandlerOptions {
    /** Id del servicio tal como lo firma Mission Control en el mc-token. */
    serviceId: string;
    /** Secreto compartido con MC. Si se pasa `getSecret`, tiene prioridad. */
    secret?: string;
    /** Lee el secreto en cada request (útil para env vars leídas en runtime). */
    getSecret?: () => string | null | undefined;
    /** TTL de la sesión local (default 8 h). Max-Age de la cookie = ttlMs / 1000. */
    ttlMs?: number;
    /**
     * A dónde redirigir tras el canje (default "/"). Se resuelve contra la URL del
     * request y solo se aceptan destinos del mismo origen; si no, cae a "/".
     */
    redirectTo?: string | ((payload: McTokenPayload) => string);
    /** Nombre de la cookie (default `MC_SESSION_COOKIE`). */
    cookieName?: string;
    /** Fuerza el flag Secure (default: NODE_ENV === "production"). */
    secure?: boolean;
    /** Hook de observabilidad para rechazos (401/500). No debe lanzar. */
    onError?: (event: McAuthErrorEvent) => void;
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
export declare function createMcAuthHandler(opts: McAuthHandlerOptions): (req: Request) => Promise<Response>;
type HeaderCarrier = {
    headers: {
        get(name: string): string | null;
    };
};
/**
 * Lee y verifica la sesión local (`mc_session`) desde un Request (o cualquier objeto
 * con `headers.get`) o directamente desde el valor del header `Cookie`.
 * Devuelve el payload o `null` si no hay cookie, la firma no cuadra o venció.
 */
export declare function readMcSession(source: HeaderCarrier | string | null | undefined, secret: string | null | undefined, cookieName?: string): SessionPayload | null;
export interface McSessionGuardOptions {
    secret?: string;
    getSecret?: () => string | null | undefined;
    /**
     * Rutas que no exigen sesión. Un string matchea la ruta exacta y todo lo que cuelga
     * de ella (`"/api/public"` cubre `"/api/public/x"`); un RegExp se prueba contra el
     * pathname. `"/api/mc-auth"` siempre es pública (si no, nadie podría entrar).
     */
    publicPaths?: (string | RegExp)[];
    /** Si se define (ruta o URL absoluta, p. ej. Mission Control), sin sesión ⇒ 307 acá; si no, 401. */
    loginRedirect?: string;
    cookieName?: string;
}
/**
 * Guard de páginas para `proxy.ts`/middleware. Devuelve `undefined` si el request
 * puede seguir (ruta pública o sesión válida) o un `Response` de rechazo:
 * 500 si falta el secreto (fail-closed), 307 a `loginRedirect` o 401 sin sesión.
 *
 * Usa node:crypto (vía verifySession): en Next 16 `proxy.ts` corre en runtime Node.
 */
export declare function mcSessionGuard(opts: McSessionGuardOptions): (req: Request) => Response | undefined;
export {};
//# sourceMappingURL=handler.d.ts.map