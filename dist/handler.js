"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.MC_SESSION_COOKIE = void 0;
exports.createMcAuthHandler = createMcAuthHandler;
exports.readMcSession = readMcSession;
exports.mcSessionGuard = mcSessionGuard;
const token_1 = require("./token");
const session_1 = require("./session");
/**
 * Nombre canónico de la cookie de sesión local tras el handoff SSO. Es el default
 * que lee `readIdentity` de @ai4u/platform.
 */
exports.MC_SESSION_COOKIE = "mc_session";
const GENERIC_CONFIG_ERROR = "Configuración de servidor incompleta";
const GENERIC_TOKEN_ERROR = "Token inválido o expirado";
function jsonError(message, status) {
    return new Response(JSON.stringify({ error: message }), {
        status,
        headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" },
    });
}
function resolveSecret(opts) {
    try {
        const value = opts.getSecret ? opts.getSecret() : opts.secret;
        return { secret: typeof value === "string" && value.length > 0 ? value : undefined };
    }
    catch (error) {
        return { error };
    }
}
function safeOnError(onError, event) {
    if (!onError)
        return;
    try {
        onError(event);
    }
    catch { /* el hook de logging nunca rompe la respuesta */ }
}
function resolveRedirect(target, requestUrl) {
    const base = new URL(requestUrl);
    try {
        const url = new URL(target, base);
        if (url.origin === base.origin)
            return url.toString();
    }
    catch { /* destino inválido ⇒ fallback */ }
    return new URL("/", base).toString();
}
function isSecureDefault() {
    return typeof process !== "undefined" && process.env?.NODE_ENV === "production";
}
function serializeCookie(name, value, maxAgeS, secure) {
    const parts = [
        `${name}=${value}`,
        "Path=/",
        `Max-Age=${maxAgeS}`,
        "HttpOnly",
        "SameSite=Lax",
    ];
    if (secure)
        parts.push("Secure");
    return parts.join("; ");
}
async function readFormToken(req) {
    // Solo form (urlencoded/multipart): es lo que envía /api/handoff de Mission Control
    // y lo único que aceptan hoy los receptores. Body ilegible ⇒ token vacío ⇒ 401.
    try {
        const form = await req.formData();
        const value = form.get("token");
        return typeof value === "string" ? value : "";
    }
    catch {
        return "";
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
function createMcAuthHandler(opts) {
    if (!opts || typeof opts.serviceId !== "string" || opts.serviceId.length === 0) {
        throw new TypeError("createMcAuthHandler: serviceId es obligatorio");
    }
    const ttlMs = opts.ttlMs ?? session_1.DEFAULT_SESSION_TTL_MS;
    if (!Number.isFinite(ttlMs) || ttlMs <= 0) {
        throw new TypeError("createMcAuthHandler: ttlMs debe ser un número positivo");
    }
    const cookieName = opts.cookieName ?? exports.MC_SESSION_COOKIE;
    const serviceId = opts.serviceId;
    return async function mcAuthHandler(req) {
        const { secret, error } = resolveSecret(opts);
        if (!secret) {
            safeOnError(opts.onError, { reason: "missing_secret", serviceId, error });
            return jsonError(GENERIC_CONFIG_ERROR, 500);
        }
        const token = await readFormToken(req);
        // verifyMcToken compara la firma en tiempo constante (timingSafeEqual) y valida
        // exp + serviceId.
        const data = (0, token_1.verifyMcToken)(token, serviceId, secret);
        if (!data) {
            safeOnError(opts.onError, { reason: "invalid_token", serviceId });
            return jsonError(GENERIC_TOKEN_ERROR, 401);
        }
        // Mismos campos que copian hoy los 12 receptores manuales.
        const sessionToken = (0, session_1.createSession)(data.tenantId, secret, ttlMs, {
            userId: data.userId,
            roles: data.roles,
            allowedModules: data.allowedModules,
            displayName: data.displayName,
        });
        const target = typeof opts.redirectTo === "function"
            ? opts.redirectTo(data)
            : (opts.redirectTo ?? "/");
        const headers = new Headers();
        headers.set("location", resolveRedirect(target, req.url));
        headers.set("cache-control", "no-store");
        headers.append("set-cookie", serializeCookie(cookieName, sessionToken, Math.floor(ttlMs / 1000), opts.secure ?? isSecureDefault()));
        // 303 para que el navegador siga el redirect como GET (no re-POST).
        return new Response(null, { status: 303, headers });
    };
}
function readCookie(header, name) {
    if (!header)
        return undefined;
    for (const part of header.split(";")) {
        const i = part.indexOf("=");
        if (i === -1)
            continue;
        if (part.slice(0, i).trim() !== name)
            continue;
        const raw = part.slice(i + 1).trim();
        try {
            return decodeURIComponent(raw);
        }
        catch {
            return raw;
        }
    }
    return undefined;
}
/**
 * Lee y verifica la sesión local (`mc_session`) desde un Request (o cualquier objeto
 * con `headers.get`) o directamente desde el valor del header `Cookie`.
 * Devuelve el payload o `null` si no hay cookie, la firma no cuadra o venció.
 */
function readMcSession(source, secret, cookieName = exports.MC_SESSION_COOKIE) {
    if (!secret)
        return null;
    const header = typeof source === "string" ? source : source?.headers.get("cookie");
    const token = readCookie(header, cookieName);
    if (!token)
        return null;
    return (0, session_1.verifySession)(token, secret);
}
const ALWAYS_PUBLIC = "/api/mc-auth";
function matchesPath(pathname, rule) {
    if (typeof rule !== "string")
        return rule.test(pathname);
    const base = rule.length > 1 && rule.endsWith("/") ? rule.slice(0, -1) : rule;
    return pathname === base || pathname.startsWith(base === "/" ? "/" : `${base}/`);
}
/**
 * Guard de páginas para `proxy.ts`/middleware. Devuelve `undefined` si el request
 * puede seguir (ruta pública o sesión válida) o un `Response` de rechazo:
 * 500 si falta el secreto (fail-closed), 307 a `loginRedirect` o 401 sin sesión.
 *
 * Usa node:crypto (vía verifySession): en Next 16 `proxy.ts` corre en runtime Node.
 */
function mcSessionGuard(opts) {
    const publicPaths = [ALWAYS_PUBLIC, ...(opts.publicPaths ?? [])];
    const cookieName = opts.cookieName ?? exports.MC_SESSION_COOKIE;
    return function guard(req) {
        const url = new URL(req.url);
        if (publicPaths.some((rule) => matchesPath(url.pathname, rule)))
            return undefined;
        // loginRedirect es configuración del desarrollador (suele ser la URL de Mission
        // Control, otro origen): se respeta tal cual. Si es del mismo origen, esa ruta no
        // se protege, para no generar un loop de redirects.
        const login = opts.loginRedirect ? new URL(opts.loginRedirect, url) : undefined;
        if (login && login.origin === url.origin && login.pathname === url.pathname)
            return undefined;
        const { secret } = resolveSecret(opts);
        if (!secret)
            return jsonError(GENERIC_CONFIG_ERROR, 500);
        if (readMcSession(req, secret, cookieName))
            return undefined;
        if (login) {
            return new Response(null, {
                status: 307,
                headers: { location: login.toString(), "cache-control": "no-store" },
            });
        }
        return jsonError("No autenticado", 401);
    };
}
