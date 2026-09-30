# @ai4u/mc-sso

Protocolo SSO entre Mission Control y los módulos del ecosistema superAI: MC firma un
mc-token de 5 minutos (`/api/handoff`, POST auto-enviado con `token` en el body del form) y
el módulo lo canjea en `/api/mc-auth` por una cookie de sesión local `mc_session` (8 h).

```bash
npm install "@ai4u/mc-sso@github:ai4u-com-co/mc-sso#v1.3.0"
```

> Fuente de verdad: `ai4u-com-co/kernel` (`packages/mc-sso`). El repo `ai4u-com-co/mc-sso`
> es un espejo que se publica al taggear `mc-sso-vX.Y.Z` en kernel.

## Receptor `/api/mc-auth` (Next App Router)

```ts
// app/api/mc-auth/route.ts
import { createMcAuthHandler } from "@ai4u/mc-sso"
import { env } from "@/lib/env"
export const POST = createMcAuthHandler({ serviceId: SERVICE_ID, getSecret: () => env.MISSION_CONTROL_SECRET })
```

Opciones:

| opción | default | |
|---|---|---|
| `serviceId` | — (obligatorio) | Debe coincidir con el `serviceId` que firma MC. |
| `secret` / `getSecret()` | — | `getSecret` tiene prioridad y se evalúa en cada request. Sin secreto ⇒ 500 genérico. |
| `ttlMs` | `DEFAULT_SESSION_TTL_MS` (8 h) | La cookie usa `Max-Age = ttlMs / 1000`, siempre alineado con el `exp` de la sesión. |
| `redirectTo` | `"/"` | String o `(payload) => string`. Solo mismo origen; si no, cae a `/`. |
| `cookieName` | `MC_SESSION_COOKIE` (`"mc_session"`) | Cambiarlo rompe `readIdentity` por defecto: evitarlo. |
| `secure` | `NODE_ENV === "production"` | Fuerza el flag `Secure`. |
| `onError` | — | `({ reason: "missing_secret" \| "invalid_token", serviceId, error? }) => void`, para logging. |

Respuestas: 303 + `Set-Cookie` (HttpOnly; SameSite=Lax; Path=/; Max-Age) si el token es
válido; 401 `{"error":"Token inválido o expirado"}`; 500
`{"error":"Configuración de servidor incompleta"}`. Nunca se expone el secreto ni el motivo
exacto del rechazo.

Con logging de `@ai4u/platform` se puede envolver igual que hoy:
`export const POST = withApiHandler(createMcAuthHandler({ ... }), { label: "POST mc-auth" })`.

## Leer la sesión

```ts
import { readMcSession } from "@ai4u/mc-sso"
const session = readMcSession(req, env.MISSION_CONTROL_SECRET)          // Request
const same    = readMcSession(req.headers.get("cookie"), secret)        // o el header Cookie
// → { tenantId, userId?, roles?, allowedModules?, displayName?, iat, exp } | null
```

En rutas API, `readIdentity` de `@ai4u/platform/auth` lee la misma cookie y el mismo formato.

### Atar la sesión a la app y al tenant (1.3.0)

`MISSION_CONTROL_SECRET` se comparte entre apps: **una firma válida no basta**. Pasa el
`serviceId` de tu app y, si la app es de un solo tenant, `allowedTenants`:

```ts
import { normalizeTenant } from "@ai4u/config/env"
const session = readMcSession(req, env.MISSION_CONTROL_SECRET, {
  serviceId:       SERVICE_ID,          // el mismo de createMcAuthHandler
  allowedTenants:  ["flexoimpresos"],   // solo apps de un tenant
  normalizeTenant,                      // opcional: resuelve alias ("flexo" → flexoimpresos)
})
```

| opción | default | |
|---|---|---|
| `serviceId` | — | Sesión emitida para otro servicio ⇒ `null`. Sin la opción no se valida la app. |
| `allowedTenants` | — | Tenant fuera de la lista ⇒ `null`. Lista vacía ⇒ rechaza todo. Sin normalizador compara sin mayúsculas/espacios. |
| `normalizeTenant` | — | `(id) => string` para comparar tenants (alias). Si lanza o da vacío ⇒ rechazada. |
| `acceptLegacy` | `true` (1.3.0) → `false` (1.4.0) | Sesiones sin `serviceId` (emitidas por ≤ 1.2.0). Con `false` se rechazan siempre. |
| `cookieName` | `MC_SESSION_COOKIE` | El 3er parámetro también puede ser este string (firma 1.2.0). |

`createMcAuthHandler` (1.3.0) ya guarda el `serviceId` en la sesión. Las sesiones viejas no
lo traen: por eso `acceptLegacy` es `true` en 1.3.0 (nadie se desloguea al desplegar) y pasa
a `false` en 1.4.0 (las sesiones duran 8 h, expiran solas).

## Guard de páginas (`proxy.ts`)

```ts
// proxy.ts (Next 16 — corre en runtime Node, necesario por node:crypto)
import { NextResponse, type NextRequest } from "next/server"
import { mcSessionGuard } from "@ai4u/mc-sso"
import { env } from "@/lib/env"

const guard = mcSessionGuard({
  getSecret: () => env.MISSION_CONTROL_SECRET,
  serviceId: SERVICE_ID,                                      // 1.3.0: rechaza sesiones de otras apps
  allowedTenants: ["flexoimpresos"],                          // 1.3.0: solo apps de un tenant (⇒ 403)
  publicPaths: ["/api/health", /^\/_next\//, "/favicon.ico"], // /api/mc-auth siempre es pública
  loginRedirect: env.MISSION_CONTROL_URL,                    // opcional; sin esto ⇒ 401
})

export function proxy(req: NextRequest) {
  return guard(req) ?? NextResponse.next()
}
```

`mcSessionGuard` devuelve `undefined` si el request puede seguir, o un `Response`: 500 si
falta el secreto (fail-closed), 403 si el tenant no está en `allowedTenants`, 307 a
`loginRedirect` o 401 si no hay sesión válida (una sesión de otro `serviceId` cuenta como
"sin sesión"). Acepta las mismas opciones `serviceId`/`allowedTenants`/`normalizeTenant`/`acceptLegacy`.
En Next 15 el `middleware.ts` corre en Edge por defecto y no tiene `node:crypto`: ahí usar
`export const config = { runtime: "nodejs" }` o validar en el layout/route handler.

## API de bajo nivel

- `createMcToken(tenantId, serviceId, displayName, secret, extra?)` — lo usa Mission Control.
- `verifyMcToken(token, serviceId, secret)` → `McTokenPayload | null`.
- `createSession(tenantId, secret, ttlMs = 8 h, extra?)` / `verifySession(token, secret)`.

Firmas HMAC-SHA256 en base64url; comparación en tiempo constante (`timingSafeEqual`).
