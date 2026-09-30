# Changelog — @ai4u/mc-sso

## 1.3.0

Sesiones atadas a la app y al tenant. `MISSION_CONTROL_SECRET` (con el que se firma
`mc_session`) se comparte entre apps, así que hasta 1.2.0 una sesión válida de una app
servía en otra copiando la cookie, y las apps de un solo tenant no validaban el tenant.
Compatible hacia atrás: sin las opciones nuevas todo se comporta como en 1.2.0.

- `createMcAuthHandler` guarda en la sesión el `serviceId` para el que se emitió
  (`SessionExtra.serviceId?`, opcional: el formato sigue siendo el mismo y los verificadores
  1.2.0 — incluido `readIdentity` de `@ai4u/platform` — leen la sesión nueva sin cambios).
- `readMcSession(source, secret, opts?)`: el 3er parámetro acepta el string de 1.2.0
  (nombre de la cookie) o `{ cookieName?, serviceId?, allowedTenants?, normalizeTenant?, acceptLegacy? }`.
  Sesión de otro `serviceId` ⇒ `null`; tenant fuera de `allowedTenants` ⇒ `null`
  (lista vacía ⇒ rechaza todo; `normalizeTenant` opcional para alias, p. ej. el de `@ai4u/config/env`).
- `mcSessionGuard({ ..., serviceId?, allowedTenants?, normalizeTenant?, acceptLegacy? })`:
  mismas reglas; tenant no permitido ⇒ **403** `{"error":"Acceso denegado"}`; sesión de otra
  app o legacy rechazada ⇒ como sin sesión (401 o 307 a `loginRedirect`).
- Sesiones legacy (sin `serviceId`, emitidas por ≤ 1.2.0): `acceptLegacy` default `true` en
  1.3.0 para no desloguear a nadie al desplegar. **En 1.4.0 el default pasa a `false`**: las
  sesiones duran 8 h, así que a más tardar 8 h después de desplegar 1.3.0 ya no queda ninguna.
- Nuevos tipos exportados: `ReadMcSessionOptions`, `McSessionScope`.

## 1.2.0

Receptor SSO estándar: reemplaza las ~12 copias manuales de `/api/mc-auth` (8 nombres de
cookie, TTL 1 h vs 8 h) por una sola implementación probada. Sin cambios en la API
existente (`createMcToken`, `verifyMcToken`, `createSession`, `verifySession`) ni en el
formato del token/sesión.

- `MC_SESSION_COOKIE = "mc_session"` y `DEFAULT_SESSION_TTL_MS` (8 h, el mismo default que ya
  usaba `createSession`).
- `createMcAuthHandler(opts)` → `(req: Request) => Promise<Response>`: lee `token` del form,
  lo verifica contra `serviceId`, emite la cookie de sesión (HttpOnly, SameSite=Lax, Path=/,
  Max-Age = ttl, Secure en producción) y responde 303. Token inválido/vencido/de otro
  servicio → 401 genérico; secreto ausente → 500 genérico (fail-closed). `redirectTo` acepta
  string o función del payload, restringido al mismo origen.
- `readMcSession(reqOCookieHeader, secret, cookieName?)` → `SessionPayload | null`.
- `mcSessionGuard({ secret | getSecret, publicPaths, loginRedirect?, cookieName? })` para
  `proxy.ts` / middleware.
- Compatible con `readIdentity` de `@ai4u/platform` (test de interoperabilidad en kernel).

## 1.1.0

- Identidad + permisos opcionales (`userId`, `roles`, `allowedModules`, `displayName`) en
  token y sesión.
