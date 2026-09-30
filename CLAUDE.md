# CLAUDE.md — @ai4u/mc-sso

## Qué es
Paquete TypeScript `@ai4u/mc-sso` (v1.3.0): protocolo SSO entre Mission Control (MC) y los módulos del
ecosistema superAI. MC firma un mc-token de 5 min; el módulo lo canjea en `/api/mc-auth` por una cookie
de sesión `mc_session` (8 h). Repo PÚBLICO: documentación y PRs sin secretos ni infraestructura interna.

## Stack
TypeScript 5, vitest 2, sin dependencias de runtime (usa `node:crypto`, por eso requiere runtime Node, no Edge).
CI con Node 22. Pensado para Next App Router (handler estándar `Request → Response`), pero no depende de Next.

## Comandos (package.json)
- `npm ci` / `npm install`
- `npm run type-check` (tsc --noEmit)
- `npm test` (vitest run)
- `npm run build` (tsc → `dist/`)

## Estructura
- `src/token.ts`: `createMcToken`, `verifyMcToken` (firma HMAC-SHA256 base64url, `exp` = ahora + 5 min).
- `src/session.ts`: `createSession`, `verifySession`, `DEFAULT_SESSION_TTL_MS` (8 h).
- `src/handler.ts`: `createMcAuthHandler`, `readMcSession`, `mcSessionGuard`, `MC_SESSION_COOKIE`.
- `src/crypto.ts`: `sign` interno. `src/index.ts`: API pública.
- `tests/` (token, session, handler, scope), `dist/` (build commiteado), `CHANGELOG.md`.

## Convenciones y trampas
- **`dist/` se commitea.** El CI corre type-check, test y build y falla si `git diff -- dist` no está
  limpio. Tras tocar `src/`, correr `npm run build` y commitear `dist/`.
- **Seguridad (fail-closed):** sin secreto ⇒ 500 genérico; token inválido/vencido/de otro `serviceId` ⇒
  401 genérico. Nunca exponer el secreto ni el motivo exacto del rechazo. Comparación de firmas con
  `timingSafeEqual`; no reemplazar por `===`.
- `redirectTo` del handler solo admite mismo origen; si no, cae a `/`.
- La cookie (HttpOnly, SameSite=Lax, Path=/) usa `Max-Age = ttlMs/1000`, alineado con el `exp` de la sesión.
  `Secure` se activa si `NODE_ENV === "production"`.
- Cambiar `cookieName` rompe `readIdentity` de `@ai4u/platform/auth` (lee la misma cookie y formato): evitarlo.
- Campos opcionales del token/sesión (`userId`, `roles`, `allowedModules`) deben seguir siendo opcionales
  para no romper verificadores existentes. No cambiar el formato de token/sesión sin versión mayor.
- `mcSessionGuard` para `proxy.ts` (Next 16, runtime Node). En Next 15 el `middleware.ts` corre en Edge
  y no tiene `node:crypto`: usar runtime nodejs o validar en layout/route handler.
- **La firma sola no basta** (el secreto se comparte entre apps): desde 1.3.0 la sesión lleva
  `serviceId` y `readMcSession`/`mcSessionGuard` aceptan `serviceId`/`allowedTenants`/`acceptLegacy`.
  `acceptLegacy` (sesiones sin `serviceId`) es `true` en 1.3.0 y debe pasar a `false` en 1.4.0.
- Multitenant: el token y la sesión llevan `tenantId`; quien consuma la sesión debe filtrar permisos y
  queries por ese tenant. No hardcodear tenants.

## Variables de entorno
El paquete solo lee `NODE_ENV`. Las apps consumidoras le pasan el secreto (en el README aparece
`MISSION_CONTROL_SECRET` y, opcionalmente, `MISSION_CONTROL_URL` para `loginRedirect`); el `serviceId`
debe coincidir con el que firma MC. Nunca commitear valores.

## Publicación y rama default
- Rama default: `master`. No hay `npm publish`: los consumidores instalan por tag de GitHub,
  `@ai4u/mc-sso@github:ai4u-com-co/mc-sso#vX.Y.Z`.
- Según el README, la fuente de verdad es el monorepo `ai4u-com-co/kernel` (`packages/mc-sso`) y este
  repo es un espejo que se publica al taggear `mc-sso-vX.Y.Z` en kernel. Por confirmar: si se acepta
  contribuir directo aquí o solo vía kernel.
- Al subir versión: `package.json`, `CHANGELOG.md`, ejemplo de instalación del README, rebuild de `dist/`.
