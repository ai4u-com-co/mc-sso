# Changelog — @ai4u/mc-sso

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
