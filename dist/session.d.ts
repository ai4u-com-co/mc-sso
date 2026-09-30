/** TTL por defecto de la sesión local tras el handoff SSO: 8 h (ver FLX-091). */
export declare const DEFAULT_SESSION_TTL_MS: number;
/** Identidad+permisos opcionales que la sesión conserva tras el handoff SSO. */
export interface SessionExtra {
    userId?: string;
    roles?: string[];
    allowedModules?: string[] | null;
    displayName?: string;
}
export interface SessionPayload extends SessionExtra {
    tenantId: string;
    iat: number;
    exp: number;
}
export declare function createSession(tenantId: string, secret: string, ttlMs?: number, extra?: SessionExtra): string;
export declare function verifySession(token: string, secret: string): SessionPayload | null;
//# sourceMappingURL=session.d.ts.map