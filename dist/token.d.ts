import { type ImpersonationInfo } from "./impersonation";
/**
 * Datos de identidad+permisos que Mission Control embebe en el token durante el
 * handoff, para que la app receptora conozca al usuario sin tocar la BD.
 * Todos opcionales ⇒ retrocompatible con los verificadores existentes.
 */
export interface McTokenExtra {
    userId?: string;
    roles?: string[];
    allowedModules?: string[] | null;
    impersonation?: ImpersonationInfo;
}
export interface McTokenPayload extends McTokenExtra {
    tenantId: string;
    serviceId: string;
    displayName: string;
    exp: number;
}
export declare function createMcToken(tenantId: string, serviceId: string, displayName: string, secret: string, extra?: McTokenExtra): string;
export declare function verifyMcToken(token: string, serviceId: string, secret: string): McTokenPayload | null;
//# sourceMappingURL=token.d.ts.map