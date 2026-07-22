/**
 * Rastro de "quién está viendo como quién" cuando un superadmin de Mission
 * Control impersona a un usuario de un tenant. Viaja dentro de `extra` en
 * McTokenPayload/SessionPayload — nunca reemplaza al userId impersonado,
 * solo lo acompaña para que la app destino pueda auditar y mostrar el banner.
 */
export interface ImpersonationInfo {
    byAdminId: string;
    byAdminEmail: string;
    startedAt: number;
}
export declare function isImpersonationInfo(value: unknown): value is ImpersonationInfo;
//# sourceMappingURL=impersonation.d.ts.map