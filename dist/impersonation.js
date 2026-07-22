"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.isImpersonationInfo = isImpersonationInfo;
function isImpersonationInfo(value) {
    if (typeof value !== "object" || value === null)
        return false;
    const v = value;
    return (typeof v.byAdminId === "string" &&
        typeof v.byAdminEmail === "string" &&
        typeof v.startedAt === "number");
}
