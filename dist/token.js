"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.createMcToken = createMcToken;
exports.verifyMcToken = verifyMcToken;
const node_crypto_1 = require("node:crypto");
const crypto_1 = require("./crypto");
const impersonation_1 = require("./impersonation");
function createMcToken(tenantId, serviceId, displayName, secret, extra = {}) {
    const data = {
        tenantId,
        serviceId,
        displayName,
        ...extra,
        exp: Date.now() + 5 * 60 * 1000,
    };
    const payload = Buffer.from(JSON.stringify(data)).toString("base64url");
    return `${payload}.${(0, crypto_1.sign)(payload, secret)}`;
}
function verifyMcToken(token, serviceId, secret) {
    if (!token || !secret)
        return null;
    const dot = token.lastIndexOf(".");
    if (dot === -1)
        return null;
    const payload = token.slice(0, dot);
    const sig = token.slice(dot + 1);
    const expected = (0, crypto_1.sign)(payload, secret);
    try {
        const a = Buffer.from(sig, "base64url");
        const b = Buffer.from(expected, "base64url");
        if (a.length !== b.length || !(0, node_crypto_1.timingSafeEqual)(a, b))
            return null;
    }
    catch {
        return null;
    }
    try {
        const data = JSON.parse(Buffer.from(payload, "base64url").toString());
        if (typeof data.tenantId !== "string" ||
            typeof data.serviceId !== "string" ||
            typeof data.displayName !== "string" ||
            typeof data.exp !== "number")
            return null;
        if (data.exp < Date.now())
            return null;
        if (data.serviceId !== serviceId)
            return null;
        if (data.impersonation !== undefined && !(0, impersonation_1.isImpersonationInfo)(data.impersonation))
            return null;
        return data;
    }
    catch {
        return null;
    }
}
