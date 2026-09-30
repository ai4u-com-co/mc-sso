"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.DEFAULT_SESSION_TTL_MS = void 0;
exports.createSession = createSession;
exports.verifySession = verifySession;
const node_crypto_1 = require("node:crypto");
const crypto_1 = require("./crypto");
/** TTL por defecto de la sesión local tras el handoff SSO: 8 h (ver FLX-091). */
exports.DEFAULT_SESSION_TTL_MS = 8 * 60 * 60 * 1000;
function createSession(tenantId, secret, ttlMs = exports.DEFAULT_SESSION_TTL_MS, extra = {}) {
    const now = Date.now();
    const data = { tenantId, ...extra, iat: now, exp: now + ttlMs };
    const payload = Buffer.from(JSON.stringify(data)).toString("base64url");
    return `${payload}.${(0, crypto_1.sign)(payload, secret)}`;
}
function verifySession(token, secret) {
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
            typeof data.iat !== "number" ||
            typeof data.exp !== "number")
            return null;
        if (data.exp < Date.now())
            return null;
        return data;
    }
    catch {
        return null;
    }
}
