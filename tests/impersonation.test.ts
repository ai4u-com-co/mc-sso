import { describe, it, expect, vi, beforeEach } from "vitest"
import { createMcToken, verifyMcToken } from "../src/token"
import { createSession, verifySession } from "../src/session"
import { isImpersonationInfo } from "../src/impersonation"

const SECRET  = "test-secret-key"
const TENANT  = "flexoimpresos"
const SERVICE = "sapb1chat"
const DISPLAY = "Flexo"

const IMPERSONATION = {
  byAdminId:    "admin-1",
  byAdminEmail: "mgarciap333@gmail.com",
  startedAt:    Date.parse("2026-01-01T00:00:00Z"),
}

describe("isImpersonationInfo", () => {
  it("accepts a well-formed object", () => {
    expect(isImpersonationInfo(IMPERSONATION)).toBe(true)
  })

  it("rejects missing fields", () => {
    expect(isImpersonationInfo({ byAdminId: "admin-1" })).toBe(false)
  })

  it("rejects wrong types", () => {
    expect(isImpersonationInfo({ ...IMPERSONATION, startedAt: "not-a-number" })).toBe(false)
  })

  it("rejects non-objects", () => {
    expect(isImpersonationInfo(null)).toBe(false)
    expect(isImpersonationInfo("string")).toBe(false)
  })
})

describe("mc token con impersonation", () => {
  beforeEach(() => {
    vi.useFakeTimers()
    vi.setSystemTime(new Date("2026-01-01T00:00:00Z"))
  })

  it("embebe y devuelve impersonation intacta", () => {
    const token = createMcToken(TENANT, SERVICE, DISPLAY, SECRET, {
      userId: "target-user",
      impersonation: IMPERSONATION,
    })
    const result = verifyMcToken(token, SERVICE, SECRET)
    expect(result).not.toBeNull()
    expect(result!.impersonation).toEqual(IMPERSONATION)
  })

  it("retrocompatible: sin impersonation, queda undefined", () => {
    const token  = createMcToken(TENANT, SERVICE, DISPLAY, SECRET, { userId: "u-1" })
    const result = verifyMcToken(token, SERVICE, SECRET)
    expect(result!.impersonation).toBeUndefined()
  })

  it("rechaza un payload con impersonation malformada (tenant firmó otra shape)", () => {
    const token = createMcToken(TENANT, SERVICE, DISPLAY, SECRET, {
      // @ts-expect-error - forzamos una forma inválida a propósito
      impersonation: { byAdminId: "admin-1" },
    })
    expect(verifyMcToken(token, SERVICE, SECRET)).toBeNull()
  })
})

describe("session con impersonation", () => {
  beforeEach(() => {
    vi.useFakeTimers()
    vi.setSystemTime(new Date("2026-01-01T00:00:00Z"))
  })

  it("embebe y devuelve impersonation intacta", () => {
    const token  = createSession(TENANT, SECRET, undefined, {
      userId: "target-user",
      impersonation: IMPERSONATION,
    })
    const result = verifySession(token, SECRET)
    expect(result).not.toBeNull()
    expect(result!.impersonation).toEqual(IMPERSONATION)
  })

  it("rechaza una sesión con impersonation malformada", () => {
    const token = createSession(TENANT, SECRET, undefined, {
      // @ts-expect-error - forzamos una forma inválida a propósito
      impersonation: { byAdminEmail: "x@y.com" },
    })
    expect(verifySession(token, SECRET)).toBeNull()
  })
})
