import { describe, it, expect, vi, afterEach } from "vitest";
import { validateTarget, publicIP } from "../shared/validation";
import { authenticate } from "../server/security";
import { validateResult, reportHTML } from "../server/results";
import { finalStatus, type Result } from "../shared/models";
import { execute } from "../runner/modules";
import dns from "node:dns/promises";
import { resolvePublic } from "../runner/network";
const token = "test-only-operator-key-with-32-characters";
afterEach(() => vi.restoreAllMocks());
describe("target authorization and SSRF boundaries", () => {
  it("accepts only exact allowlist matches", () => {
    expect(
      validateTarget("https://owned.example/path", ["owned.example"]).hostname,
    ).toBe("owned.example");
    expect(() =>
      validateTarget("https://sub.owned.example", ["owned.example"]),
    ).toThrow("allowlist");
  });
  it.each([
    "file:///etc/passwd",
    "ftp://owned.example",
    "http://localhost",
    "http://127.0.0.1",
    "http://[::1]",
    "http://2130706433",
    "http://169.254.169.254",
    "https://metadata.google.internal",
    "https://user:password@owned.example",
    "https://owned.example:8443",
    "https://owned.example/?next=evil",
    "https://owned.example/#fragment",
    "https://owned.example.evil.com",
    "https://owned.example.",
  ])("rejects unsafe URL %s", (u) =>
    expect(() => validateTarget(u, ["owned.example"])).toThrow(),
  );
  it.each([
    "127.0.0.1",
    "0.0.0.0",
    "10.0.0.1",
    "172.16.0.1",
    "192.168.1.1",
    "169.254.169.254",
    "100.64.0.1",
    "198.18.0.1",
    "224.0.0.1",
    "192.0.0.9",
    "192.88.99.1",
    "::1",
    "::",
    "fc00::1",
    "fe80::1",
    "::ffff:127.0.0.1",
    "2001:db8::1",
    "64:ff9b::a00:1",
    "64:ff9b:1::a00:1",
  ])("rejects nonpublic address %s", (ip) => expect(publicIP(ip)).toBe(false));
  it("accepts ordinary public addresses", () => {
    expect(publicIP("93.184.216.34")).toBe(true);
    expect(publicIP("2606:4700:4700::1111")).toBe(true);
  });
  it("rejects a hostname with mixed public and private answers", async () => {
    vi.spyOn(dns, "lookup").mockResolvedValue([
      { address: "93.184.216.34", family: 4 },
      { address: "10.0.0.1", family: 4 },
    ] as never);
    await expect(resolvePublic("owned.example")).rejects.toThrow("not public");
  });
  it("revalidates DNS for each connection", async () => {
    const lookup = vi
      .spyOn(dns, "lookup")
      .mockResolvedValueOnce([{ address: "93.184.216.34", family: 4 }] as never)
      .mockResolvedValueOnce([{ address: "127.0.0.1", family: 4 }] as never);
    await resolvePublic("owned.example");
    await expect(resolvePublic("owned.example")).rejects.toThrow();
    expect(lookup).toHaveBeenCalledTimes(2);
  });
});
describe("operator authentication", () => {
  it("accepts the configured secret", async () => {
    await expect(
      authenticate(
        new Request("https://panel.example", {
          headers: { Authorization: `Bearer ${token}` },
        }),
        token,
      ),
    ).resolves.toBeUndefined();
  });
  it.each([undefined, "", "Bearer incorrect-token"])(
    "rejects absent or incorrect credentials",
    async (auth) => {
      await expect(
        authenticate(
          new Request("https://panel.example", {
            headers: auth ? { Authorization: auth } : {},
          }),
          token,
        ),
      ).rejects.toThrow("Invalid access token");
    },
  );
  it("fails closed when not configured", async () => {
    await expect(
      authenticate(new Request("https://panel.example"), undefined),
    ).rejects.toThrow("not configured");
  });
});
describe("honest result and report handling", () => {
  const result: Result = {
    testId: "headers",
    status: "NOT TESTED",
    startedAt: new Date().toISOString(),
    endedAt: new Date().toISOString(),
    findings: [],
    summary: "No observations available.",
  };
  it("preserves skipped and error outcomes", () => {
    for (const status of ["ERROR", "NOT TESTED"])
      expect(validateResult({ ...result, status }, "headers").status).toBe(
        status,
      );
  });
  it("rejects malformed and mismatched results", () => {
    expect(() =>
      validateResult({ ...result, testId: "tls" }, "headers"),
    ).toThrow();
    expect(() =>
      validateResult({ ...result, status: "SUCCESS" }, "headers"),
    ).toThrow();
    expect(() =>
      validateResult({ ...result, findings: [{}] }, "headers"),
    ).toThrow();
  });
  it("refuses success with actionable findings", () =>
    expect(() =>
      validateResult(
        {
          ...result,
          status: "PASS",
          findings: [
            {
              title: "Issue",
              severity: "high",
              endpoint: "https://owned.example",
              evidence: "x",
              impact: "x",
              remediation: "x",
            },
          ],
        },
        "headers",
      ),
    ).toThrow("inconsistent"));
  it("maps real findings to the proper outcome", () => {
    expect(finalStatus([])).toBe("PASS");
    expect(finalStatus([{ severity: "medium" } as never])).toBe("FAIL");
    expect(finalStatus([{ severity: "info" } as never])).toBe("WARNING");
  });
  it("escapes untrusted report content", () => {
    const html = reportHTML([
      {
        id: "x",
        status: "ERROR",
        started_at: "now",
        result: { ...result, summary: "<script>alert(1)</script>" },
      },
    ]);
    expect(html).not.toContain("<script>");
    expect(html).toContain("&lt;script&gt;");
  });
  it("runs real isolated SQL queries on synthetic data", async () => {
    const result = await execute(
      { testId: "sql", labCase: "injection" },
      new AbortController().signal,
    );
    expect(result.status).toBe("WARNING");
    expect(result.summary).toContain(
      "Vulnerable query returned 3 rows; parameterized query returned 0 rows",
    );
  });
});
