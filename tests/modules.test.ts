import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import * as network from "../runner/network";
import { execute } from "../runner/modules";
const signal = () => new AbortController().signal;
const url = "https://owned.example/";
beforeEach(() => {
  vi.spyOn(network, "resolvePublic").mockResolvedValue({
    address: "93.184.216.34",
    family: 4,
  });
  vi.spyOn(network, "snapshot").mockResolvedValue({
    status: 200,
    headers: {},
    body: "",
    bytes: 0,
    duration: 12,
  });
});
afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllEnvs();
});
describe("network module outcome handling with explicitly synthetic responses", () => {
  it("reports missing headers as actionable observations", async () => {
    const r = await execute({ testId: "headers", url }, signal());
    expect(r.status).toBe("FAIL");
    expect(r.findings).toHaveLength(5);
    expect(r.findings[0].remediation).toContain("Content-Security-Policy");
  });
  it("reports PASS only when the checked headers are present and valid", async () => {
    vi.mocked(network.snapshot).mockResolvedValue({
      status: 200,
      headers: {
        "content-security-policy": "default-src 'self'",
        "strict-transport-security": "max-age=31536000",
        "x-content-type-options": "nosniff",
        "referrer-policy": "no-referrer",
        "permissions-policy": "camera=()",
      },
      body: "",
      bytes: 0,
      duration: 5,
    });
    const r = await execute({ testId: "headers", url }, signal());
    expect(r.status).toBe("PASS");
    expect(r.findings).toHaveLength(0);
  });
  it("never passes an HTTP error response", async () => {
    vi.mocked(network.snapshot).mockResolvedValue({
      status: 503,
      headers: {},
      body: "",
      bytes: 0,
      duration: 5,
    });
    const r = await execute({ testId: "headers", url }, signal());
    expect(r.status).toBe("ERROR");
    expect(r.summary).toContain("503");
  });
  it("marks absent cookies NOT TESTED", async () =>
    expect((await execute({ testId: "cookies", url }, signal())).status).toBe(
      "NOT TESTED",
    ));
  it("reports cookie flags without storing names or values", async () => {
    vi.mocked(network.snapshot).mockResolvedValue({
      status: 200,
      headers: {
        "set-cookie": [
          "secret_name=sensitive_cookie_value; Path=/; SameSite=None",
        ],
      },
      body: "",
      bytes: 0,
      duration: 5,
    });
    const r = await execute({ testId: "cookies", url }, signal());
    expect(r.status).toBe("FAIL");
    expect(JSON.stringify(r)).not.toContain("sensitive_cookie_value");
    expect(JSON.stringify(r)).not.toContain("secret_name");
    expect(r.findings).toHaveLength(2);
  });
  it("accepts appropriately flagged cookies", async () => {
    vi.mocked(network.snapshot).mockResolvedValue({
      status: 200,
      headers: {
        "set-cookie": ["session=synthetic; Secure; HttpOnly; SameSite=Lax"],
      },
      body: "",
      bytes: 0,
      duration: 5,
    });
    expect((await execute({ testId: "cookies", url }, signal())).status).toBe(
      "PASS",
    );
  });
  it("does not infer input safety from an unreflected marker", async () => {
    vi.stubEnv("INPUT_PATHS", "/security-test");
    const r = await execute(
      { testId: "input", url, inputPath: "/security-test" },
      signal(),
    );
    expect(r.status).toBe("WARNING");
    expect(r.findings[0].impact).toContain(
      "absence does not prove input safety",
    );
  });
  it("refuses input paths outside the independent runner policy", async () => {
    vi.stubEnv("INPUT_PATHS", "/security-test");
    await expect(
      execute({ testId: "input", url, inputPath: "/admin" }, signal()),
    ).rejects.toThrow("policy");
    expect(network.snapshot).not.toHaveBeenCalled();
  });
  it("marks unconfigured TCP assessment NOT TESTED", async () => {
    vi.stubEnv("ALLOWED_PORTS", "");
    expect((await execute({ testId: "ports", url }, signal())).status).toBe(
      "NOT TESTED",
    );
  });
  it("refuses broad TCP ranges", async () => {
    vi.stubEnv("ALLOWED_PORTS", "22,80");
    await expect(execute({ testId: "ports", url }, signal())).rejects.toThrow(
      "port policy",
    );
  });
  it("enforces the hard request cap", async () => {
    await expect(
      execute({ testId: "load", url, count: 6 }, signal()),
    ).rejects.toThrow("1–5");
    expect(network.snapshot).not.toHaveBeenCalled();
  });
  it("reports real bounded-request measurements", async () => {
    const r = await execute({ testId: "load", url, count: 1 }, signal());
    expect(r.status).toBe("PASS");
    expect(r.summary).toContain("mean 12 ms");
    expect(network.snapshot).toHaveBeenCalledTimes(1);
  });
  it("does not execute a pre-cancelled network job", async () => {
    const c = new AbortController();
    c.abort();
    await expect(
      execute({ testId: "headers", url }, c.signal),
    ).rejects.toThrow();
    expect(network.snapshot).not.toHaveBeenCalled();
  });
  it("preserves transport failures rather than manufacturing findings", async () => {
    vi.mocked(network.snapshot).mockRejectedValue(
      new Error("Synthetic transport failure"),
    );
    await expect(execute({ testId: "tls", url }, signal())).rejects.toThrow(
      "transport failure",
    );
  });
});
