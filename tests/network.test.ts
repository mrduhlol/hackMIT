import { describe, it, expect, vi, afterEach } from "vitest";
import { EventEmitter } from "node:events";
import { PassThrough } from "node:stream";
import dns from "node:dns/promises";
import https from "node:https";
import { snapshot } from "../runner/network";
afterEach(() => vi.restoreAllMocks());
function transport(status: number, body: Buffer = Buffer.alloc(0)) {
  vi.spyOn(dns, "lookup").mockResolvedValue([
    { address: "93.184.216.34", family: 4 },
  ] as never);
  const request = vi.spyOn(https, "request");
  request.mockImplementation(((
    url: URL,
    options: https.RequestOptions,
    callback: (r: unknown) => void,
  ) => {
    const req = new EventEmitter() as EventEmitter & {
      end: () => void;
      destroy: (e: Error) => void;
    };
    req.end = () =>
      queueMicrotask(() => {
        const response = new PassThrough() as PassThrough & {
          statusCode: number;
          headers: Record<string, string>;
          socket: unknown;
        };
        response.statusCode = status;
        response.headers = { location: "http://169.254.169.254/" };
        response.socket = {
          authorized: true,
          getPeerCertificate: () => ({ valid_to: "Jan 01 2030 GMT" }),
          getProtocol: () => "TLSv1.3",
        };
        callback(response);
        if (!response.destroyed) response.end(body);
        req.emit("close");
      });
    req.destroy = (e) => req.emit("error", e);
    return req;
  }) as never);
  return request;
}
describe("pinned HTTP transport using synthetic sockets", () => {
  it("connects through the validated address and preserves the original hostname", async () => {
    const request = transport(200);
    const url = new URL("https://owned.example/");
    const r = await snapshot(url, new AbortController().signal);
    expect(r.status).toBe(200);
    expect(r.tls?.authorized).toBe(true);
    expect(request.mock.calls[0][0]).toEqual(url);
    const options = request.mock.calls[0][1] as https.RequestOptions;
    expect(options.family).toBe(4);
    expect(options.rejectUnauthorized).toBe(true);
    expect(options.agent).toBe(false);
    const callback = vi.fn();
    (options.lookup as Function)("owned.example", {}, callback);
    expect(callback).toHaveBeenCalledWith(null, "93.184.216.34", 4);
  });
  it("refuses redirects without contacting their destination", async () => {
    const request = transport(302);
    await expect(
      snapshot(new URL("https://owned.example"), new AbortController().signal),
    ).rejects.toThrow("Redirect refused");
    expect(request).toHaveBeenCalledTimes(1);
  });
  it("enforces the response body bound for input probes", async () => {
    transport(200, Buffer.alloc(65537));
    await expect(
      snapshot(
        new URL("https://owned.example"),
        new AbortController().signal,
        true,
      ),
    ).rejects.toThrow("64 KiB");
  });
  it("never opens a connection after unsafe resolution", async () => {
    const request = transport(200);
    vi.mocked(dns.lookup).mockResolvedValue([
      { address: "169.254.169.254", family: 4 },
    ] as never);
    await expect(
      snapshot(new URL("https://owned.example"), new AbortController().signal),
    ).rejects.toThrow("not public");
    expect(request).not.toHaveBeenCalled();
  });
});
