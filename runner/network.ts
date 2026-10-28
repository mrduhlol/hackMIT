import dns from "node:dns/promises";
import http from "node:http";
import https from "node:https";
import { publicIP, AppError } from "../shared/validation";
export async function resolvePublic(host: string) {
  const addresses = await Promise.race([
    dns.lookup(host, { all: true, verbatim: true }),
    new Promise<never>((_, reject) => {
      const timer = setTimeout(
        () => reject(new AppError(504, "DNS resolution timed out.")),
        3000,
      );
      timer.unref();
    }),
  ]);
  if (!addresses.length || addresses.some((a) => !publicIP(a.address)))
    throw new AppError(400, "DNS destination is not public.");
  return addresses[0];
}
export interface Snapshot {
  status: number;
  headers: http.IncomingHttpHeaders;
  body: string;
  bytes: number;
  duration: number;
  tls?: { authorized: boolean; validTo: string; protocol: string };
}
// No proxy environment, redirect following, connection pooling, or second DNS lookup.
export async function snapshot(
  url: URL,
  signal: AbortSignal,
  body = false,
): Promise<Snapshot> {
  const address = await resolvePublic(url.hostname);
  signal.throwIfAborted();
  return new Promise((resolve, reject) => {
    const started = performance.now();
    const transport = url.protocol === "https:" ? https : http;
    const req = transport.request(
      url,
      {
        method: body ? "GET" : "HEAD",
        agent: false,
        signal,
        family: address.family,
        rejectUnauthorized: true,
        lookup: (_h, _o, cb) => cb(null, address.address, address.family),
        headers: {
          "User-Agent": "Sentinel-Authorized-Audit/1.0",
          Accept: "text/html",
          "Accept-Encoding": "identity",
        },
      },
      (res) => {
        if ((res.statusCode || 0) >= 300 && (res.statusCode || 0) < 400) {
          res.destroy();
          reject(
            new AppError(
              400,
              "Redirect refused. Register the final hostname and URL explicitly.",
            ),
          );
          return;
        }
        const sock = res.socket as import("node:tls").TLSSocket;
        const tls =
          url.protocol === "https:"
            ? {
                authorized: !!sock.authorized,
                validTo: sock.getPeerCertificate()?.valid_to || "Unavailable",
                protocol: sock.getProtocol() || "Unavailable",
              }
            : undefined;
        let size = 0;
        const chunks: Buffer[] = [];
        res.on("data", (chunk: Buffer) => {
          size += chunk.length;
          if (size > 65536) {
            res.destroy(
              new AppError(400, "Response exceeds the 64 KiB safety limit."),
            );
            return;
          }
          if (body) chunks.push(chunk);
        });
        res.on("error", reject);
        res.on("end", () => {
          resolve({
            status: res.statusCode || 0,
            headers: res.headers,
            body: Buffer.concat(chunks).toString("utf8"),
            bytes: size,
            duration: Math.round(performance.now() - started),
            tls,
          });
        });
      },
    );
    const deadline = setTimeout(
      () => req.destroy(new Error("Request deadline exceeded.")),
      5000,
    );
    req.on("close", () => clearTimeout(deadline));
    req.on("error", reject);
    req.end();
  });
}
