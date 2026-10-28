import ipaddr from "ipaddr.js";
export class AppError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
  }
}
export function publicIP(value: string): boolean {
  try {
    const ip = ipaddr.parse(value);
    return (
      ip.range() === "unicast" &&
      (ip.kind() === "ipv4" ||
        (ip as ipaddr.IPv6).match(ipaddr.IPv6.parse("2000::"), 3))
    );
  } catch {
    return false;
  }
}
export function allowlist(value: string): string[] {
  return value
    .split(",")
    .map((h) => h.trim().toLowerCase())
    .filter(Boolean);
}
export function validateTarget(value: unknown, hosts: string[]): URL {
  if (typeof value !== "string" || value.length > 2048)
    throw new AppError(400, "Enter a valid target URL.");
  let u: URL;
  try {
    u = new URL(value);
  } catch {
    throw new AppError(400, "Enter a complete HTTP or HTTPS URL.");
  }
  if (
    !["https:", "http:"].includes(u.protocol) ||
    u.username ||
    u.password ||
    u.hash ||
    u.search ||
    u.port
  )
    throw new AppError(
      400,
      "Use HTTP or HTTPS on the standard port, without credentials, query strings or fragments.",
    );
  const h = u.hostname.toLowerCase();
  if (
    !/^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(
      h,
    ) ||
    h.endsWith(".local") ||
    h.endsWith(".internal") ||
    h.endsWith(".localhost") ||
    h.endsWith(".test") ||
    h === "metadata.google.internal" ||
    h === "instance-data.ec2.internal"
  )
    throw new AppError(400, "Only public DNS hostnames are supported.");
  if (!hosts.includes(h))
    throw new AppError(403, "Hostname is not in the server allowlist.");
  return u;
}
export function escapeHTML(s: string) {
  return s.replace(
    /[&<>"']/g,
    (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        c
      ]!,
  );
}
