import { AppError } from "../shared/validation";
export async function authenticate(
  request: Request,
  token: string | undefined,
) {
  if (!token || token.length < 32)
    throw new AppError(503, "Authentication is not configured on the server.");
  const value =
    request.headers.get("Authorization")?.match(/^Bearer (.+)$/)?.[1] || "";
  const enc = new TextEncoder();
  const algorithm = { name: "HMAC", hash: "SHA-256" };
  const expected = await crypto.subtle.importKey(
    "raw",
    enc.encode(token),
    algorithm,
    false,
    ["sign"],
  );
  const provided = await crypto.subtle.importKey(
    "raw",
    enc.encode(value || "empty"),
    algorithm,
    false,
    ["verify"],
  );
  const signature = await crypto.subtle.sign(
    algorithm,
    expected,
    enc.encode("sentinel-auth-v1"),
  );
  if (
    !(await crypto.subtle.verify(
      algorithm,
      provided,
      signature,
      enc.encode("sentinel-auth-v1"),
    ))
  )
    throw new AppError(401, "Invalid access token.");
}
export async function boundedJSON(
  request: Request | Response,
  limit = 8192,
): Promise<Record<string, unknown>> {
  const reader = request.body?.getReader();
  if (!reader) throw new AppError(400, "JSON body required.");
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      size += value.length;
      if (size > limit)
        throw new AppError(413, "Request exceeds safety limit.");
      chunks.push(value);
    }
  } finally {
    await reader.cancel();
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.length;
  }
  let data: unknown;
  try {
    data = JSON.parse(new TextDecoder().decode(bytes));
  } catch {
    throw new AppError(400, "Invalid JSON body.");
  }
  if (!data || typeof data !== "object" || Array.isArray(data))
    throw new AppError(400, "JSON object required.");
  return data as Record<string, unknown>;
}
