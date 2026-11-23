import { userAuthorizationJwks } from "@/lib/auth/recognize";

// The public half of the key that signs the Recognize "user authorization" tokens (see lib/auth/recognize.ts).
// Keyless fetches this when the tenant's User Authorization is set to RemoteJWKSet. Public keys only.
export const dynamic = "force-dynamic";

export function GET(): Response {
  const jwks = userAuthorizationJwks();
  if (!jwks) return new Response("Not found", { status: 404 });
  return Response.json(jwks, { headers: { "Cache-Control": "public, max-age=300" } });
}
