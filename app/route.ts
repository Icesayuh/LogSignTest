import { publishedJwks, recognizeRequired } from "@/lib/recognize/server";

// The public key Keyless uses to check our user-authorization tokens ("User Authorization JWKs URI").
export const dynamic = "force-dynamic";

export function GET(): Response {
  if (!recognizeRequired()) return new Response("Not found", { status: 404 });
  try {
    return Response.json(publishedJwks(), { headers: { "Cache-Control": "public, max-age=300" } });
  } catch (error) {
    console.error("Could not publish the Recognize JWKS:", error);
    return new Response("Not configured", { status: 503 });
  }
}
