import { NextResponse } from "next/server";
import { API_BASE_URL } from "@/lib/api";

/**
 * Fallback bridge for Google OAuth callback registered under the frontend origin:
 * https://hrhiringloop.vercel.app/api/auth/callback/google
 *
 * Forwards code, state, and error parameters directly to the backend OAuth handler:
 * https://hrhiringloopbackend.vercel.app/auth/google/callback
 */
export async function GET(request: Request) {
  const { search } = new URL(request.url);
  return NextResponse.redirect(`${API_BASE_URL}/auth/google/callback${search}`);
}
