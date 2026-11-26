import { NextResponse } from "next/server";
import { API_BASE_URL } from "@/lib/api";

export async function GET() {
  try {
    const authUrl = `${API_BASE_URL}/auth/google`;
    return NextResponse.json({ url: authUrl });
  } catch (error) {
    return NextResponse.json(
      { detail: "Failed to connect to authentication service" },
      { status: 500 }
    );
  }
}
