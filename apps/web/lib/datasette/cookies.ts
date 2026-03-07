"use server";

import { cookies } from "next/headers";
import { parseSetCookie } from "cookie";

export async function setCookiesFromResponse(response: Response) {
    const cookieStore = await cookies();
    const rawCookies = response.headers.getSetCookie?.();
    for (const c of rawCookies) {
        const parsed = parseSetCookie(c);
        if (parsed.value === undefined) continue;
        cookieStore.set({
            name: parsed.name,
            value: parsed.value,
            path: parsed.path,
            domain: parsed.domain,
            expires: parsed.expires ? new Date(parsed.expires) : undefined,
            maxAge: parsed.maxAge,
            secure: parsed.secure,
            httpOnly: parsed.httpOnly,
            sameSite: parsed.sameSite as "lax" | "strict" | "none" | undefined,
        });
    }
}

export async function getCookieString() {
    const cookieStore = await cookies();
    const allCookies = cookieStore.getAll();
    return allCookies.map((c) => `${c.name}=${c.value}`).join("; ");
}
