import { ReadonlyRequestCookies } from "next/dist/server/web/spec-extension/adapters/request-cookies";
import { cookies } from "next/headers";
import { DATASETTE_URL } from "../environment";
import { setCookiesFromResponse } from "./cookies";

export async function ensureCsrfToken() {
    const cookieStore = await cookies();
    const existing = getCsrfTokenFromCookies(cookieStore);
    if (existing) {
        return existing;
    }
    // We need to use a regular request here, instead of datasetteFetch to
    // avoid infinite recursion when fetching the CSRF token itself.
    const res = await fetch(`${DATASETTE_URL}/csrf`, {
        method: "GET",
    });
    await setCookiesFromResponse(res);
    const token = getCsrfTokenFromCookies(cookieStore);
    if (!token) {
        throw new Error("Failed to obtain Datasette CSRF token");
    }
    return token;
}

function getCsrfTokenFromCookies(cookieStore: ReadonlyRequestCookies) {
    return cookieStore.get("ds_csrftoken")?.value;
}
