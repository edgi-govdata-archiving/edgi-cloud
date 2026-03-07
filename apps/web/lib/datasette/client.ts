import { DATASETTE_URL } from "../environment";
import { getCookieString, setCookiesFromResponse } from "./cookies";
import { ensureCsrfToken } from "./csrf";

export async function datasetteFetch(path: string, options: RequestInit = {}) {
    const token = await ensureCsrfToken();
    const cookieString = await getCookieString();
    const res = await fetch(`${DATASETTE_URL}${path}`, {
        ...options,
        headers: {
            "x-csrftoken": token,
            ...(options.headers || {}),
            cookie: cookieString,
        },
    });
    if (!res.ok) {
        throw new Error(`Datasette request failed: ${res.status}`);
    }
    await setCookiesFromResponse(res);
    return res;
}
