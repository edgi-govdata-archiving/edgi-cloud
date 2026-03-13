import { DATASETTE_URL } from "../environment";
import {
    getCookieString,
    setCookiesFromResponse,
    deleteCookie,
} from "./cookies";
import { ensureCsrfToken } from "./csrf";
import { FORBIDDEN_STATUS } from "@/lib/http";

export async function datasetteFetch(path: string, options: RequestInit = {}) {
    let res = await executeRequest(path, options);
    if (res.status === FORBIDDEN_STATUS) {
        // One possible scenario is that the server has refreshed and the CSRF
        // token is no longer valid.
        await deleteCookie("ds_csrftoken");
        res = await executeRequest(path, options);
    }
    await setCookiesFromResponse(res);
    return res;
}

async function executeRequest(path: string, options: RequestInit) {
    const token = await ensureCsrfToken();
    const cookieString = await getCookieString();
    return fetch(`${DATASETTE_URL}${path}`, {
        ...options,
        headers: {
            "x-csrftoken": token,
            ...(options.headers || {}),
            cookie: cookieString,
        },
    });
}
