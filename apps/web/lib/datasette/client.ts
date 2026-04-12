import { DATASETTE_URL } from "../environment";
import {
    getCookieString,
    setCookiesFromResponse,
    deleteCookie,
} from "./cookies";
import { ensureCsrfToken } from "./csrf";
import { FORBIDDEN_STATUS, INTERNAL_SERVER_ERROR } from "@/lib/http";

export async function datasetteFetch(path: string, options: RequestInit = {}) {
    let res = await executeRequest(path, options);
    switch (res.status) {
        case FORBIDDEN_STATUS:
            /* One possible scenario is that the server has refreshed and the CSRF
             * token is no longer valid. */
            await deleteCookie("ds_csrftoken");
            res = await executeRequest(path, options);
            break;
        case INTERNAL_SERVER_ERROR:
            const body = await res.json();
            throw Error(body["error"]);
        default:
            break;
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
