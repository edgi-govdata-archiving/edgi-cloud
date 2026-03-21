"use server";

import { datasetteFetch } from "@/lib/datasette/client";
import { getEmptyLoginState, loginSchema, LoginState } from "./schema";
import { z } from "zod";
import { UNAUTHORIZED_STATUS } from "@/lib/http";
import { getUser } from "@/lib/auth";

export async function login(
    _prev: LoginState,
    formData: FormData,
): Promise<LoginState> {
    const parsed = loginSchema.safeParse(Object.fromEntries(formData));
    if (!parsed.success) {
        const { fieldErrors, formErrors } = z.flattenError(parsed.error);
        return {
            ...getEmptyLoginState(),
            fieldErrors: {
                username:
                    fieldErrors.username?.map((m) => ({ message: m })) ?? [],
                password:
                    fieldErrors.password?.map((m) => ({ message: m })) ?? [],
            },
            formError: formErrors[0],
            values: Object.fromEntries(formData) as {
                username: string;
                password: string;
            },
        };
    }

    const { username, password } = parsed.data;
    const res = await datasetteFetch(`/resette/login`, {
        method: "POST",
        credentials: "include",
        body: JSON.stringify({ username, password }),
    });
    const data = await res.json();
    if (res.status === UNAUTHORIZED_STATUS) {
        return { ...getEmptyLoginState(), formError: data.error };
    }

    const user = await getUser();
    const redirectTo = data?.redirectTo || "";

    return { ...getEmptyLoginState(), user, redirectTo };
}
