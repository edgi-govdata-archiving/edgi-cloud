"use server";

import { cookies } from "next/headers";
import { redirect } from "next/navigation";

export type User = {
    id: string;
    name: string;
    role: string;
    username: string;
    mustChangePassword: boolean;
};

export async function getUser(): Promise<User | null> {
    const cookieStore = await cookies();
    const ds_actor_cookie = cookieStore.get("ds_actor");
    if (!ds_actor_cookie?.value) {
        return null;
    }

    try {
        const json = Buffer.from(ds_actor_cookie.value, "base64").toString(
            "utf-8",
        );
        const user = JSON.parse(json) as User;
        return user;
    } catch {
        return null;
    }
}

export async function requireUser(): Promise<User> {
    const user = await getUser();
    if (!user) {
        redirect("/login");
    }
    return user;
}
