import { z } from "zod";
import type { User } from "@/lib/auth";

export const loginSchema = z.object({
    username: z.string().trim().min(1, "Username is required"),
    password: z.string().min(1, "Password is required"),
});

export type LoginInput = z.infer<typeof loginSchema>;

export type LoginState = {
    fieldErrors: {
        username: Array<{ message: string }>;
        password: Array<{ message: string }>;
    };
    formError: string;
    values: { username: string; password: string };
    user: User | null;
    redirectTo: string;
};

export function getEmptyLoginState(): LoginState {
    return {
        fieldErrors: { username: [], password: [] },
        formError: "",
        values: { username: "", password: "" },
        user: null,
        redirectTo: "",
    };
}
