"use client";

import { cn } from "@/lib/utils";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { AlertCircleIcon, Eye, EyeOff } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
    Field,
    FieldError,
    FieldGroup,
    FieldLabel,
} from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { login } from "./actions";
import { useActionState, useEffect, useState } from "react";
import { getEmptyLoginState, LoginState } from "./schema";
import { useAuth } from "@/hooks/use-auth";
import { useRouter } from "next/navigation";

const initialState: LoginState = getEmptyLoginState();

export function LoginForm({
    className,
    ...props
}: React.ComponentProps<"form">) {
    const auth = useAuth();
    const router = useRouter();
    const [state, formAction, pending] = useActionState(login, initialState);
    const [showPassword, setShowPassword] = useState(false);

    useEffect(() => {
        if (!state.user) {
            return;
        }
        auth.setUser(state.user);
        if (state.redirectTo) {
            router.push(state.redirectTo);
        }
    }, [auth, router, state.redirectTo, state.user]);

    return (
        <form
            action={formAction}
            className={cn("flex flex-col gap-6", className)}
            {...props}
        >
            {state.formError && (
                <FormError title="Login failed" description={state.formError} />
            )}
            <FieldGroup>
                <Field>
                    <FieldLabel htmlFor="username">Username</FieldLabel>
                    <Input
                        id="username"
                        name="username"
                        type="text"
                        placeholder="Enter your username"
                        defaultValue={state.values?.username ?? ""}
                    />
                    <FieldError errors={state.fieldErrors?.username} />
                </Field>
                <Field>
                    <FieldLabel htmlFor="password">Password</FieldLabel>
                    <div className="relative">
                        <Input
                            id="password"
                            name="password"
                            type={showPassword ? "text" : "password"}
                            placeholder="Enter your password"
                            defaultValue={state.values?.password ?? ""}
                            className="pr-10"
                        />
                        <button
                            type="button"
                            onClick={() => setShowPassword(!showPassword)}
                            className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                        >
                            {showPassword ? (
                                <EyeOff size={18} />
                            ) : (
                                <Eye size={18} />
                            )}
                        </button>
                    </div>
                    <FieldError errors={state.fieldErrors?.password} />
                </Field>
                <Field>
                    <Button type="submit" disabled={pending}>
                        Login
                    </Button>
                </Field>
            </FieldGroup>
        </form>
    );
}

function FormError({
    title,
    description,
    className,
    ...props
}: { title: string; description: string } & React.ComponentProps<"div">) {
    return (
        <Alert
            variant="destructive"
            className={cn("w-full border-destructive", className)}
            {...props}
        >
            <AlertCircleIcon />
            <AlertTitle>{title}</AlertTitle>
            <AlertDescription>{description}</AlertDescription>
        </Alert>
    );
}
