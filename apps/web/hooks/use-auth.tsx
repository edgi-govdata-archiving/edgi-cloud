"use client";

import { createContext, useContext, useState } from "react";
import { User } from "@/lib/auth";

type AuthContextType = {
    user: User | null;
    setUser: (user: User | null) => void;
};

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function AuthProvider({
    initialUser,
    children,
}: {
    initialUser: User | null;
    children: React.ReactNode;
}) {
    const [user, setUser] = useState<User | null>(initialUser);

    return (
        <AuthContext.Provider value={{ user, setUser }}>
            {children}
        </AuthContext.Provider>
    );
}

export function useAuth() {
    const ctx = useContext(AuthContext);
    if (!ctx) {
        throw new Error("useAuth must be used inside AuthProvider");
    }
    return ctx;
}
