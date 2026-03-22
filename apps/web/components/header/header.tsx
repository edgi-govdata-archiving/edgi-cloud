"use client";

import Link from "next/link";

import { Leaf } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import {
    DropdownMenu,
    DropdownMenuContent,
    DropdownMenuGroup,
    DropdownMenuItem,
    DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { useAuth } from "@/hooks/use-auth";
import { User } from "@/lib/auth";
import { useRouter, usePathname } from "next/navigation";
import { deleteCookie } from "@/lib/datasette/cookies";

export function Header() {
    const auth = useAuth();
    const pathname = usePathname();

    const displayingOnMainPage = pathname === "/";

    return (
        <div
            className={`py-2 px-6 ${displayingOnMainPage ? "lg:container lg:px-16 xl:px-20" : ""} mx-auto `}
        >
            <div className="flex justify-between">
                <div className="flex gap-2 items-center justify-center">
                    <Leaf />
                    {displayingOnMainPage ? (
                        <h1 className="font-bold text-xl">Resette</h1>
                    ) : (
                        <></>
                    )}
                </div>
                <div>
                    {!auth.user ? (
                        <Link href="/login">
                            <Button size="sm">
                                <span>Sign in</span>
                            </Button>
                        </Link>
                    ) : (
                        <div className="flex gap-2 items-center">
                            {displayingOnMainPage && (
                                <Link href="/databases">
                                    <Button size="sm">Databases</Button>
                                </Link>
                            )}
                            <AvatarDropdown user={auth.user} />
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
}

function AvatarDropdown({ user }: { user: User }) {
    const auth = useAuth();
    const router = useRouter();
    const fallbackLetter = user.username[0].toUpperCase();

    const handleLogout = async () => {
        await deleteCookie("ds_actor");
        router.push("/");
        auth.setUser(null);
    };

    return (
        <DropdownMenu>
            <DropdownMenuTrigger asChild>
                <Button variant="ghost" size="icon" className="rounded-full">
                    <Avatar>
                        <AvatarFallback>{fallbackLetter}</AvatarFallback>
                    </Avatar>
                </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent className="w-32" align="end">
                <DropdownMenuGroup>
                    <DropdownMenuItem
                        variant="destructive"
                        onClick={handleLogout}
                    >
                        Log out
                    </DropdownMenuItem>
                </DropdownMenuGroup>
            </DropdownMenuContent>
        </DropdownMenu>
    );
}
