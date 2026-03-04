import Link from "next/link";

import { Leaf } from "lucide-react";
import { Button } from "../ui/button";

export function Header() {
    return (
        <div className="py-2 px-6 lg:container mx-auto lg:px-16 xl:px-20">
            <div className="flex justify-between">
                <div className="flex gap-2 items-center justify-center">
                    <Leaf />
                    <h1 className="font-bold text-xl">Resette</h1>
                </div>
                {/* Login and whatnot */}
                <div>
                    <Link href="#">
                        <Button size="sm">
                            <span>Sign in</span>
                        </Button>
                    </Link>
                </div>
            </div>
        </div>
    );
}
