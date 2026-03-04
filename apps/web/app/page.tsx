import Image from "next/image";

import { Header } from "@/components/header/header";
import { CircleCheck, Shield } from "lucide-react";
import { Card } from "@/components/ui/card";

export default async function Page() {
    return (
        <div>
            <Header />
            <div className="relative w-full md:h-[50vh] h-[30vh] overflow-hidden">
                <Image
                    src="/hendrik-cornelissen--qrcOR33ErA-unsplash.jpg"
                    alt="Hero"
                    fill
                    priority
                    className="object-cover object-center"
                />
            </div>
            <div className="relative">
                <div className="md:rounded-xl p-12 drop-shadow-2xl mx-auto md:w-[80dvw] md:max-w-[800px] md:-translate-y-1/2 bg-background w-full text-center">
                    <div className="flex flex-col gap-1 opacity-60 items-center justify-center">
                        <h2 className="italic">
                            Environmental Data Governance Initiative
                        </h2>
                        <Shield size={16} />
                    </div>
                    <div className="mt-6 flex flex-col gap-2 font-medium text-xl">
                        <span>
                            Resette is the home for public environmental
                            datasets.
                        </span>
                        <span>
                            Upload your data, generate an interactive site
                            instantly, and make it accessible to researchers,
                            policymakers, and the public.
                        </span>
                    </div>
                </div>
            </div>
            <Features />
        </div>
    );
}

function Features() {
    const cardDescriptions = [
        {
            title: "Create & Import Data",
            features: [
                "Upload CSV files or import SQLite databases",
                "Create multiple data tables in one database",
                "Automatic data type detection and indexing",
            ],
        },
        {
            title: "Customize & Publish",
            features: [
                "Design custom homepages",
                "Control table visibility and display order",
                "Publish your database portal to the world",
            ],
        },
        {
            title: "Explore & Share",
            features: [
                "Advanced filtering and faceted browsing",
                "Full-text search across all columns",
                "Export filtered data as CSV or JSON",
            ],
        },
    ];

    return (
        <div className="container mx-auto flex lg:flex-row flex-col justify-between gap-4 pb-24 lg:px-16 xl:px-20">
            {cardDescriptions.map((c) => (
                <Card
                    className="flex flex-col gap-4 p-8 drop-shadow-2xl border-0 ring-0"
                    key={c.title}
                >
                    <div>
                        <span className="text-2xl font-bold">{c.title}</span>
                    </div>
                    <ul>
                        {c.features.map((f) => (
                            <li key={f} className="flex gap-2 items-center">
                                <CircleCheck size={18} />
                                <span className="text-lg">{f}</span>
                            </li>
                        ))}
                    </ul>
                </Card>
            ))}
        </div>
    );
}
