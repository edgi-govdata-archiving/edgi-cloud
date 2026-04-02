import { datasetteFetch } from "@/lib/datasette/client";
import { type Dataset } from "../datasets.types";

async function getDataset(id: string): Promise<Dataset> {
    const res = await datasetteFetch(`/datasets/${id}`);
    if (!res.ok) throw Error("getDataset failed");
    const data = await res.json();
    return data.dataset;
}

export default async function Page({
    params,
}: {
    params: Promise<{ id: string }>;
}) {
    const { id } = await params;
    const dataset = await getDataset(id);

    return <span>{dataset.db_name}</span>;
}
