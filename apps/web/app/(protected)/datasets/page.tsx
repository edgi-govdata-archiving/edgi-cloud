import { TableView } from "@/app/(protected)/datasets/table-view";
import { datasetteFetch } from "@/lib/datasette/client";
import { Dataset } from "./datasets.types";

const getDatasets = async (): Promise<Dataset[]> => {
    const res = await datasetteFetch("/datasets");
    if (!res.ok) throw Error("getDatasets failed");
    const data = await res.json();
    return data.datasets;
};

export default async function Page() {
    const datasets = await getDatasets();

    return (
        <div>
            <div className="container max-w-[1200px] px-4 lg:px-6 xl:px-10 w-full mx-auto pt-12">
                <div className="space-y-4">
                    <div className="flex items-center justify-between gap-4">
                        <div className="space-y-4">
                            <div className="flex items-center gap-4">
                                <div className="space-y-1">
                                    <h1 className="text-2xl">Datasets</h1>
                                </div>
                            </div>
                        </div>
                        <div className="flex items-center gap-2"></div>
                    </div>
                </div>
            </div>
            <div className="mx-auto w-full container max-w-[1200px] px-4 lg:px-6 xl:px-10 grow flex">
                <div className="flex flex-col first:pt-12 py-6 w-full pb-0">
                    <TableView datasets={datasets} />
                </div>
            </div>
        </div>
    );
}
