import { Check, EllipsisVertical } from "lucide-react";
import { type Dataset } from "./datasets.types";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";

export function TableView({ datasets }: { datasets: Dataset[] }) {
    return (
        <div className="overflow-hidden rounded-lg border bg-surface-100 text-card-foreground shadow-sm flex-1 min-h-0 overflow-y-auto mb-8">
            <div className="relative">
                <div className="w-full overflow-auto">
                    <table className="group/table w-full caption-bottom text-sm">
                        <TableHeader />
                        <TableBody datasets={datasets} />
                    </table>
                </div>
            </div>
        </div>
    );
}

function TableHeader() {
    return (
        <thead className="[&_tr]:border-b [&>;tr]:bg-200">
            <tr className="border-b [&>td]:hover:bg-surface-200 data-[state=selected]:bg-muted">
                <th
                    className="h-10 px-4 text-left align-middle heading-meta whitespace-nowrap text-foreground-lighter [&:has([role=checkbox])]:pr-0 transition-colors"
                    aria-sort="ascending"
                >
                    <button
                        type="button"
                        className="group/table-head-sort heading-meta whitespace-nowrap flex items-center gap-1 cursor-pointer select-none bg-transparent! border-none p-0 w-full text-left"
                    >
                        Name
                    </button>
                </th>
                <th className="h-10 px-4 text-left align-middle heading-meta whitespace-nowrap text-foreground-lighter [&:has([role=checkbox])]:pr-0 transition-colors">
                    Status
                </th>
                <th className="h-10 px-4 text-left align-middle heading-meta whitespace-nowrap text-foreground-lighter [&:has([role=checkbox])]:pr-0 transition-colors">
                    Created
                </th>
                <th className="h-10 px-4 text-left align-middle heading-meta whitespace-nowrap text-foreground-lighter [&:has([role=checkbox])]:pr-0 transition-colors">
                    Updated
                </th>
                <th className="h-10 px-4 text-left align-middle heading-meta whitespace-nowrap text-foreground-lighter [&:has([role=checkbox])]:pr-0 transition-colors"></th>
            </tr>
        </thead>
    );
}

function TableBody({ datasets }: { datasets: Dataset[] }) {
    const getDisplayDate = (isoString: string) => {
        const date = new Date(isoString);
        return date.toLocaleDateString() + " " + date.toLocaleTimeString();
    };

    return (
        <tbody className="[&_tr:last-child]:border-0">
            {datasets.map((d: Dataset) => {
                return (
                    <tr
                        key={d.db_id}
                        className="border-b [&>td]:hover:bg-surface-200 data-[state=selected]:bg-muted cursor-pointer hover:bg-surface-200 inset-focus"
                    >
                        <td className="transition-colors p-4 align-middle [&:has([role=checkbox])]:pr-0">
                            <div className="flex flex-col gap-y-2">
                                <div>
                                    <h5 className="text-sm font-bold">
                                        {d.db_name}
                                    </h5>
                                </div>
                            </div>
                        </td>
                        <td className="transition-colors p-4 align-middle [&:has([role=checkbox])]:pr-0">
                            <div className="flex items-center">
                                <DatasetStatusBadge status={d.status} />
                            </div>
                        </td>
                        <td className="transition-colors p-4 align-middle [&:has([role=checkbox])]:pr-0">
                            <div className="w-fit">
                                <span>{getDisplayDate(d.created_at)}</span>
                            </div>
                        </td>
                        <td className="transition-colors p-4 align-middle [&:has([role=checkbox])]:pr-0">
                            <span>{getDisplayDate(d.updated_at)}</span>
                        </td>
                        <td className="transition-colors p-4 align-middle [&:has([role=checkbox])]:pr-0 text-right">
                            <div>
                                <Button variant="outline" size="icon">
                                    <EllipsisVertical />
                                </Button>
                            </div>
                        </td>
                    </tr>
                );
            })}
        </tbody>
    );
}

function DatasetStatusBadge({ status }: { status: string }) {
    switch (status.toLowerCase()) {
        case "published":
            return (
                <Badge className="bg-green-50 text-green-700 dark:bg-green-950 dark:text-green-300">
                    <Check data-icon="inline-start" />
                    {status}
                </Badge>
            );
        case "draft":
            return (
                <Badge className="bg-blue-50 text-blue-700 dark:bg-blue-950 dark:text-blue-300">
                    {status}
                </Badge>
            );
    }
    return (
        <Badge className="bg-yellow-50 text-yellow-700 dark:bg-yellow-950 dark:text-yellow-300">
            {status}
        </Badge>
    );
}
