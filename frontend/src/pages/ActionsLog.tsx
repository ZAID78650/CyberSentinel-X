import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { ClipboardList } from "lucide-react";
import { api } from "../services/api";
import { Card, EmptyState, Skeleton } from "../components/ui";
import type { ActionLogEntry, Paginated } from "../types";

export default function ActionsLog() {
  const [page, setPage] = useState(1);
  const [action, setAction] = useState("");

  const { data, isLoading } = useQuery({
    queryKey: ["actions-log", page, action],
    queryFn: async () => {
      const params: Record<string, string | number> = { page, page_size: 30 };
      if (action) params.action = action;
      return (await api.get<Paginated<ActionLogEntry>>("/actions-log", { params })).data;
    },
  });

  const actionColor = (a: string) =>
    a.includes("APPROVAL.APPROVED") || a.includes("RESPONSE.EXECUTED")
      ? "#4ade80"
      : a.includes("APPROVAL.REJECTED") || a.includes("FAILED")
        ? "#f87171"
        : a.includes("SIMULATION")
          ? "#a78bfa"
          : "#38bdf8";

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <ClipboardList className="h-5 w-5 text-electric-400" />
        <h2 className="text-lg font-bold text-slate-100">Actions Log</h2>
        <p className="text-xs text-slate-500">Immutable audit trail of every platform action</p>
        <input
          className="input ml-auto w-56"
          placeholder="Filter by action…"
          value={action}
          onChange={(e) => { setAction(e.target.value); setPage(1); }}
        />
      </div>

      <Card>
        {isLoading && !data ? (
          <div className="space-y-2">{[...Array(10)].map((_, i) => <Skeleton key={i} className="h-10" />)}</div>
        ) : !data || data.items.length === 0 ? (
          <EmptyState icon={<ClipboardList className="h-8 w-8" />} title="No actions recorded" />
        ) : (
          <div className="overflow-x-auto">
            <table className="table-base">
              <thead>
                <tr><th>Time</th><th>Actor</th><th>Action</th><th>Target</th><th>Detail</th><th>IP</th></tr>
              </thead>
              <tbody>
                {data.items.map((l) => (
                  <tr key={l.id}>
                    <td className="whitespace-nowrap font-mono text-xs text-slate-500">{new Date(l.created_at).toLocaleString()}</td>
                    <td className="font-mono text-xs text-slate-300">{l.actor}</td>
                    <td>
                      <span className="badge border" style={{ color: actionColor(l.action), borderColor: `${actionColor(l.action)}44`, background: `${actionColor(l.action)}11` }}>
                        {l.action}
                      </span>
                    </td>
                    <td className="text-xs text-slate-500">{l.target_type ? `${l.target_type}/${l.target_id ?? ""}` : "—"}</td>
                    <td className="max-w-[220px] truncate text-xs text-slate-600">
                      {l.detail ? JSON.stringify(l.detail).slice(0, 80) : "—"}
                    </td>
                    <td className="font-mono text-xs text-slate-600">{l.ip_address ?? "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {data && (
          <div className="mt-4 flex items-center justify-between text-xs text-slate-500">
            <span>Page {data.page} of {data.pages} · {data.total} entries</span>
            <div className="flex gap-2">
              <button className="btn-ghost" disabled={page <= 1} onClick={() => setPage((p) => p - 1)}>Prev</button>
              <button className="btn-ghost" disabled={page >= data.pages} onClick={() => setPage((p) => p + 1)}>Next</button>
            </div>
          </div>
        )}
      </Card>
    </div>
  );
}
