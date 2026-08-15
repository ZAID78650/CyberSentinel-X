import { useEffect, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { CheckCircle2, ListChecks, Loader2, XCircle } from "lucide-react";
import { api, getErrorMessage } from "../services/api";
import { useSocket } from "../contexts/WebSocketContext";
import { useToast } from "../components/ui/Toast";
import { Card, EmptyState, SeverityBadge, Skeleton, StatusBadge } from "../components/ui";
import type { Approval } from "../types";

export default function HumanApprovals() {
  const [filter, setFilter] = useState("PENDING");
  const { success, error: toastError } = useToast();
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const [busy, setBusy] = useState<string | null>(null);

  const { data, isLoading } = useQuery({
    queryKey: ["approvals", filter],
    queryFn: async () => (await api.get<Approval[]>("/approvals", { params: { status: filter } })).data,
    refetchInterval: filter === "PENDING" ? 5000 : false,
  });

  const { on } = useSocket();
  useEffect(() => {
    return on("new_incident", () => queryClient.invalidateQueries({ queryKey: ["approvals"] }));
  }, [on, queryClient]);

  const decide = async (id: string, decision: "approve" | "reject") => {
    setBusy(id);
    try {
      const res = await api.post(`/approvals/${id}/${decision}`, { reason: "Analyst decision" });
      success(decision === "approve" ? "Approved" : "Rejected", res.data.message as string);
      queryClient.invalidateQueries({ queryKey: ["approvals"] });
      queryClient.invalidateQueries({ queryKey: ["incidents"] });
      queryClient.invalidateQueries({ queryKey: ["dashboard"] });
    } catch (err) {
      toastError("Failed", getErrorMessage(err));
    } finally {
      setBusy(null);
    }
  };

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <ListChecks className="h-5 w-5 text-electric-400" />
        <h2 className="text-lg font-bold text-slate-100">Human Approvals</h2>
        <p className="text-xs text-slate-500">High-impact response actions require explicit analyst approval</p>
        <select className="input ml-auto w-auto" value={filter} onChange={(e) => setFilter(e.target.value)}>
          {["PENDING", "APPROVED", "REJECTED"].map((s) => <option key={s}>{s}</option>)}
        </select>
      </div>

      <Card>
        {isLoading && !data ? (
          <div className="space-y-2">{[...Array(5)].map((_, i) => <Skeleton key={i} className="h-16" />)}</div>
        ) : !data || data.length === 0 ? (
          <EmptyState
            icon={<ListChecks className="h-8 w-8" />}
            title="No approval requests"
            description={filter === "PENDING" ? "Approval requests raised by the Response Agent appear here." : "No decisions in this state yet."}
          />
        ) : (
          <div className="space-y-3">
            {data.map((a) => (
              <div key={a.id} className="rounded-lg border border-night-700 bg-night-850/60 p-4">
                <div className="flex flex-wrap items-center gap-2">
                  <StatusBadge status={a.status} />
                  {a.incident_severity && <SeverityBadge severity={a.incident_severity} />}
                  <span className="text-sm font-semibold text-slate-100">{a.recommendation_action ?? "Response action"}</span>
                  {a.incident_title && (
                    <button
                      onClick={() => navigate(`/incidents/${a.incident_id}`)}
                      className="text-xs text-electric-400 hover:underline"
                    >
                      {a.incident_title}
                    </button>
                  )}
                </div>
                <div className="mt-2 flex flex-wrap items-center gap-4 text-xs text-slate-500">
                  <span>Requested by <span className="font-mono text-slate-400">{a.requested_by}</span></span>
                  <span>{new Date(a.created_at).toLocaleString()}</span>
                  {a.decision_by && <span>Decided by {a.decision_by}</span>}
                  {a.reason && <span className="italic">“{a.reason}”</span>}
                </div>
                {a.status === "PENDING" && (
                  <div className="mt-3 flex gap-2">
                    <button className="btn-primary" disabled={busy !== null} onClick={() => decide(a.id, "approve")}>
                      {busy === a.id ? <Loader2 className="h-4 w-4 animate-spin" /> : <CheckCircle2 className="h-4 w-4" />}
                      Approve & Execute
                    </button>
                    <button className="btn-ghost" disabled={busy !== null} onClick={() => decide(a.id, "reject")}>
                      <XCircle className="h-4 w-4" /> Reject
                    </button>
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </Card>
    </div>
  );
}
