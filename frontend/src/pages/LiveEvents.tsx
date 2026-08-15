import { useEffect, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { Activity, Fingerprint, Filter, Search } from "lucide-react";
import { api } from "../services/api";
import { useSocket } from "../contexts/WebSocketContext";
import { Card, EmptyState, SeverityBadge, Skeleton } from "../components/ui";
import type { Paginated, SecurityEvent } from "../types";

export default function LiveEvents() {
  const [page, setPage] = useState(1);
  const [eventType, setEventType] = useState("");
  const [severity, setSeverity] = useState("");
  const [search, setSearch] = useState("");
  const [liveItems, setLiveItems] = useState<SecurityEvent[]>([]);
  const { connected } = useSocket();

  const { data, isLoading } = useQuery({
    queryKey: ["events", page, eventType, severity],
    queryFn: async () => {
      const params: Record<string, string | number> = { page, page_size: 25 };
      if (eventType) params.event_type = eventType;
      if (severity) params.severity = severity;
      const res = await api.get<Paginated<SecurityEvent>>("/events", { params });
      return res.data;
    },
  });

  const { on } = useSocket();
  useEffect(() => {
    return on("new_event", (d) => {
      setLiveItems((prev) => [
        {
          id: (d.event_id as string) ?? `live-${Date.now()}`,
          event_id: (d.event_id as string) ?? "",
          timestamp: (d.timestamp as string) ?? new Date().toISOString(),
          event_type: (d.event_type as string) ?? "",
          severity: (d.severity as string) ?? "LOW",
          source_ip: (d.source_ip as string) ?? null,
          user_id: (d.user_id as string) ?? null,
          is_anomalous: Boolean(d.is_anomalous),
          anomaly_score: null,
          source: "live",
          destination_ip: null,
          device_id: null,
          asset_id: null,
          metadata: null,
          detection_reason: null,
        },
        ...prev,
      ].slice(0, 20));
    });
  }, [on]);

  const items = liveItems.length > 0 && !eventType && !severity ? liveItems.slice(0, 25) : (data?.items ?? []);
  const filtered =
    search.trim()
      ? items.filter((e) =>
          [e.event_id, e.event_type, e.source_ip, e.user_id, e.detection_reason]
            .filter(Boolean)
            .some((v) => String(v).toLowerCase().includes(search.toLowerCase())),
        )
      : items;

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <div className="relative">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-500" />
          <input
            className="input pl-10"
            placeholder="Search events…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>
        <div className="flex items-center gap-2">
          <Filter className="h-4 w-4 text-slate-500" />
          <select className="input w-auto" value={eventType} onChange={(e) => { setEventType(e.target.value); setPage(1); }}>
            <option value="">All types</option>
            {["LOGIN_SUCCESS", "LOGIN_FAILURE", "NEW_DEVICE", "UNUSUAL_LOCATION", "PRIVILEGE_ESCALATION",
              "SUSPICIOUS_PROCESS", "FILE_ACCESS", "DATABASE_ACCESS", "DATA_DOWNLOAD", "DATA_EXFILTRATION",
              "MALWARE_DETECTED", "PORT_SCAN", "BRUTE_FORCE", "SUSPICIOUS_NETWORK_CONNECTION"].map((t) => (
              <option key={t} value={t}>{t}</option>
            ))}
          </select>
          <select className="input w-auto" value={severity} onChange={(e) => { setSeverity(e.target.value); setPage(1); }}>
            <option value="">All severities</option>
            {["LOW", "MEDIUM", "HIGH", "CRITICAL"].map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
        </div>
        <span className={`ml-auto flex items-center gap-1.5 text-xs font-semibold ${connected ? "text-cyber-green" : "text-cyber-yellow"}`}>
          <Activity className="h-4 w-4" /> {connected ? "LIVE STREAM ACTIVE" : "POLLING"}
        </span>
      </div>

      <Card>
        {isLoading && !data ? (
          <div className="space-y-2">{[...Array(8)].map((_, i) => <Skeleton key={i} className="h-10" />)}</div>
        ) : filtered.length === 0 ? (
          <EmptyState icon={<Activity className="h-8 w-8" />} title="No events match" description="Adjust filters or run a simulation." />
        ) : (
          <div className="overflow-x-auto">
            <table className="table-base">
              <thead>
                <tr>
                  <th>Timestamp</th><th>Event ID</th><th>Type</th><th>Severity</th>
                  <th>Source IP</th><th>User</th><th>Anomaly</th><th>Detection reason</th><th></th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((e) => (
                  <tr key={e.event_id}>
                    <td className="whitespace-nowrap font-mono text-xs text-slate-400">
                      {new Date(e.timestamp).toLocaleString()}
                    </td>
                    <td className="font-mono text-[11px] text-electric-400">{e.event_id}</td>
                    <td className="font-mono text-xs text-slate-200">{e.event_type}</td>
                    <td><SeverityBadge severity={e.severity} /></td>
                    <td className="font-mono text-xs">
                      {e.source_ip ? (
                        <Link to={`/entity/ip/${encodeURIComponent(e.source_ip)}`} className="text-electric-400 hover:underline">{e.source_ip}</Link>
                      ) : "—"}
                    </td>
                    <td className="text-xs">
                      {e.user_id ? (
                        <Link to={`/entity/user/${encodeURIComponent(e.user_id)}`} className="text-slate-300 hover:text-electric-400 hover:underline">{e.user_id}</Link>
                      ) : "—"}
                    </td>
                    <td>
                      {e.is_anomalous ? (
                        <span className="badge border border-cyber-red/30 bg-cyber-red/10 text-cyber-red">ANOMALOUS</span>
                      ) : (
                        <span className="badge border border-night-700 text-slate-600">normal</span>
                      )}
                    </td>
                    <td className="max-w-[280px] truncate text-xs text-slate-500">{e.detection_reason ?? "—"}</td>
                    <td>
                      <Link to={`/threat-analyzer?q=${encodeURIComponent(e.event_id)}`} className="inline-flex items-center gap-1 rounded-md border border-night-700 px-2 py-1 text-[10px] font-semibold text-slate-400 transition hover:border-electric-500/50 hover:text-electric-400" title="Run the threat analyzer on this event">
                        <Fingerprint className="h-3 w-3" /> Analyze
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {data && (
          <div className="mt-4 flex items-center justify-between text-xs text-slate-500">
            <span>
              Page {data.page} of {data.pages} · {data.total} events
            </span>
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
