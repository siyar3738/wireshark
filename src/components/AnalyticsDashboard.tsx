import React from "react";
import { TrafficStats, SecurityAlert } from "../types";
import {
  AreaChart,
  Area,
  BarChart,
  Bar,
  PieChart,
  Pie,
  Cell,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from "recharts";
import {
  Activity,
  Zap,
  ShieldAlert,
  Server,
  ArrowUpRight,
  Wifi,
  AlertTriangle,
  Radio,
  Play
} from "lucide-react";

interface AnalyticsDashboardProps {
  stats: TrafficStats;
  alerts: SecurityAlert[];
  isLiveCapturing: boolean;
  onSimulateAnomaly: (type: "portscan" | "dnsflood" | "httperror") => void;
  timeSeriesData: { time: string; packets: number; bytes: number; bandwidthKbps: number }[];
}

const PROTOCOL_COLORS: Record<string, string> = {
  TCP: "#3b82f6",
  UDP: "#0284c7",
  DNS: "#14b8a6",
  HTTP: "#10b981",
  HTTPS: "#059669",
  TLS: "#8b5cf6",
  ICMP: "#f59e0b",
  ARP: "#64748b",
  SSH: "#f97316",
  MQTT: "#ec4899",
  OTHER: "#94a3b8",
};

export const AnalyticsDashboard: React.FC<AnalyticsDashboardProps> = ({
  stats,
  alerts,
  isLiveCapturing,
  onSimulateAnomaly,
  timeSeriesData,
}) => {
  // Protocol distribution for Donut Chart
  const pieData = Object.entries(stats.protocolCounts).map(([name, value]) => ({
    name,
    value: Number(value) || 0,
    color: PROTOCOL_COLORS[name] || "#64748b",
  }));

  return (
    <div className="h-full overflow-y-auto p-4 space-y-4 bg-slate-950 text-slate-100 scrollbar-thin">
      {/* Top Metric Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
        {/* Total Packets & Rate */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 shadow-sm relative overflow-hidden">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400">
              Total Traffic Volume
            </span>
            <div className="p-2 bg-blue-500/10 text-blue-400 rounded-lg">
              <Activity className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-2 flex items-baseline justify-between">
            <div>
              <span className="text-2xl font-bold text-white">
                {stats.totalPackets.toLocaleString()}
              </span>
              <span className="text-xs text-slate-400 ml-1">pkts</span>
            </div>
            <span className="text-xs text-emerald-400 font-semibold bg-emerald-500/10 px-2 py-0.5 rounded">
              {stats.packetsPerSec} pkts/s
            </span>
          </div>
          <div className="mt-2 text-[11px] text-slate-400 border-t border-slate-800/80 pt-1.5 flex justify-between">
            <span>Payload Size:</span>
            <span className="font-mono text-slate-200">
              {(stats.totalBytes / 1024).toFixed(1)} KB
            </span>
          </div>
        </div>

        {/* Bandwidth Throughput */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 shadow-sm relative overflow-hidden">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400">
              Bandwidth Throughput
            </span>
            <div className="p-2 bg-emerald-500/10 text-emerald-400 rounded-lg">
              <Zap className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-2 flex items-baseline justify-between">
            <div>
              <span className="text-2xl font-bold text-white">
                {stats.bandwidthKbps > 1000
                  ? (stats.bandwidthKbps / 1000).toFixed(2) + " Mbps"
                  : stats.bandwidthKbps + " Kbps"}
              </span>
            </div>
            {isLiveCapturing && (
              <span className="flex items-center text-[10px] text-emerald-400 font-bold bg-emerald-500/10 px-2 py-0.5 rounded animate-pulse">
                <Radio className="w-3 h-3 mr-1" /> Live Stream
              </span>
            )}
          </div>
          <div className="mt-2 text-[11px] text-slate-400 border-t border-slate-800/80 pt-1.5 flex justify-between">
            <span>Avg Data Rate:</span>
            <span className="font-mono text-slate-200">
              {(stats.bytesPerSec / 1024).toFixed(1)} KB/s
            </span>
          </div>
        </div>

        {/* Security Alerts */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 shadow-sm relative overflow-hidden">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400">
              Security Alerts
            </span>
            <div className="p-2 bg-rose-500/10 text-rose-400 rounded-lg">
              <ShieldAlert className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-2 flex items-baseline justify-between">
            <div>
              <span className="text-2xl font-bold text-rose-400">
                {alerts.length}
              </span>
              <span className="text-xs text-slate-400 ml-1">threats</span>
            </div>
            {alerts.length > 0 && (
              <span className="text-[10px] text-rose-300 font-bold bg-rose-500/20 border border-rose-500/30 px-2 py-0.5 rounded">
                Action Req.
              </span>
            )}
          </div>
          <div className="mt-2 text-[11px] text-slate-400 border-t border-slate-800/80 pt-1.5 flex justify-between">
            <span>Retransmissions:</span>
            <span className="font-mono text-slate-200">
              {stats.retransmissionCount} pkts
            </span>
          </div>
        </div>

        {/* Top Protocol */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 shadow-sm relative overflow-hidden">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400">
              Dominant Protocol
            </span>
            <div className="p-2 bg-purple-500/10 text-purple-400 rounded-lg">
              <Wifi className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-2 flex items-baseline justify-between">
            <div>
              <span className="text-xl font-bold text-purple-300">
                {pieData[0]?.name || "N/A"}
              </span>
            </div>
            <span className="text-xs text-purple-400 font-semibold bg-purple-500/10 px-2 py-0.5 rounded">
              {pieData[0] ? Math.round((pieData[0].value / (stats.totalPackets || 1)) * 100) : 0}%
            </span>
          </div>
          <div className="mt-2 text-[11px] text-slate-400 border-t border-slate-800/80 pt-1.5 flex justify-between">
            <span>Active Protocols:</span>
            <span className="font-mono text-slate-200">
              {Object.keys(stats.protocolCounts).length} types
            </span>
          </div>
        </div>
      </div>

      {/* Live Anomaly Generator Bar */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-3 flex flex-col md:flex-row items-center justify-between gap-3">
        <div className="flex items-center space-x-2">
          <div className="p-1.5 bg-amber-500/10 text-amber-400 rounded-lg">
            <AlertTriangle className="w-4 h-4" />
          </div>
          <div>
            <h4 className="text-xs font-bold text-slate-200">Real-Time Threat Simulation Controls</h4>
            <p className="text-[11px] text-slate-400">Inject synthetic network events into live monitoring stream:</p>
          </div>
        </div>
        <div className="flex items-center space-x-2 w-full md:w-auto justify-end">
          <button
            onClick={() => onSimulateAnomaly("portscan")}
            className="px-3 py-1.5 bg-rose-900/50 hover:bg-rose-800/80 border border-rose-700/80 text-rose-200 rounded-lg text-xs font-medium transition flex items-center gap-1.5"
          >
            <Zap className="w-3.5 h-3.5 text-rose-400" />
            <span>Simulate Port Scan</span>
          </button>
          <button
            onClick={() => onSimulateAnomaly("dnsflood")}
            className="px-3 py-1.5 bg-amber-900/50 hover:bg-amber-800/80 border border-amber-700/80 text-amber-200 rounded-lg text-xs font-medium transition flex items-center gap-1.5"
          >
            <ShieldAlert className="w-3.5 h-3.5 text-amber-400" />
            <span>Simulate DNS Burst</span>
          </button>
        </div>
      </div>

      {/* Main Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Real-time Bandwidth & Throughput Chart */}
        <div className="lg:col-span-2 bg-slate-900 border border-slate-800 rounded-xl p-4 shadow-sm flex flex-col h-80">
          <div className="flex items-center justify-between mb-2">
            <div>
              <h3 className="text-xs font-bold text-slate-200 flex items-center gap-2">
                <Activity className="w-4 h-4 text-cyan-400" />
                Network Throughput & Rate (Kbps / Packets)
              </h3>
            </div>
            <span className="text-[11px] text-slate-400">Time Window (Seconds)</span>
          </div>
          <div className="flex-1 w-full mt-2">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={timeSeriesData}>
                <defs>
                  <linearGradient id="bandwidthGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.8} />
                    <stop offset="95%" stopColor="#06b6d4" stopOpacity={0.0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#334155" opacity={0.4} />
                <XAxis dataKey="time" stroke="#94a3b8" fontSize={10} />
                <YAxis stroke="#94a3b8" fontSize={10} />
                <Tooltip
                  contentStyle={{ backgroundColor: "#0f172a", borderColor: "#334155", borderRadius: "8px", fontSize: "12px" }}
                />
                <Area
                  type="monotone"
                  dataKey="bandwidthKbps"
                  name="Bandwidth (Kbps)"
                  stroke="#06b6d4"
                  strokeWidth={2}
                  fillOpacity={1}
                  fill="url(#bandwidthGrad)"
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Protocol Distribution Donut Chart */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 shadow-sm flex flex-col h-80">
          <h3 className="text-xs font-bold text-slate-200 mb-2 flex items-center gap-2">
            <Wifi className="w-4 h-4 text-purple-400" />
            Protocol Distribution
          </h3>
          <div className="flex-1 w-full relative">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={pieData}
                  cx="50%"
                  cy="50%"
                  innerRadius={55}
                  outerRadius={80}
                  paddingAngle={3}
                  dataKey="value"
                >
                  {pieData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{ backgroundColor: "#0f172a", borderColor: "#334155", borderRadius: "8px", fontSize: "12px" }}
                />
                <Legend
                  verticalAlign="bottom"
                  height={36}
                  iconSize={8}
                  wrapperStyle={{ fontSize: "11px" }}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Secondary Row: Top Talkers Bar Chart & Security Alerts Feed */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Top Talkers Matrix */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 shadow-sm flex flex-col h-80">
          <h3 className="text-xs font-bold text-slate-200 mb-2 flex items-center gap-2">
            <Server className="w-4 h-4 text-blue-400" />
            Top Source Hosts by Traffic Volume (Bytes)
          </h3>
          <div className="flex-1 w-full mt-2">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={stats.topSources}>
                <CartesianGrid strokeDasharray="3 3" stroke="#334155" opacity={0.4} />
                <XAxis dataKey="ip" stroke="#94a3b8" fontSize={10} />
                <YAxis stroke="#94a3b8" fontSize={10} />
                <Tooltip
                  contentStyle={{ backgroundColor: "#0f172a", borderColor: "#334155", borderRadius: "8px", fontSize: "12px" }}
                />
                <Bar dataKey="bytes" name="Bytes Sent" fill="#3b82f6" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Security Alerts Log */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 shadow-sm flex flex-col h-80 overflow-hidden">
          <div className="flex items-center justify-between mb-3 border-b border-slate-800 pb-2">
            <h3 className="text-xs font-bold text-slate-200 flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-rose-400" />
              Real-Time Security Threat Feed
            </h3>
            <span className="text-[10px] px-2 py-0.5 rounded-full bg-slate-800 text-slate-300">
              {alerts.length} Events
            </span>
          </div>

          <div className="flex-1 overflow-y-auto space-y-2 scrollbar-thin pr-1">
            {alerts.length === 0 ? (
              <div className="h-full flex flex-col items-center justify-center text-slate-500 text-xs py-8">
                <ShieldAlert className="w-8 h-8 mb-2 text-slate-700" />
                <p>No active security threats or anomalies detected.</p>
              </div>
            ) : (
              alerts.map((alt) => (
                <div
                  key={alt.id}
                  className="bg-slate-950/80 border border-slate-800 hover:border-slate-700 p-2.5 rounded-lg text-xs space-y-1 transition"
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-2">
                      <span
                        className={`px-1.5 py-0.5 text-[10px] font-bold rounded uppercase ${
                          alt.severity === "critical"
                            ? "bg-rose-500 text-white animate-pulse"
                            : alt.severity === "high"
                            ? "bg-rose-950 text-rose-300 border border-rose-800"
                            : "bg-amber-950 text-amber-300 border border-amber-800"
                        }`}
                      >
                        {alt.type}
                      </span>
                      <span className="font-mono text-[11px] text-slate-400">
                        {alt.sourceIp} → {alt.destinationIp}
                      </span>
                    </div>
                    <span className="text-[10px] text-slate-500 font-mono">
                      {alt.timestamp}
                    </span>
                  </div>
                  <p className="text-slate-300 text-[11px] leading-relaxed">
                    {alt.message}
                  </p>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
