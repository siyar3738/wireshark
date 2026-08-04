import React, { useState } from "react";
import { Packet } from "../types";
import {
  Sparkles,
  AlertTriangle,
  ArrowUpDown,
  Search,
  Filter,
  ArrowDownCircle
} from "lucide-react";

interface PacketTableProps {
  packets: Packet[];
  selectedPacket: Packet | null;
  onSelectPacket: (packet: Packet) => void;
  onAnalyzePacket: (packet: Packet) => void;
  onQuickFilter: (filterExpr: string) => void;
  autoScroll: boolean;
  setAutoScroll: (val: boolean) => void;
}

type SortField = "no" | "time" | "src" | "dst" | "protocol" | "length";

export const PacketTable: React.FC<PacketTableProps> = ({
  packets,
  selectedPacket,
  onSelectPacket,
  onAnalyzePacket,
  onQuickFilter,
  autoScroll,
  setAutoScroll,
}) => {
  const [sortField, setSortField] = useState<SortField>("no");
  const [sortAsc, setSortAsc] = useState<boolean>(true);
  const [searchTerm, setSearchTerm] = useState<string>("");

  const handleSort = (field: SortField) => {
    if (sortField === field) {
      setSortAsc(!sortAsc);
    } else {
      setSortField(field);
      setSortAsc(true);
    }
  };

  const filtered = packets.filter((p) => {
    if (!searchTerm) return true;
    const term = searchTerm.toLowerCase();
    return (
      p.info.toLowerCase().includes(term) ||
      p.src.toLowerCase().includes(term) ||
      p.dst.toLowerCase().includes(term) ||
      p.protocol.toLowerCase().includes(term)
    );
  });

  const sorted = [...filtered].sort((a, b) => {
    let valA = a[sortField] ?? 0;
    let valB = b[sortField] ?? 0;

    if (typeof valA === "string") valA = (valA as string).toLowerCase();
    if (typeof valB === "string") valB = (valB as string).toLowerCase();

    if (valA < valB) return sortAsc ? -1 : 1;
    if (valA > valB) return sortAsc ? 1 : -1;
    return 0;
  });

  const getRowColorClass = (pkt: Packet, isSelected: boolean) => {
    if (isSelected) {
      return "bg-cyan-600 text-white font-medium shadow-sm";
    }

    if (pkt.error || pkt.flags?.rst) {
      return "bg-rose-950/60 text-rose-200 hover:bg-rose-900/80 border-l-2 border-rose-500";
    }

    if (pkt.suspicious || pkt.riskLevel === "high") {
      return "bg-amber-950/60 text-amber-200 hover:bg-amber-900/80 border-l-2 border-amber-500";
    }

    switch (pkt.protocol) {
      case "DNS":
        return "bg-teal-950/40 text-teal-200 hover:bg-teal-900/60";
      case "HTTP":
      case "HTTPS":
        return "bg-emerald-950/40 text-emerald-200 hover:bg-emerald-900/60";
      case "TLS":
        return "bg-purple-950/40 text-purple-200 hover:bg-purple-900/60";
      case "UDP":
        return "bg-sky-950/40 text-sky-200 hover:bg-sky-900/60";
      case "ICMP":
      case "ARP":
        return "bg-slate-800/80 text-slate-300 hover:bg-slate-700/80";
      case "SSH":
      case "MQTT":
        return "bg-orange-950/40 text-orange-200 hover:bg-orange-900/60";
      default:
        return "bg-slate-900/90 text-slate-200 hover:bg-slate-800/90";
    }
  };

  return (
    <div className="flex flex-col h-full bg-slate-900 rounded-lg border border-slate-800 shadow-sm overflow-hidden">
      {/* Table Toolbar */}
      <div className="flex items-center justify-between px-3 py-2 bg-slate-800/90 border-b border-slate-700/80 text-xs text-slate-300">
        <div className="flex items-center space-x-2">
          <span className="font-semibold text-slate-100 flex items-center gap-1.5">
            Packet List
          </span>
          <span className="text-slate-400">({sorted.length} displayed)</span>
        </div>

        <div className="flex items-center space-x-3">
          {/* Quick Search */}
          <div className="relative">
            <Search className="w-3.5 h-3.5 absolute left-2 top-1.5 text-slate-400" />
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Search in table..."
              className="bg-slate-900 border border-slate-700 rounded pl-7 pr-2 py-1 text-[11px] text-slate-200 focus:outline-none focus:border-cyan-500 w-36 sm:w-48"
            />
          </div>

          {/* Auto scroll toggle */}
          <button
            onClick={() => setAutoScroll(!autoScroll)}
            className={`flex items-center space-x-1 px-2 py-1 rounded text-[11px] font-medium transition ${
              autoScroll
                ? "bg-cyan-600 text-white"
                : "bg-slate-700 text-slate-300 hover:bg-slate-600"
            }`}
          >
            <ArrowDownCircle className="w-3.5 h-3.5" />
            <span>Auto-Scroll</span>
          </button>
        </div>
      </div>

      {/* Main Table */}
      <div className="flex-1 overflow-y-auto font-mono text-xs scrollbar-thin">
        <table className="w-full text-left border-collapse min-w-[720px]">
          <thead className="bg-slate-800 text-slate-300 sticky top-0 z-10 border-b border-slate-700 shadow-sm">
            <tr>
              <th
                onClick={() => handleSort("no")}
                className="py-2 px-3 cursor-pointer hover:bg-slate-700/80 w-16"
              >
                <div className="flex items-center space-x-1">
                  <span>No.</span>
                  <ArrowUpDown className="w-3 h-3 text-slate-400" />
                </div>
              </th>
              <th
                onClick={() => handleSort("time")}
                className="py-2 px-3 cursor-pointer hover:bg-slate-700/80 w-28"
              >
                <div className="flex items-center space-x-1">
                  <span>Time (s)</span>
                  <ArrowUpDown className="w-3 h-3 text-slate-400" />
                </div>
              </th>
              <th
                onClick={() => handleSort("src")}
                className="py-2 px-3 cursor-pointer hover:bg-slate-700/80 w-40"
              >
                <div className="flex items-center space-x-1">
                  <span>Source</span>
                  <ArrowUpDown className="w-3 h-3 text-slate-400" />
                </div>
              </th>
              <th
                onClick={() => handleSort("dst")}
                className="py-2 px-3 cursor-pointer hover:bg-slate-700/80 w-40"
              >
                <div className="flex items-center space-x-1">
                  <span>Destination</span>
                  <ArrowUpDown className="w-3 h-3 text-slate-400" />
                </div>
              </th>
              <th
                onClick={() => handleSort("protocol")}
                className="py-2 px-3 cursor-pointer hover:bg-slate-700/80 w-24"
              >
                <div className="flex items-center space-x-1">
                  <span>Protocol</span>
                  <ArrowUpDown className="w-3 h-3 text-slate-400" />
                </div>
              </th>
              <th
                onClick={() => handleSort("length")}
                className="py-2 px-3 cursor-pointer hover:bg-slate-700/80 w-20 text-right"
              >
                <div className="flex items-center justify-end space-x-1">
                  <span>Length</span>
                  <ArrowUpDown className="w-3 h-3 text-slate-400" />
                </div>
              </th>
              <th className="py-2 px-3">Info / Summary</th>
              <th className="py-2 px-2 text-center w-16">AI</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60">
            {sorted.length === 0 ? (
              <tr>
                <td colSpan={8} className="text-center py-12 text-slate-500 font-sans">
                  No packets match the current filter or search criteria.
                </td>
              </tr>
            ) : (
              sorted.map((pkt) => {
                const isSelected = selectedPacket?.no === pkt.no;
                const rowClass = getRowColorClass(pkt, isSelected);

                return (
                  <tr
                    key={pkt.no}
                    onClick={() => onSelectPacket(pkt)}
                    className={`cursor-pointer transition-colors ${rowClass}`}
                  >
                    <td className="py-1.5 px-3 font-semibold">{pkt.no}</td>
                    <td className="py-1.5 px-3 text-slate-300">
                      {pkt.time.toFixed(6)}
                    </td>
                    <td className="py-1.5 px-3">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          onQuickFilter(`ip.addr == ${pkt.src}`);
                        }}
                        className="hover:underline flex items-center gap-1 group"
                        title={`Filter by Source IP ${pkt.src}`}
                      >
                        <span>{pkt.src}</span>
                        {pkt.srcPort && (
                          <span className="text-[10px] opacity-70">
                            :{pkt.srcPort}
                          </span>
                        )}
                        <Filter className="w-2.5 h-2.5 opacity-0 group-hover:opacity-100 transition" />
                      </button>
                    </td>
                    <td className="py-1.5 px-3">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          onQuickFilter(`ip.addr == ${pkt.dst}`);
                        }}
                        className="hover:underline flex items-center gap-1 group"
                        title={`Filter by Destination IP ${pkt.dst}`}
                      >
                        <span>{pkt.dst}</span>
                        {pkt.dstPort && (
                          <span className="text-[10px] opacity-70">
                            :{pkt.dstPort}
                          </span>
                        )}
                        <Filter className="w-2.5 h-2.5 opacity-0 group-hover:opacity-100 transition" />
                      </button>
                    </td>
                    <td className="py-1.5 px-3">
                      <span className="font-bold text-[11px] uppercase tracking-wide">
                        {pkt.protocol}
                      </span>
                    </td>
                    <td className="py-1.5 px-3 text-right">{pkt.length}</td>
                    <td className="py-1.5 px-3 truncate max-w-md">
                      <div className="flex items-center space-x-1.5">
                        {pkt.suspicious && (
                          <AlertTriangle className="w-3.5 h-3.5 text-amber-400 shrink-0" />
                        )}
                        <span className="truncate">{pkt.info}</span>
                      </div>
                    </td>
                    <td className="py-1.5 px-2 text-center">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          onAnalyzePacket(pkt);
                        }}
                        className="p-1 rounded hover:bg-slate-700/80 text-amber-400 hover:text-amber-300 transition"
                        title="Analyze Packet with Gemini AI"
                      >
                        <Sparkles className="w-3.5 h-3.5" />
                      </button>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};
