import React from "react";
import { Filter, X, Bookmark, Check, AlertCircle } from "lucide-react";
import { validateFilterSyntax } from "../utils/filterEngine";

interface FilterBarProps {
  filterText: string;
  setFilterText: (text: string) => void;
  filteredCount: number;
  totalCount: number;
  onClearFilter: () => void;
}

const PRESET_FILTERS = [
  { label: "HTTP Traffic", filter: "http" },
  { label: "DNS Queries", filter: "dns" },
  { label: "TLS / HTTPS", filter: "tls" },
  { label: "TCP SYN", filter: "tcp.flags.syn == 1" },
  { label: "Errors & Retransmits", filter: "error" },
  { label: "Suspicious Activity", filter: "suspicious" },
  { label: "Host 192.168.1.105", filter: "ip.addr == 192.168.1.105" },
];

export const FilterBar: React.FC<FilterBarProps> = ({
  filterText,
  setFilterText,
  filteredCount,
  totalCount,
  onClearFilter,
}) => {
  const validation = validateFilterSyntax(filterText);
  const isFiltering = filterText.trim().length > 0;

  // Determine Wireshark-like background color
  let bgClass = "bg-slate-900 border-slate-700 text-slate-100";
  if (isFiltering) {
    if (validation.isValid) {
      bgClass = "bg-emerald-950/80 border-emerald-500/80 text-emerald-100 focus-within:ring-2 focus-within:ring-emerald-500";
    } else {
      bgClass = "bg-rose-950/80 border-rose-500/80 text-rose-100 focus-within:ring-2 focus-within:ring-rose-500";
    }
  }

  return (
    <div className="bg-slate-900/90 border-b border-slate-800 p-2.5 sm:px-4">
      <div className="flex flex-col md:flex-row items-stretch md:items-center gap-2">
        {/* Main Filter Input Field */}
        <div className="flex-1 relative">
          <div className={`flex items-center rounded-md border px-3 py-1.5 transition-colors ${bgClass}`}>
            <Filter className="w-4 h-4 mr-2 text-slate-400 shrink-0" />
            <input
              type="text"
              value={filterText}
              onChange={(e) => setFilterText(e.target.value)}
              placeholder='Apply display filter... (e.g. ip.addr == 192.168.1.1, tcp.port == 443, dns, http, error)'
              className="w-full bg-transparent text-xs sm:text-sm focus:outline-none placeholder:text-slate-500 font-mono"
            />
            {isFiltering && (
              <div className="flex items-center space-x-1.5 ml-2">
                {validation.isValid ? (
                  <Check className="w-4 h-4 text-emerald-400" />
                ) : (
                  <AlertCircle className="w-4 h-4 text-rose-400" />
                )}
                <button
                  onClick={onClearFilter}
                  className="p-0.5 rounded hover:bg-slate-800 text-slate-400 hover:text-slate-200"
                  title="Clear display filter"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>
            )}
          </div>
          {!validation.isValid && validation.errorMessage && (
            <p className="text-[11px] text-rose-400 mt-1 font-mono px-1">
              {validation.errorMessage}
            </p>
          )}
        </div>

        {/* Filtered Count Indicator */}
        <div className="flex items-center justify-between md:justify-end gap-2 text-xs text-slate-400">
          <div className="flex items-center space-x-1 px-2.5 py-1 rounded bg-slate-800 border border-slate-700/80">
            <span className="font-semibold text-slate-200">{filteredCount}</span>
            <span>/</span>
            <span>{totalCount} packets</span>
            {isFiltering && (
              <span className="text-cyan-400 font-medium ml-1">
                ({Math.round((filteredCount / (totalCount || 1)) * 100)}%)
              </span>
            )}
          </div>
        </div>
      </div>

      {/* Preset Chips */}
      <div className="flex items-center gap-1.5 overflow-x-auto pt-2 scrollbar-none text-[11px]">
        <span className="text-slate-500 font-medium flex items-center gap-1 shrink-0">
          <Bookmark className="w-3 h-3" /> Quick Filters:
        </span>
        {PRESET_FILTERS.map((preset) => {
          const isActive = filterText === preset.filter;
          return (
            <button
              key={preset.label}
              onClick={() => setFilterText(isActive ? "" : preset.filter)}
              className={`px-2 py-0.5 rounded-full font-mono transition shrink-0 border ${
                isActive
                  ? "bg-cyan-600 text-white border-cyan-400"
                  : "bg-slate-800/80 hover:bg-slate-700 text-slate-300 border-slate-700 hover:border-slate-600"
              }`}
            >
              {preset.label}
            </button>
          );
        })}
      </div>
    </div>
  );
};
