import React from "react";
import {
  Activity,
  FileText,
  Upload,
  Play,
  Square,
  Sparkles,
  Download,
  ShieldAlert,
  Server
} from "lucide-react";

interface HeaderProps {
  currentDatasetName: string;
  isLiveCapturing: boolean;
  onToggleLiveCapture: () => void;
  onOpenUploadModal: () => void;
  onRunAIAudit: () => void;
  onExportPackets: (format: "json" | "csv") => void;
  activeTab: "packets" | "analytics";
  setActiveTab: (tab: "packets" | "analytics") => void;
  packetCount: number;
  alertCount: number;
}

export const Header: React.FC<HeaderProps> = ({
  currentDatasetName,
  isLiveCapturing,
  onToggleLiveCapture,
  onOpenUploadModal,
  onRunAIAudit,
  onExportPackets,
  activeTab,
  setActiveTab,
  packetCount,
  alertCount,
}) => {
  return (
    <header className="bg-slate-900 border-b border-slate-800 text-slate-100 sticky top-0 z-30 shadow-md">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex flex-col md:flex-row items-center justify-between py-3 gap-3">
          {/* Brand Logo & Name */}
          <div className="flex items-center space-x-3 w-full md:w-auto justify-between md:justify-start">
            <div className="flex items-center space-x-2.5">
              <div className="p-2 bg-gradient-to-tr from-cyan-600 to-blue-600 rounded-lg shadow-sm">
                <Activity className="w-5 h-5 text-white" />
              </div>
              <div>
                <div className="flex items-center space-x-2">
                  <h1 className="font-bold text-base tracking-tight text-white">
                    Wireshark Packet Inspector
                  </h1>
                  <span className="text-xs px-2 py-0.5 rounded-full bg-slate-800 text-slate-300 font-medium border border-slate-700">
                    v2.4
                  </span>
                </div>
                <p className="text-xs text-slate-400 flex items-center gap-1.5 mt-0.5">
                  <Server className="w-3 h-3 text-cyan-400" />
                  Loaded: <span className="text-cyan-300 font-medium">{currentDatasetName}</span>
                </p>
              </div>
            </div>

            {/* Mobile View Tab Toggle */}
            <div className="flex md:hidden bg-slate-800 p-1 rounded-lg border border-slate-700">
              <button
                onClick={() => setActiveTab("packets")}
                className={`px-3 py-1 rounded-md text-xs font-medium transition ${
                  activeTab === "packets"
                    ? "bg-cyan-600 text-white"
                    : "text-slate-400 hover:text-white"
                }`}
              >
                Packets
              </button>
              <button
                onClick={() => setActiveTab("analytics")}
                className={`px-3 py-1 rounded-md text-xs font-medium transition ${
                  activeTab === "analytics"
                    ? "bg-cyan-600 text-white"
                    : "text-slate-400 hover:text-white"
                }`}
              >
                Dashboard
              </button>
            </div>
          </div>

          {/* Desktop Navigation Tabs */}
          <div className="hidden md:flex items-center bg-slate-800/80 p-1 rounded-lg border border-slate-700/80">
            <button
              onClick={() => setActiveTab("packets")}
              className={`flex items-center space-x-2 px-4 py-1.5 rounded-md text-xs font-medium transition ${
                activeTab === "packets"
                  ? "bg-cyan-600 text-white shadow-sm"
                  : "text-slate-300 hover:text-white hover:bg-slate-700/50"
              }`}
            >
              <FileText className="w-3.5 h-3.5" />
              <span>Packet Viewer</span>
              <span className="ml-1 px-1.5 py-0.2 rounded-full text-[10px] bg-slate-900/60 text-slate-200">
                {packetCount}
              </span>
            </button>
            <button
              onClick={() => setActiveTab("analytics")}
              className={`flex items-center space-x-2 px-4 py-1.5 rounded-md text-xs font-medium transition ${
                activeTab === "analytics"
                  ? "bg-cyan-600 text-white shadow-sm"
                  : "text-slate-300 hover:text-white hover:bg-slate-700/50"
              }`}
            >
              <Activity className="w-3.5 h-3.5" />
              <span>Analytics & Monitoring</span>
              {alertCount > 0 && (
                <span className="ml-1 px-1.5 py-0.2 rounded-full text-[10px] bg-rose-500 text-white font-bold animate-pulse">
                  {alertCount}
                </span>
              )}
            </button>
          </div>

          {/* Controls & Action Buttons */}
          <div className="flex items-center space-x-2 w-full md:w-auto justify-end">
            {/* Live Capture Toggle */}
            <button
              onClick={onToggleLiveCapture}
              className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-md text-xs font-medium border transition ${
                isLiveCapturing
                  ? "bg-rose-500/10 border-rose-500/30 text-rose-300 hover:bg-rose-500/20"
                  : "bg-emerald-500/10 border-emerald-500/30 text-emerald-300 hover:bg-emerald-500/20"
              }`}
            >
              {isLiveCapturing ? (
                <>
                  <span className="relative flex h-2 w-2">
                    <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-rose-400 opacity-75"></span>
                    <span className="relative inline-flex rounded-full h-2 w-2 bg-rose-500"></span>
                  </span>
                  <Square className="w-3 h-3 fill-current" />
                  <span>Stop Capture</span>
                </>
              ) : (
                <>
                  <Play className="w-3 h-3 fill-current text-emerald-400" />
                  <span>Live Capture</span>
                </>
              )}
            </button>

            {/* Load File Button */}
            <button
              onClick={onOpenUploadModal}
              className="flex items-center space-x-1.5 px-3 py-1.5 rounded-md text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition"
            >
              <Upload className="w-3.5 h-3.5 text-slate-400" />
              <span>Open PCAP</span>
            </button>

            {/* AI Network Audit */}
            <button
              onClick={onRunAIAudit}
              className="flex items-center space-x-1.5 px-3 py-1.5 rounded-md text-xs font-semibold bg-gradient-to-r from-amber-500 to-orange-600 hover:from-amber-600 hover:to-orange-700 text-white shadow-sm transition"
            >
              <Sparkles className="w-3.5 h-3.5" />
              <span>AI Health Audit</span>
            </button>

            {/* Export Menu */}
            <div className="relative group">
              <button className="flex items-center space-x-1 px-2.5 py-1.5 rounded-md text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition">
                <Download className="w-3.5 h-3.5 text-slate-400" />
              </button>
              <div className="absolute right-0 mt-1 w-36 bg-slate-800 border border-slate-700 rounded-md shadow-xl py-1 hidden group-hover:block z-50">
                <button
                  onClick={() => onExportPackets("json")}
                  className="w-full text-left px-3 py-1.5 text-xs text-slate-300 hover:bg-slate-700 hover:text-white"
                >
                  Export as JSON
                </button>
                <button
                  onClick={() => onExportPackets("csv")}
                  className="w-full text-left px-3 py-1.5 text-xs text-slate-300 hover:bg-slate-700 hover:text-white"
                >
                  Export as CSV
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>
    </header>
  );
};
