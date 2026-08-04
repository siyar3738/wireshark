import React from "react";
import { Packet, AIPacketAnalysis } from "../types";
import { Sparkles, X, ShieldAlert, CheckCircle2, AlertTriangle, Cpu, Terminal } from "lucide-react";

interface AIPacketModalProps {
  packet: Packet | null;
  analysis: AIPacketAnalysis | null;
  isLoading: boolean;
  error: string | null;
  onClose: () => void;
}

export const AIPacketModal: React.FC<AIPacketModalProps> = ({
  packet,
  analysis,
  isLoading,
  error,
  onClose,
}) => {
  if (!packet) return null;

  return (
    <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
      <div className="bg-slate-900 border border-slate-700 rounded-2xl max-w-2xl w-full max-h-[90vh] flex flex-col shadow-2xl overflow-hidden animate-in fade-in zoom-in duration-150">
        {/* Header */}
        <div className="px-5 py-4 bg-slate-800/90 border-b border-slate-700 flex items-center justify-between">
          <div className="flex items-center space-x-2.5">
            <div className="p-2 bg-gradient-to-tr from-amber-500 to-orange-600 rounded-lg text-white shadow-sm">
              <Sparkles className="w-5 h-5" />
            </div>
            <div>
              <h2 className="font-bold text-base text-slate-100 flex items-center gap-2">
                Gemini AI Packet Inspector
              </h2>
              <p className="text-xs text-slate-400 font-mono">
                Frame #{packet.no} • {packet.protocol} • {packet.src} → {packet.dst}
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content Body */}
        <div className="p-5 flex-1 overflow-y-auto space-y-4 text-xs text-slate-200 scrollbar-thin">
          {isLoading ? (
            <div className="py-12 flex flex-col items-center justify-center space-y-3">
              <div className="relative">
                <div className="w-12 h-12 rounded-full border-2 border-amber-500/20 border-t-amber-500 animate-spin" />
                <Sparkles className="w-5 h-5 text-amber-400 absolute top-3.5 left-3.5" />
              </div>
              <p className="text-sm font-medium text-slate-300">
                Analyzing packet headers & hex payload with Gemini AI...
              </p>
            </div>
          ) : error ? (
            <div className="bg-rose-950/60 border border-rose-800/80 rounded-xl p-4 text-rose-200 space-y-2">
              <div className="flex items-center space-x-2 font-bold text-sm text-rose-300">
                <AlertTriangle className="w-4 h-4" />
                <span>Analysis Failed</span>
              </div>
              <p className="text-xs">{error}</p>
            </div>
          ) : analysis ? (
            <>
              {/* Risk Banner */}
              <div
                className={`p-3 rounded-xl border flex items-center justify-between ${
                  analysis.riskLevel === "critical" || analysis.riskLevel === "high"
                    ? "bg-rose-950/60 border-rose-800 text-rose-200"
                    : analysis.riskLevel === "medium"
                    ? "bg-amber-950/60 border-amber-800 text-amber-200"
                    : "bg-emerald-950/60 border-emerald-800 text-emerald-200"
                }`}
              >
                <div className="flex items-center space-x-2">
                  <ShieldAlert className="w-4 h-4 shrink-0" />
                  <span className="font-bold text-xs uppercase tracking-wide">
                    Assessment: {analysis.securityAssessment}
                  </span>
                </div>
                <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider bg-slate-950/60 border border-current">
                  {analysis.riskLevel} Risk
                </span>
              </div>

              {/* Executive Summary */}
              <div className="bg-slate-950/60 border border-slate-800 rounded-xl p-3.5 space-y-1">
                <h3 className="font-bold text-slate-300 flex items-center gap-1.5 text-xs">
                  <Cpu className="w-3.5 h-3.5 text-cyan-400" /> Executive Overview
                </h3>
                <p className="text-slate-300 leading-relaxed text-xs">
                  {analysis.summary}
                </p>
              </div>

              {/* Protocol Details */}
              <div className="bg-slate-950/60 border border-slate-800 rounded-xl p-3.5 space-y-1">
                <h3 className="font-bold text-slate-300 flex items-center gap-1.5 text-xs">
                  <Terminal className="w-3.5 h-3.5 text-purple-400" /> Protocol Breakdown
                </h3>
                <p className="text-slate-300 leading-relaxed text-xs">
                  {analysis.protocolDetails}
                </p>
              </div>

              {/* Recommendations */}
              {analysis.recommendations && analysis.recommendations.length > 0 && (
                <div className="bg-slate-950/60 border border-slate-800 rounded-xl p-3.5 space-y-2">
                  <h3 className="font-bold text-slate-300 flex items-center gap-1.5 text-xs">
                    <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" /> Actionable Recommendations
                  </h3>
                  <ul className="space-y-1.5 pl-2">
                    {analysis.recommendations.map((rec, i) => (
                      <li key={i} className="flex items-start gap-2 text-slate-300 text-xs">
                        <span className="text-emerald-400 font-bold">•</span>
                        <span>{rec}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </>
          ) : null}
        </div>
      </div>
    </div>
  );
};
