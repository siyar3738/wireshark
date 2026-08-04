import React from "react";
import { AITrafficReport } from "../types";
import { Sparkles, X, ShieldAlert, CheckCircle, AlertTriangle, Activity, CheckSquare } from "lucide-react";

interface AIAuditModalProps {
  isOpen: boolean;
  report: AITrafficReport | null;
  isLoading: boolean;
  error: string | null;
  onClose: () => void;
}

export const AIAuditModal: React.FC<AIAuditModalProps> = ({
  isOpen,
  report,
  isLoading,
  error,
  onClose,
}) => {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
      <div className="bg-slate-900 border border-slate-700 rounded-2xl max-w-3xl w-full max-h-[90vh] flex flex-col shadow-2xl overflow-hidden animate-in fade-in zoom-in duration-150">
        {/* Header */}
        <div className="px-6 py-4 bg-slate-800/90 border-b border-slate-700 flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className="p-2 bg-gradient-to-tr from-amber-500 to-orange-600 rounded-xl text-white shadow-md">
              <Sparkles className="w-5 h-5" />
            </div>
            <div>
              <h2 className="font-bold text-lg text-slate-100">
                Gemini AI Network Security & Health Audit
              </h2>
              <p className="text-xs text-slate-400">
                Automated Wireshark traffic assessment & anomaly report
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content Body */}
        <div className="p-6 flex-1 overflow-y-auto space-y-5 text-xs text-slate-200 scrollbar-thin">
          {isLoading ? (
            <div className="py-16 flex flex-col items-center justify-center space-y-4">
              <div className="relative">
                <div className="w-14 h-14 rounded-full border-2 border-amber-500/20 border-t-amber-500 animate-spin" />
                <Sparkles className="w-6 h-6 text-amber-400 absolute top-4 left-4" />
              </div>
              <p className="text-sm font-semibold text-slate-200">
                Evaluating Network Topology, Conversations, and Security Alerts...
              </p>
            </div>
          ) : error ? (
            <div className="bg-rose-950/60 border border-rose-800 rounded-xl p-4 text-rose-200 space-y-2">
              <div className="flex items-center space-x-2 font-bold text-sm text-rose-300">
                <AlertTriangle className="w-4 h-4" />
                <span>Audit Generation Error</span>
              </div>
              <p className="text-xs">{error}</p>
            </div>
          ) : report ? (
            <>
              {/* Health Score Gauge & Executive Summary */}
              <div className="grid grid-cols-1 md:grid-cols-4 gap-4 items-center bg-slate-950/80 border border-slate-800 rounded-xl p-4">
                <div className="md:col-span-1 flex flex-col items-center justify-center p-3 bg-slate-900 border border-slate-800 rounded-lg text-center">
                  <span className="text-3xl font-black text-cyan-400 font-mono">
                    {report.healthScore}/100
                  </span>
                  <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wider mt-1">
                    Health Score
                  </span>
                </div>
                <div className="md:col-span-3 space-y-1">
                  <h3 className="font-bold text-slate-200 text-xs">
                    Executive Health Summary
                  </h3>
                  <p className="text-slate-300 leading-relaxed text-xs">
                    {report.executiveSummary}
                  </p>
                </div>
              </div>

              {/* Threat Findings */}
              <div className="space-y-2">
                <h3 className="font-bold text-slate-200 flex items-center gap-2 text-sm">
                  <ShieldAlert className="w-4 h-4 text-rose-400" /> Security Threat Findings
                </h3>
                <div className="space-y-2">
                  {report.threatFindings.map((finding, idx) => (
                    <div
                      key={idx}
                      className="bg-slate-950/80 border border-slate-800/80 rounded-xl p-3.5 space-y-1.5"
                    >
                      <div className="flex items-center justify-between">
                        <div className="flex items-center space-x-2">
                          <span
                            className={`px-2 py-0.5 text-[10px] font-bold rounded uppercase ${
                              finding.severity === "High"
                                ? "bg-rose-500/20 text-rose-300 border border-rose-500/40"
                                : finding.severity === "Medium"
                                ? "bg-amber-500/20 text-amber-300 border border-amber-500/40"
                                : "bg-slate-800 text-slate-300"
                            }`}
                          >
                            {finding.severity}
                          </span>
                          <span className="font-bold text-slate-200 text-xs">
                            {finding.title}
                          </span>
                        </div>
                        {finding.affectedHosts && (
                          <span className="font-mono text-[10px] text-slate-400">
                            Hosts: {finding.affectedHosts.join(", ")}
                          </span>
                        )}
                      </div>
                      <p className="text-slate-300 text-xs leading-relaxed">
                        {finding.description}
                      </p>
                    </div>
                  ))}
                </div>
              </div>

              {/* Performance Insights */}
              <div className="space-y-2">
                <h3 className="font-bold text-slate-200 flex items-center gap-2 text-sm">
                  <Activity className="w-4 h-4 text-cyan-400" /> Performance Insights
                </h3>
                <div className="bg-slate-950/80 border border-slate-800/80 rounded-xl p-3.5 space-y-2">
                  {report.performanceInsights.map((insight, i) => (
                    <div key={i} className="flex items-start gap-2 text-slate-300 text-xs">
                      <span className="text-cyan-400 font-bold">•</span>
                      <span>{insight}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Action Items */}
              <div className="space-y-2">
                <h3 className="font-bold text-slate-200 flex items-center gap-2 text-sm">
                  <CheckSquare className="w-4 h-4 text-emerald-400" /> Action Items & Remediation
                </h3>
                <div className="bg-slate-950/80 border border-slate-800/80 rounded-xl p-3.5 space-y-2">
                  {report.actionItems.map((action, i) => (
                    <div key={i} className="flex items-start gap-2 text-slate-300 text-xs">
                      <CheckCircle className="w-3.5 h-3.5 text-emerald-400 shrink-0 mt-0.5" />
                      <span>{action}</span>
                    </div>
                  ))}
                </div>
              </div>
            </>
          ) : null}
        </div>
      </div>
    </div>
  );
};
