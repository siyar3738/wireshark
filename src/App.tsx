import React, { useState, useEffect } from "react";
import { Packet, TrafficStats, SecurityAlert, AIPacketAnalysis, AITrafficReport } from "./types";
import { SAMPLE_DATASETS } from "./utils/sampleData";
import { filterPackets } from "./utils/filterEngine";
import { calculateTrafficStats, generateLiveSimulatedPacket } from "./utils/packetSim";
import { Header } from "./components/Header";
import { FilterBar } from "./components/FilterBar";
import { PacketTable } from "./components/PacketTable";
import { PacketDetails } from "./components/PacketDetails";
import { HexViewer } from "./components/HexViewer";
import { AnalyticsDashboard } from "./components/AnalyticsDashboard";
import { AIPacketModal } from "./components/AIPacketModal";
import { AIAuditModal } from "./components/AIAuditModal";
import { FileUploadModal } from "./components/FileUploadModal";

export default function App() {
  const [currentDatasetName, setCurrentDatasetName] = useState<string>(
    SAMPLE_DATASETS[0].name
  );
  const [packets, setPackets] = useState<Packet[]>(SAMPLE_DATASETS[0].packets);
  const [selectedPacket, setSelectedPacket] = useState<Packet | null>(
    SAMPLE_DATASETS[0].packets[0] || null
  );
  const [filterText, setFilterText] = useState<string>("");
  const [isLiveCapturing, setIsLiveCapturing] = useState<boolean>(false);
  const [autoScroll, setAutoScroll] = useState<boolean>(true);
  const [activeTab, setActiveTab] = useState<"packets" | "analytics">("packets");

  // Hover highlighting in Hex Inspector
  const [hoverOffset, setHoverOffset] = useState<number | undefined>(undefined);
  const [hoverLength, setHoverLength] = useState<number | undefined>(undefined);

  // Security Alerts
  const [alerts, setAlerts] = useState<SecurityAlert[]>(
    SAMPLE_DATASETS[0].alerts || []
  );

  // Time-series data for analytics chart
  const [timeSeriesData, setTimeSeriesData] = useState<
    { time: string; packets: number; bytes: number; bandwidthKbps: number }[]
  >([
    { time: "0s", packets: 5, bytes: 420, bandwidthKbps: 3.3 },
    { time: "1s", packets: 8, bytes: 910, bandwidthKbps: 7.2 },
    { time: "2s", packets: 12, bytes: 1450, bandwidthKbps: 11.6 },
    { time: "3s", packets: 18, bytes: 2100, bandwidthKbps: 16.8 },
  ]);

  // AI Modals
  const [aiPacketModalOpen, setAiPacketModalOpen] = useState<boolean>(false);
  const [aiPacket, setAiPacket] = useState<Packet | null>(null);
  const [aiPacketAnalysis, setAiPacketAnalysis] = useState<AIPacketAnalysis | null>(null);
  const [isAnalyzingPacket, setIsAnalyzingPacket] = useState<boolean>(false);
  const [aiPacketError, setAiPacketError] = useState<string | null>(null);

  const [aiAuditOpen, setAiAuditOpen] = useState<boolean>(false);
  const [aiAuditReport, setAiAuditReport] = useState<AITrafficReport | null>(null);
  const [isGeneratingAudit, setIsGeneratingAudit] = useState<boolean>(false);
  const [aiAuditError, setAiAuditError] = useState<string | null>(null);

  const [uploadModalOpen, setUploadModalOpen] = useState<boolean>(false);

  // Filtered Packets
  const filteredPackets = filterPackets(packets, filterText);

  // Traffic Stats
  const trafficStats: TrafficStats = calculateTrafficStats(packets);

  // Live Packet Capture Simulation
  useEffect(() => {
    if (!isLiveCapturing) return;

    const interval = setInterval(() => {
      setPackets((prevPackets) => {
        const lastNo = prevPackets.length > 0 ? prevPackets[prevPackets.length - 1].no : 0;
        const lastTime = prevPackets.length > 0 ? prevPackets[prevPackets.length - 1].time : 0;

        const { packet, alert } = generateLiveSimulatedPacket(lastNo + 1, lastTime);

        if (alert) {
          setAlerts((prevAlerts) => [alert, ...prevAlerts]);
        }

        const newPackets = [...prevPackets, packet];

        // Update time series
        const statsNow = calculateTrafficStats(newPackets);
        setTimeSeriesData((prevTs) => {
          const updated = [
            ...prevTs,
            {
              time: `${statsNow.durationSeconds}s`,
              packets: statsNow.packetsPerSec,
              bytes: statsNow.bytesPerSec,
              bandwidthKbps: statsNow.bandwidthKbps,
            },
          ];
          return updated.slice(-15); // keep last 15 points
        });

        return newPackets;
      });
    }, 1000);

    return () => clearInterval(interval);
  }, [isLiveCapturing]);

  // Handle Load Dataset / Packets
  const handleLoadPackets = (newPackets: Packet[], datasetName: string) => {
    setCurrentDatasetName(datasetName);
    setPackets(newPackets);
    setSelectedPacket(newPackets[0] || null);
    setFilterText("");

    // Find any alerts in sample dataset if applicable
    const foundSample = SAMPLE_DATASETS.find((s) => s.name === datasetName);
    setAlerts(foundSample?.alerts || []);

    const newStats = calculateTrafficStats(newPackets);
    setTimeSeriesData([
      { time: "0s", packets: Math.round(newStats.packetsPerSec * 0.5), bytes: Math.round(newStats.bytesPerSec * 0.5), bandwidthKbps: newStats.bandwidthKbps * 0.5 },
      { time: `${newStats.durationSeconds}s`, packets: newStats.packetsPerSec, bytes: newStats.bytesPerSec, bandwidthKbps: newStats.bandwidthKbps },
    ]);
  };

  // Simulate Anomaly Event
  const handleSimulateAnomaly = (type: "portscan" | "dnsflood" | "httperror") => {
    const lastNo = packets.length > 0 ? packets[packets.length - 1].no : 0;
    const lastTime = packets.length > 0 ? packets[packets.length - 1].time : 0;

    const { packet, alert } = generateLiveSimulatedPacket(lastNo + 1, lastTime, type);

    setPackets((prev) => [...prev, packet]);
    setSelectedPacket(packet);

    if (alert) {
      setAlerts((prev) => [alert, ...prev]);
    }
  };

  // Analyze single packet with Gemini AI
  const handleAnalyzePacket = async (pkt: Packet) => {
    setAiPacket(pkt);
    setAiPacketAnalysis(null);
    setAiPacketError(null);
    setIsAnalyzingPacket(true);
    setAiPacketModalOpen(true);

    try {
      const res = await fetch("/api/analyze-packet", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ packet: pkt }),
      });

      const data = await res.json();
      if (!res.ok || !data.success) {
        throw new Error(data.error || "Failed to analyze packet.");
      }

      setAiPacketAnalysis(data.analysis);
    } catch (err: any) {
      setAiPacketError(err.message || "Failed to connect to AI server.");
    } finally {
      setIsAnalyzingPacket(false);
    }
  };

  // Run AI Network Traffic Health Audit
  const handleRunAIAudit = async () => {
    setAiAuditOpen(true);
    setIsGeneratingAudit(true);
    setAiAuditError(null);

    try {
      const res = await fetch("/api/analyze-traffic", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          trafficStats,
          suspiciousPackets: packets.filter((p) => p.suspicious || p.error).slice(0, 5),
        }),
      });

      const data = await res.json();
      if (!res.ok || !data.success) {
        throw new Error(data.error || "Failed to generate AI Audit.");
      }

      setAiAuditReport(data.report);
    } catch (err: any) {
      setAiAuditError(err.message || "Failed to connect to AI server.");
    } finally {
      setIsGeneratingAudit(false);
    }
  };

  // Export Packets
  const handleExportPackets = (format: "json" | "csv") => {
    if (format === "json") {
      const jsonStr = JSON.stringify(filteredPackets, null, 2);
      const blob = new Blob([jsonStr], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `packets_export_${Date.now()}.json`;
      a.click();
    } else {
      const headers = ["No", "Time", "Source", "Destination", "Protocol", "Length", "Info"];
      const rows = filteredPackets.map((p) => [
        p.no,
        p.time,
        `"${p.src}"`,
        `"${p.dst}"`,
        `"${p.protocol}"`,
        p.length,
        `"${p.info.replace(/"/g, '""')}"`,
      ]);
      const csvStr = [headers.join(","), ...rows.map((r) => r.join(","))].join("\n");
      const blob = new Blob([csvStr], { type: "text/csv" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `packets_export_${Date.now()}.csv`;
      a.click();
    }
  };

  return (
    <div className="flex flex-col h-screen bg-slate-950 font-sans text-slate-100 overflow-hidden">
      {/* Top Header Navigation */}
      <Header
        currentDatasetName={currentDatasetName}
        isLiveCapturing={isLiveCapturing}
        onToggleLiveCapture={() => setIsLiveCapturing(!isLiveCapturing)}
        onOpenUploadModal={() => setUploadModalOpen(true)}
        onRunAIAudit={handleRunAIAudit}
        onExportPackets={handleExportPackets}
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        packetCount={packets.length}
        alertCount={alerts.length}
      />

      {/* Main Workspace Layout */}
      {activeTab === "packets" ? (
        <div className="flex-1 flex flex-col min-h-0">
          {/* Wireshark Display Filter Bar */}
          <FilterBar
            filterText={filterText}
            setFilterText={setFilterText}
            filteredCount={filteredPackets.length}
            totalCount={packets.length}
            onClearFilter={() => setFilterText("")}
          />

          {/* Wireshark 3-Pane View */}
          <div className="flex-1 p-2 flex flex-col gap-2 min-h-0 overflow-hidden">
            {/* Top Pane: Packet List Table (60% height) */}
            <div className="h-[55%] min-h-[180px]">
              <PacketTable
                packets={filteredPackets}
                selectedPacket={selectedPacket}
                onSelectPacket={setSelectedPacket}
                onAnalyzePacket={handleAnalyzePacket}
                onQuickFilter={(expr) => setFilterText(expr)}
                autoScroll={autoScroll}
                setAutoScroll={setAutoScroll}
              />
            </div>

            {/* Bottom Split Panes: Packet Details Tree & Hex Inspector (40% height) */}
            <div className="h-[45%] grid grid-cols-1 md:grid-cols-2 gap-2 min-h-0">
              {/* Middle Pane: Protocol Layer Tree */}
              <PacketDetails
                packet={selectedPacket}
                onHoverField={(offset, length) => {
                  setHoverOffset(offset);
                  setHoverLength(length);
                }}
              />

              {/* Bottom Pane: Hex & ASCII Viewer */}
              <HexViewer
                packet={selectedPacket}
                highlightOffset={hoverOffset}
                highlightLength={hoverLength}
              />
            </div>
          </div>
        </div>
      ) : (
        /* Real-Time Analytics Dashboard Tab */
        <div className="flex-1 min-h-0">
          <AnalyticsDashboard
            stats={trafficStats}
            alerts={alerts}
            isLiveCapturing={isLiveCapturing}
            onSimulateAnomaly={handleSimulateAnomaly}
            timeSeriesData={timeSeriesData}
          />
        </div>
      )}

      {/* Gemini AI Packet Modal */}
      <AIPacketModal
        packet={aiPacket}
        analysis={aiPacketAnalysis}
        isLoading={isAnalyzingPacket}
        error={aiPacketError}
        onClose={() => setAiPacketModalOpen(false)}
      />

      {/* Gemini AI Audit Modal */}
      <AIAuditModal
        isOpen={aiAuditOpen}
        report={aiAuditReport}
        isLoading={isGeneratingAudit}
        error={aiAuditError}
        onClose={() => setAiAuditOpen(false)}
      />

      {/* File Upload & Sample Selector Modal */}
      <FileUploadModal
        isOpen={uploadModalOpen}
        onClose={() => setUploadModalOpen(false)}
        onLoadPackets={handleLoadPackets}
      />
    </div>
  );
}
