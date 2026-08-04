import React, { useRef, useState } from "react";
import { SAMPLE_DATASETS } from "../utils/sampleData";
import { SampleDataset, Packet } from "../types";
import { parseUploadedFile } from "../utils/pcapParser";
import { Upload, FileText, Database, X, Check, FileCheck, HardDrive } from "lucide-react";

interface FileUploadModalProps {
  isOpen: boolean;
  onClose: () => void;
  onLoadPackets: (packets: Packet[], datasetName: string) => void;
}

export const FileUploadModal: React.FC<FileUploadModalProps> = ({
  isOpen,
  onClose,
  onLoadPackets,
}) => {
  const [isParsing, setIsParsing] = useState(false);
  const [parseError, setParseError] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  if (!isOpen) return null;

  const handleFileChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setIsParsing(true);
    setParseError(null);

    const result = await parseUploadedFile(file);
    setIsParsing(false);

    if (result.error || result.packets.length === 0) {
      setParseError(result.error || "No valid packets found in file.");
    } else {
      onLoadPackets(result.packets, `${file.name} (${result.fileType})`);
      onClose();
    }
  };

  const handleSelectSample = (sample: SampleDataset) => {
    onLoadPackets(sample.packets, sample.name);
    onClose();
  };

  return (
    <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
      <div className="bg-slate-900 border border-slate-700 rounded-2xl max-w-2xl w-full max-h-[90vh] flex flex-col shadow-2xl overflow-hidden animate-in fade-in zoom-in duration-150">
        {/* Header */}
        <div className="px-5 py-4 bg-slate-800/90 border-b border-slate-700 flex items-center justify-between">
          <div className="flex items-center space-x-2.5">
            <div className="p-2 bg-cyan-600 rounded-lg text-white">
              <Upload className="w-5 h-5" />
            </div>
            <div>
              <h2 className="font-bold text-base text-slate-100">
                Load Wireshark Capture File
              </h2>
              <p className="text-xs text-slate-400">
                Upload PCAP, PCAPNG, JSON, CSV, PDML or pick a sample dataset
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
        <div className="p-5 flex-1 overflow-y-auto space-y-5 text-xs text-slate-200 scrollbar-thin">
          {/* File Upload Zone */}
          <div
            onClick={() => fileInputRef.current?.click()}
            className="border-2 border-dashed border-slate-700 hover:border-cyan-500 rounded-xl p-8 text-center bg-slate-950/60 hover:bg-slate-950/90 cursor-pointer transition flex flex-col items-center justify-center space-y-2 group"
          >
            <input
              type="file"
              ref={fileInputRef}
              onChange={handleFileChange}
              accept=".pcap,.pcapng,.json,.csv,.pdml,.xml,.txt"
              className="hidden"
            />
            <div className="p-3 bg-slate-800 group-hover:bg-cyan-600/20 text-slate-400 group-hover:text-cyan-400 rounded-full transition">
              <HardDrive className="w-6 h-6" />
            </div>
            <div>
              <p className="font-bold text-slate-200 text-sm">
                Click or Drag & Drop Wireshark File
              </p>
              <p className="text-slate-400 text-xs mt-1">
                Supports <span className="text-cyan-400 font-mono">.pcap</span>,{" "}
                <span className="text-cyan-400 font-mono">.pcapng</span>,{" "}
                <span className="text-cyan-400 font-mono">.json</span>,{" "}
                <span className="text-cyan-400 font-mono">.csv</span>,{" "}
                <span className="text-cyan-400 font-mono">.pdml</span>
              </p>
            </div>
          </div>

          {isParsing && (
            <div className="p-3 bg-cyan-950/60 border border-cyan-800 text-cyan-200 rounded-xl text-center text-xs font-semibold animate-pulse">
              Parsing packet headers and byte payload...
            </div>
          )}

          {parseError && (
            <div className="p-3 bg-rose-950/60 border border-rose-800 text-rose-200 rounded-xl text-xs">
              {parseError}
            </div>
          )}

          {/* Sample Captures Section */}
          <div className="space-y-2">
            <h3 className="font-bold text-slate-300 text-xs flex items-center gap-1.5">
              <Database className="w-3.5 h-3.5 text-cyan-400" /> Pre-loaded Sample Datasets
            </h3>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
              {SAMPLE_DATASETS.map((sample) => (
                <div
                  key={sample.id}
                  onClick={() => handleSelectSample(sample)}
                  className="bg-slate-950/80 border border-slate-800 hover:border-cyan-500/80 p-3 rounded-xl cursor-pointer transition space-y-1 group"
                >
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-slate-200 group-hover:text-cyan-300 transition text-xs">
                      {sample.name}
                    </span>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-400">
                      {sample.packetCount} pkts
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-400 line-clamp-2">
                    {sample.description}
                  </p>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
