import React from "react";
import { Packet } from "../types";
import { Binary, Terminal } from "lucide-react";

interface HexViewerProps {
  packet: Packet | null;
  highlightOffset?: number;
  highlightLength?: number;
}

export const HexViewer: React.FC<HexViewerProps> = ({
  packet,
  highlightOffset,
  highlightLength,
}) => {
  if (!packet || !packet.hexData) {
    return (
      <div className="h-full bg-slate-900 border border-slate-800 rounded-lg p-4 flex flex-col items-center justify-center text-slate-500 text-xs">
        <Binary className="w-8 h-8 mb-2 text-slate-600 stroke-[1.5]" />
        <p>No hex payload available.</p>
      </div>
    );
  }

  // Parse hex bytes
  const hexString = packet.hexData.replace(/\s+/g, "");
  const bytes: number[] = [];
  for (let i = 0; i < hexString.length; i += 2) {
    bytes.push(parseInt(hexString.substr(i, 2), 16) || 0);
  }

  // Group into 16-byte rows
  const rows: { offset: number; hexBytes: number[]; ascii: string }[] = [];
  for (let i = 0; i < bytes.length; i += 16) {
    const rowBytes = bytes.slice(i, i + 16);
    const ascii = rowBytes
      .map((b) => (b >= 32 && b <= 126 ? String.fromCharCode(b) : "."))
      .join("");
    rows.push({
      offset: i,
      hexBytes: rowBytes,
      ascii,
    });
  }

  const isHighlighted = (byteIdx: number) => {
    if (highlightOffset === undefined || highlightLength === undefined) return false;
    return byteIdx >= highlightOffset && byteIdx < highlightOffset + highlightLength;
  };

  return (
    <div className="h-full bg-slate-900 border border-slate-800 rounded-lg flex flex-col overflow-hidden text-xs text-slate-200">
      {/* Header */}
      <div className="px-3 py-2 bg-slate-800/90 border-b border-slate-700/80 flex items-center justify-between text-slate-300 font-semibold">
        <div className="flex items-center space-x-2">
          <Terminal className="w-4 h-4 text-cyan-400" />
          <span>Packet Bytes (Hex & ASCII Inspector)</span>
        </div>
        <span className="font-mono text-[11px] text-slate-400">
          {bytes.length} bytes
        </span>
      </div>

      {/* Hex Grid */}
      <div className="flex-1 overflow-y-auto p-3 font-mono text-[11px] leading-relaxed scrollbar-thin select-text">
        <div className="space-y-1">
          {rows.map((row) => (
            <div key={row.offset} className="flex items-center space-x-4 hover:bg-slate-800/30 px-1 py-0.5 rounded">
              {/* Offset Column */}
              <span className="text-cyan-500/80 font-bold w-12 shrink-0">
                {row.offset.toString(16).padStart(4, "0")}
              </span>

              {/* Hex Bytes Column */}
              <div className="flex items-center space-x-1 shrink-0 font-mono">
                {row.hexBytes.map((b, bIdx) => {
                  const absoluteIdx = row.offset + bIdx;
                  const highlighted = isHighlighted(absoluteIdx);

                  return (
                    <React.Fragment key={bIdx}>
                      {bIdx === 8 && <span className="w-2" />}
                      <span
                        className={`px-0.5 rounded transition ${
                          highlighted
                            ? "bg-amber-500 text-slate-950 font-bold"
                            : "text-slate-300 hover:text-white"
                        }`}
                      >
                        {b.toString(16).padStart(2, "0")}
                      </span>
                    </React.Fragment>
                  );
                })}
              </div>

              {/* ASCII Representation Column */}
              <div className="flex-1 pl-4 border-l border-slate-800 text-slate-400 font-mono tracking-widest truncate">
                {row.ascii.split("").map((char, cIdx) => {
                  const absoluteIdx = row.offset + cIdx;
                  const highlighted = isHighlighted(absoluteIdx);

                  return (
                    <span
                      key={cIdx}
                      className={
                        highlighted
                          ? "bg-amber-500 text-slate-950 font-bold px-0.5 rounded"
                          : char !== "."
                          ? "text-emerald-400 font-semibold"
                          : "text-slate-600"
                      }
                    >
                      {char}
                    </span>
                  );
                })}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
