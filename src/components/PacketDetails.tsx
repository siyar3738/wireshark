import React, { useState } from "react";
import { Packet, PacketLayer, PacketField } from "../types";
import { ChevronRight, ChevronDown, Layers, Info, Tag } from "lucide-react";

interface PacketDetailsProps {
  packet: Packet | null;
  onHoverField?: (offset?: number, length?: number) => void;
}

export const PacketDetails: React.FC<PacketDetailsProps> = ({
  packet,
  onHoverField,
}) => {
  const [expandedLayers, setExpandedLayers] = useState<Record<string, boolean>>({
    "0": true,
    "1": true,
    "2": true,
    "3": true,
  });

  if (!packet) {
    return (
      <div className="h-full bg-slate-900 border border-slate-800 rounded-lg p-4 flex flex-col items-center justify-center text-slate-500 text-xs">
        <Layers className="w-8 h-8 mb-2 text-slate-600 stroke-[1.5]" />
        <p>Select a packet from the table above to inspect detailed headers.</p>
      </div>
    );
  }

  const toggleLayer = (layerIdx: number) => {
    setExpandedLayers((prev) => ({
      ...prev,
      [layerIdx]: !prev[layerIdx],
    }));
  };

  return (
    <div className="h-full bg-slate-900 border border-slate-800 rounded-lg flex flex-col overflow-hidden text-xs text-slate-200">
      {/* Header */}
      <div className="px-3 py-2 bg-slate-800/90 border-b border-slate-700/80 flex items-center justify-between text-slate-300 font-semibold">
        <div className="flex items-center space-x-2">
          <Layers className="w-4 h-4 text-cyan-400" />
          <span>Packet Details (Frame #{packet.no})</span>
        </div>
        <span className="font-mono text-[11px] text-cyan-300 bg-slate-900/60 px-2 py-0.5 rounded border border-slate-700">
          {packet.protocol} - {packet.length} bytes
        </span>
      </div>

      {/* Layer Tree */}
      <div className="flex-1 overflow-y-auto p-2 font-mono scrollbar-thin space-y-1">
        {packet.layers.map((layer, idx) => {
          const isExpanded = expandedLayers[idx] !== false;

          return (
            <div key={idx} className="border border-slate-800/80 rounded overflow-hidden">
              {/* Layer Title Row */}
              <button
                onClick={() => toggleLayer(idx)}
                className="w-full flex items-center space-x-2 px-2.5 py-1.5 bg-slate-800/60 hover:bg-slate-800 text-left text-slate-200 transition"
              >
                {isExpanded ? (
                  <ChevronDown className="w-3.5 h-3.5 text-slate-400 shrink-0" />
                ) : (
                  <ChevronRight className="w-3.5 h-3.5 text-slate-400 shrink-0" />
                )}
                <span className="font-bold text-[11px] text-cyan-300 truncate">
                  {layer.name}
                </span>
              </button>

              {/* Layer Fields */}
              {isExpanded && (
                <div className="pl-6 pr-3 py-1.5 bg-slate-950/40 space-y-1 divide-y divide-slate-800/40">
                  {layer.fields.map((field, fIdx) => (
                    <FieldTreeRow
                      key={fIdx}
                      field={field}
                      onHoverField={onHoverField}
                    />
                  ))}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
};

interface FieldTreeRowProps {
  field: PacketField;
  onHoverField?: (offset?: number, length?: number) => void;
}

const FieldTreeRow: React.FC<FieldTreeRowProps> = ({ field, onHoverField }) => {
  const [expanded, setExpanded] = useState<boolean>(false);
  const hasSub = field.subFields && field.subFields.length > 0;

  return (
    <div
      className="py-0.5 hover:bg-slate-800/50 rounded px-1 transition text-[11px]"
      onMouseEnter={() => onHoverField?.(field.byteOffset, field.byteLength)}
      onMouseLeave={() => onHoverField?.(undefined, undefined)}
    >
      <div className="flex items-center space-x-1.5">
        {hasSub ? (
          <button
            onClick={() => setExpanded(!expanded)}
            className="p-0.5 text-slate-400 hover:text-slate-200"
          >
            {expanded ? (
              <ChevronDown className="w-3 h-3" />
            ) : (
              <ChevronRight className="w-3 h-3" />
            )}
          </button>
        ) : (
          <span className="w-4" />
        )}
        <span className="text-slate-400 font-medium">{field.label}:</span>
        <span className="text-slate-100 font-mono font-semibold truncate">
          {field.value}
        </span>
      </div>

      {hasSub && expanded && (
        <div className="pl-4 mt-0.5 space-y-0.5 border-l border-slate-800 ml-2">
          {field.subFields!.map((sub, sIdx) => (
            <FieldTreeRow
              key={sIdx}
              field={sub}
              onHoverField={onHoverField}
            />
          ))}
        </div>
      )}
    </div>
  );
};
