export interface PacketField {
  label: string;
  value: string;
  byteOffset?: number;
  byteLength?: number;
  subFields?: PacketField[];
}

export interface PacketLayer {
  name: string; // e.g. "Frame 101", "Ethernet II", "Internet Protocol Version 4", "Transmission Control Protocol"
  summary: string;
  fields: PacketField[];
}

export interface Packet {
  no: number;
  time: number; // relative timestamp in seconds e.g. 0.000123
  absoluteTime?: string; // ISO or formatted timestamp string
  src: string; // e.g. "192.168.1.50" or MAC "00:11:22:33:44:55"
  srcPort?: number;
  srcMac?: string;
  dst: string; // e.g. "142.250.190.46"
  dstPort?: number;
  dstMac?: string;
  protocol: "TCP" | "UDP" | "DNS" | "HTTP" | "HTTPS" | "TLS" | "ICMP" | "ARP" | "SSH" | "MQTT" | "QUIC" | "NTP" | "DHCP" | string;
  length: number; // in bytes
  info: string; // e.g. "54321 → 443 [SYN] Seq=0 Win=64240 Len=0 MSS=1460"
  hexData: string; // Hex string e.g. "001122334455..."
  layers: PacketLayer[];
  flags?: {
    syn?: boolean;
    ack?: boolean;
    fin?: boolean;
    rst?: boolean;
    psh?: boolean;
    urg?: boolean;
  };
  retransmission?: boolean;
  error?: boolean;
  suspicious?: boolean;
  riskLevel?: "normal" | "low" | "medium" | "high";
  riskReason?: string;
}

export interface TrafficStats {
  totalPackets: number;
  totalBytes: number;
  durationSeconds: number;
  packetsPerSec: number;
  bytesPerSec: number;
  bandwidthKbps: number;
  protocolCounts: Record<string, number>;
  topSources: { ip: string; packets: number; bytes: number }[];
  topDestinations: { ip: string; packets: number; bytes: number }[];
  errorCount: number;
  retransmissionCount: number;
  suspiciousCount: number;
}

export interface SecurityAlert {
  id: string;
  timestamp: string;
  type: "Port Scan" | "SYN Flood" | "Cleartext Password" | "ARP Spoofing" | "DNS Tunneling" | "High Retransmissions" | "Malformed Packet";
  severity: "low" | "medium" | "high" | "critical";
  sourceIp: string;
  destinationIp: string;
  protocol: string;
  message: string;
  packetNo?: number;
}

export interface SampleDataset {
  id: string;
  name: string;
  description: string;
  category: string;
  packetCount: number;
  duration: string;
  packets: Packet[];
  alerts?: SecurityAlert[];
}

export interface AIPacketAnalysis {
  summary: string;
  protocolDetails: string;
  securityAssessment: string;
  riskLevel: "low" | "medium" | "high" | "critical";
  recommendations: string[];
}

export interface AITrafficReport {
  executiveSummary: string;
  healthScore: number;
  threatFindings: {
    severity: "High" | "Medium" | "Low" | "Info";
    title: string;
    description: string;
    impact: string;
    affectedHosts: string[];
  }[];
  performanceInsights: string[];
  actionItems: string[];
}
