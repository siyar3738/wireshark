import { Packet, TrafficStats, SecurityAlert } from "../types";

export function calculateTrafficStats(packets: Packet[]): TrafficStats {
  if (packets.length === 0) {
    return {
      totalPackets: 0,
      totalBytes: 0,
      durationSeconds: 0,
      packetsPerSec: 0,
      bytesPerSec: 0,
      bandwidthKbps: 0,
      protocolCounts: {},
      topSources: [],
      topDestinations: [],
      errorCount: 0,
      retransmissionCount: 0,
      suspiciousCount: 0,
    };
  }

  let totalBytes = 0;
  const protocolCounts: Record<string, number> = {};
  const sourcesMap: Record<string, { packets: number; bytes: number }> = {};
  const destsMap: Record<string, { packets: number; bytes: number }> = {};

  let errorCount = 0;
  let retransmissionCount = 0;
  let suspiciousCount = 0;

  let minTime = packets[0].time;
  let maxTime = packets[0].time;

  packets.forEach((pkt) => {
    totalBytes += pkt.length;
    if (pkt.time < minTime) minTime = pkt.time;
    if (pkt.time > maxTime) maxTime = pkt.time;

    // Protocol count
    const proto = pkt.protocol || "OTHER";
    protocolCounts[proto] = (protocolCounts[proto] || 0) + 1;

    // Sources
    if (!sourcesMap[pkt.src]) sourcesMap[pkt.src] = { packets: 0, bytes: 0 };
    sourcesMap[pkt.src].packets += 1;
    sourcesMap[pkt.src].bytes += pkt.length;

    // Destinations
    if (!destsMap[pkt.dst]) destsMap[pkt.dst] = { packets: 0, bytes: 0 };
    destsMap[pkt.dst].packets += 1;
    destsMap[pkt.dst].bytes += pkt.length;

    if (pkt.error) errorCount++;
    if (pkt.retransmission) retransmissionCount++;
    if (pkt.suspicious || pkt.riskLevel === "high") suspiciousCount++;
  });

  const durationSeconds = Math.max(0.1, maxTime - minTime || 1);
  const packetsPerSec = packets.length / durationSeconds;
  const bytesPerSec = totalBytes / durationSeconds;
  const bandwidthKbps = (bytesPerSec * 8) / 1000;

  const topSources = Object.entries(sourcesMap)
    .map(([ip, data]) => ({ ip, ...data }))
    .sort((a, b) => b.bytes - a.bytes)
    .slice(0, 5);

  const topDestinations = Object.entries(destsMap)
    .map(([ip, data]) => ({ ip, ...data }))
    .sort((a, b) => b.bytes - a.bytes)
    .slice(0, 5);

  return {
    totalPackets: packets.length,
    totalBytes,
    durationSeconds: parseFloat(durationSeconds.toFixed(2)),
    packetsPerSec: parseFloat(packetsPerSec.toFixed(1)),
    bytesPerSec: Math.round(bytesPerSec),
    bandwidthKbps: parseFloat(bandwidthKbps.toFixed(1)),
    protocolCounts,
    topSources,
    topDestinations,
    errorCount,
    retransmissionCount,
    suspiciousCount,
  };
}

export function generateLiveSimulatedPacket(
  packetNumber: number,
  lastTimestamp: number,
  anomalyType?: "portscan" | "dnsflood" | "httperror"
): { packet: Packet; alert?: SecurityAlert } {
  const relTime = lastTimestamp + parseFloat((Math.random() * 0.05 + 0.01).toFixed(4));

  if (anomalyType === "portscan") {
    const targetPort = Math.floor(Math.random() * 10000) + 20;
    const pkt: Packet = {
      no: packetNumber,
      time: relTime,
      src: "10.0.0.220",
      srcPort: Math.floor(Math.random() * 20000) + 40000,
      dst: "192.168.1.1",
      dstPort: targetPort,
      protocol: "TCP",
      length: 60,
      flags: { syn: true },
      suspicious: true,
      riskLevel: "high",
      riskReason: `Port scan probe to port ${targetPort}`,
      info: `Port Scan Probe → 192.168.1.1:${targetPort} [SYN]`,
      hexData: "00112233445500aa3344556608004500002812340000400688990a0000dcc0a80101afc8005000000000000000005002040012340000",
      layers: [
        {
          name: `TCP Port Scan Probe to Port ${targetPort}`,
          summary: `Port Scan from untrusted host 10.0.0.220`,
          fields: [
            { label: "Target Port", value: `${targetPort}` },
            { label: "Flag", value: "SYN" },
          ],
        },
      ],
    };

    const alert: SecurityAlert = {
      id: `alert-sim-${Date.now()}`,
      timestamp: `${relTime.toFixed(3)}s`,
      type: "Port Scan",
      severity: "high",
      sourceIp: "10.0.0.220",
      destinationIp: "192.168.1.1",
      protocol: "TCP",
      message: `Port scan probe detected targeting port ${targetPort}`,
      packetNo: packetNumber,
    };

    return { packet: pkt, alert };
  }

  if (anomalyType === "dnsflood") {
    const domains = ["sub1.malicious-domain.xyz", "botnet-c2.test.net", "tunnel.data-exfil.org"];
    const domain = domains[Math.floor(Math.random() * domains.length)];
    const pkt: Packet = {
      no: packetNumber,
      time: relTime,
      src: "192.168.1.180",
      srcPort: Math.floor(Math.random() * 20000) + 30000,
      dst: "8.8.8.8",
      dstPort: 53,
      protocol: "DNS",
      length: 88,
      suspicious: true,
      riskLevel: "medium",
      riskReason: "High frequency DNS lookup for suspicious dynamic domain",
      info: `Standard query TXT ${domain}`,
      hexData: "001122334455001a2b3c4d5e08004500003c1a2b00004011a1b2c0a801b408080808d35600350028a1b21a2b01000001",
      layers: [
        {
          name: "Domain Name System (query)",
          summary: `Suspicious TXT query: ${domain}`,
          fields: [
            { label: "Query", value: domain },
            { label: "Record Type", value: "TXT (16)" },
          ],
        },
      ],
    };

    const alert: SecurityAlert = {
      id: `alert-sim-${Date.now()}`,
      timestamp: `${relTime.toFixed(3)}s`,
      type: "DNS Tunneling",
      severity: "medium",
      sourceIp: "192.168.1.180",
      destinationIp: "8.8.8.8",
      protocol: "DNS",
      message: `Suspicious DNS burst TXT query for ${domain}`,
      packetNo: packetNumber,
    };

    return { packet: pkt, alert };
  }

  // Normal random packet generation
  const protocols = ["HTTPS", "HTTP", "TCP", "UDP", "DNS", "TLS"];
  const selectedProto = protocols[Math.floor(Math.random() * protocols.length)];

  const clientIps = ["192.168.1.102", "192.168.1.105", "192.168.1.112", "192.168.1.140"];
  const serverIps = ["142.250.190.46", "104.21.55.12", "151.101.1.140", "1.1.1.1"];

  const srcIp = clientIps[Math.floor(Math.random() * clientIps.length)];
  const dstIp = serverIps[Math.floor(Math.random() * serverIps.length)];
  const srcPort = Math.floor(Math.random() * 30000) + 30000;
  const dstPort = selectedProto === "HTTPS" || selectedProto === "TLS" ? 443 : selectedProto === "HTTP" ? 80 : 53;
  const length = Math.floor(Math.random() * 1200) + 60;

  const info = `${srcPort} -> ${dstPort} [${selectedProto}] Len=${length}`;

  const pkt: Packet = {
    no: packetNumber,
    time: relTime,
    src: srcIp,
    srcPort,
    dst: dstIp,
    dstPort,
    protocol: selectedProto,
    length,
    info,
    hexData: "001122334455001a2b3c4d5e08004500003c1a2b00004006a1b2c0a80169c0a80101d35600350028a1b21a2b01000001",
    layers: [
      {
        name: `Frame ${packetNumber}: ${length} bytes on wire`,
        summary: `${length} bytes captured`,
        fields: [
          { label: "Arrival Time", value: `${relTime.toFixed(6)}s` },
          { label: "Frame Length", value: `${length} bytes` },
        ],
      },
      {
        name: `Internet Protocol Version 4, Src: ${srcIp}, Dst: ${dstIp}`,
        summary: `IPv4 packet`,
        fields: [
          { label: "Source Address", value: srcIp },
          { label: "Destination Address", value: dstIp },
        ],
      },
      {
        name: `Transport Layer (${selectedProto})`,
        summary: `Ports ${srcPort} -> ${dstPort}`,
        fields: [
          { label: "Source Port", value: String(srcPort) },
          { label: "Destination Port", value: String(dstPort) },
        ],
      },
    ],
  };

  return { packet: pkt };
}
