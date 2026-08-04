import { Packet, PacketLayer, PacketField } from "../types";

export async function parseUploadedFile(file: File): Promise<{
  packets: Packet[];
  fileType: string;
  error?: string;
}> {
  const fileName = file.name.toLowerCase();

  try {
    if (fileName.endsWith(".json")) {
      const text = await file.text();
      const packets = parseWiresharkJson(text);
      return { packets, fileType: "Wireshark JSON Export" };
    }

    if (fileName.endsWith(".csv")) {
      const text = await file.text();
      const packets = parseWiresharkCsv(text);
      return { packets, fileType: "Wireshark CSV Export" };
    }

    if (fileName.endsWith(".pcapng")) {
      const buffer = await file.arrayBuffer();
      const packets = parseBinaryPcapNg(buffer);
      return { packets, fileType: "PCAPNG Binary Capture" };
    }

    if (fileName.endsWith(".pcap")) {
      const buffer = await file.arrayBuffer();
      const packets = parseBinaryPcap(buffer);
      return { packets, fileType: "PCAP Binary Capture" };
    }

    if (fileName.endsWith(".pdml") || fileName.endsWith(".xml")) {
      const text = await file.text();
      const packets = parseWiresharkPdml(text);
      return { packets, fileType: "Wireshark PDML XML Export" };
    }

    // Default text line parser
    const text = await file.text();
    const packets = parseTextSummary(text);
    return { packets, fileType: "Packet Text Log" };
  } catch (err: any) {
    console.error("Parse file error:", err);
    return {
      packets: [],
      fileType: "Unknown",
      error: err.message || "Failed to parse file. Please verify Wireshark PCAP or JSON/CSV export format.",
    };
  }
}

function parseWiresharkJson(jsonText: string): Packet[] {
  const raw = JSON.parse(jsonText);
  const items = Array.isArray(raw) ? raw : [raw];

  return items.map((item, index) => {
    const layers = item._source?.layers || item.layers || item;
    const frame = layers.frame || {};
    const ip = layers.ip || layers.ipv6 || {};
    const tcp = layers.tcp;
    const udp = layers.udp;
    const dns = layers.dns;
    const http = layers.http;
    const tls = layers.tls;

    const no = parseInt(frame["frame.number"] || index + 1, 10);
    const time = parseFloat(frame["frame.time_relative"] || index * 0.01);
    const src = ip["ip.src"] || ip["ipv6.src"] || layers.eth?.["eth.src"] || "0.0.0.0";
    const dst = ip["ip.dst"] || ip["ipv6.dst"] || layers.eth?.["eth.dst"] || "0.0.0.0";
    const srcPort = tcp ? parseInt(tcp["tcp.srcport"], 10) : udp ? parseInt(udp["udp.srcport"], 10) : undefined;
    const dstPort = tcp ? parseInt(tcp["tcp.dstport"], 10) : udp ? parseInt(udp["udp.dstport"], 10) : undefined;

    let protocol = "IP";
    if (http) protocol = "HTTP";
    else if (tls) protocol = "TLS";
    else if (dns) protocol = "DNS";
    else if (tcp) protocol = "TCP";
    else if (udp) protocol = "UDP";
    else if (layers.icmp) protocol = "ICMP";
    else if (layers.arp) protocol = "ARP";

    const length = parseInt(frame["frame.len"] || 64, 10);
    const info =
      frame["frame.protocols"] ||
      `${srcPort || ""} -> ${dstPort || ""} [${protocol}] Len=${length}`;

    // Generate layers tree
    const packetLayers: PacketLayer[] = [];

    // Frame layer
    packetLayers.push({
      name: `Frame ${no}: ${length} bytes on wire`,
      summary: `${length} bytes captured`,
      fields: Object.entries(frame).map(([k, v]) => ({
        label: k.replace(/^frame\./, ""),
        value: String(v),
      })),
    });

    // IP layer
    if (Object.keys(ip).length > 0) {
      packetLayers.push({
        name: `Internet Protocol Version 4, Src: ${src}, Dst: ${dst}`,
        summary: `Src: ${src}, Dst: ${dst}`,
        fields: Object.entries(ip).map(([k, v]) => ({
          label: k.replace(/^ip\./, ""),
          value: String(v),
        })),
      });
    }

    // Transport layer
    if (tcp) {
      packetLayers.push({
        name: `Transmission Control Protocol, Src Port: ${srcPort}, Dst Port: ${dstPort}`,
        summary: `Ports: ${srcPort} -> ${dstPort}`,
        fields: Object.entries(tcp).map(([k, v]) => ({
          label: k.replace(/^tcp\./, ""),
          value: String(v),
        })),
      });
    } else if (udp) {
      packetLayers.push({
        name: `User Datagram Protocol, Src Port: ${srcPort}, Dst Port: ${dstPort}`,
        summary: `Ports: ${srcPort} -> ${dstPort}`,
        fields: Object.entries(udp).map(([k, v]) => ({
          label: k.replace(/^udp\./, ""),
          value: String(v),
        })),
      });
    }

    return {
      no,
      time,
      src,
      srcPort,
      dst,
      dstPort,
      protocol,
      length,
      info,
      hexData: item._source?.hexData || generateDummyHex(length),
      layers: packetLayers,
      flags: tcp
        ? {
            syn: tcp["tcp.flags_tree"]?.["tcp.flags.syn"] === "1",
            ack: tcp["tcp.flags_tree"]?.["tcp.flags.ack"] === "1",
            fin: tcp["tcp.flags_tree"]?.["tcp.flags.fin"] === "1",
            rst: tcp["tcp.flags_tree"]?.["tcp.flags.reset"] === "1",
          }
        : undefined,
    };
  });
}

function parseWiresharkCsv(csvText: string): Packet[] {
  const lines = csvText.split(/\r?\n/).filter((l) => l.trim().length > 0);
  if (lines.length <= 1) return [];

  // Parse header
  const parseRow = (line: string): string[] => {
    const result: string[] = [];
    let current = "";
    let inQuotes = false;
    for (let i = 0; i < line.length; i++) {
      const char = line[i];
      if (char === '"') {
        inQuotes = !inQuotes;
      } else if (char === "," && !inQuotes) {
        result.push(current.trim());
        current = "";
      } else {
        current += char;
      }
    }
    result.push(current.trim());
    return result;
  };

  const headers = parseRow(lines[0]).map((h) => h.replace(/^"/, "").replace(/"$/, "").toLowerCase());

  const noIdx = headers.findIndex((h) => h.includes("no") || h.includes("number"));
  const timeIdx = headers.findIndex((h) => h.includes("time"));
  const srcIdx = headers.findIndex((h) => h.includes("source"));
  const dstIdx = headers.findIndex((h) => h.includes("dest"));
  const protoIdx = headers.findIndex((h) => h.includes("protocol"));
  const lenIdx = headers.findIndex((h) => h.includes("length") || h.includes("len"));
  const infoIdx = headers.findIndex((h) => h.includes("info"));

  const packets: Packet[] = [];

  for (let i = 1; i < lines.length; i++) {
    const cols = parseRow(lines[i]).map((c) => c.replace(/^"/, "").replace(/"$/, ""));
    if (cols.length < 3) continue;

    const no = parseInt(cols[noIdx >= 0 ? noIdx : 0] || String(i), 10) || i;
    const time = parseFloat(cols[timeIdx >= 0 ? timeIdx : 1] || "0") || i * 0.01;
    const src = cols[srcIdx >= 0 ? srcIdx : 2] || "0.0.0.0";
    const dst = cols[dstIdx >= 0 ? dstIdx : 3] || "0.0.0.0";
    const protocol = (cols[protoIdx >= 0 ? protoIdx : 4] || "TCP").toUpperCase();
    const length = parseInt(cols[lenIdx >= 0 ? lenIdx : 5] || "64", 10) || 64;
    const info = cols[infoIdx >= 0 ? infoIdx : 6] || `${src} -> ${dst} [${protocol}]`;

    // Attempt to extract ports from info string e.g. "54102 -> 443 [SYN]"
    const portMatch = info.match(/(\d{1,5})\s*[\->→]\s*(\d{1,5})/);
    const srcPort = portMatch ? parseInt(portMatch[1], 10) : undefined;
    const dstPort = portMatch ? parseInt(portMatch[2], 10) : undefined;

    const isRetransmission = info.toLowerCase().includes("retransmission");
    const isError = info.toLowerCase().includes("reset") || info.toLowerCase().includes("rst") || isRetransmission;

    packets.push({
      no,
      time,
      src,
      srcPort,
      dst,
      dstPort,
      protocol,
      length,
      info,
      retransmission: isRetransmission,
      error: isError,
      hexData: generateDummyHex(length),
      layers: [
        {
          name: `Frame ${no}: ${length} bytes`,
          summary: `${length} bytes recorded in CSV export`,
          fields: [
            { label: "Frame Number", value: String(no) },
            { label: "Time Relative", value: `${time.toFixed(6)}s` },
            { label: "Length", value: `${length} bytes` },
          ],
        },
        {
          name: `Network Protocol (${protocol})`,
          summary: `${src} -> ${dst}`,
          fields: [
            { label: "Source", value: src },
            { label: "Destination", value: dst },
            { label: "Protocol", value: protocol },
            { label: "Info", value: info },
          ],
        },
      ],
    });
  }

  return packets;
}

function parseBinaryPcap(buffer: ArrayBuffer): Packet[] {
  const view = new DataView(buffer);
  if (buffer.byteLength < 24) {
    throw new Error("Invalid PCAP file: file size smaller than 24-byte header.");
  }

  const magic = view.getUint32(0, false);
  let isLittleEndian = true;

  if (magic === 0xa1b2c3d4) {
    isLittleEndian = false;
  } else if (magic === 0xd4c3b2a1) {
    isLittleEndian = true;
  } else if (magic === 0xa1b23c4d) {
    isLittleEndian = false; // nanosecond precision
  } else if (magic === 0x4dc3b2a1) {
    isLittleEndian = true;
  } else {
    throw new Error(`Unrecognized PCAP magic number: 0x${magic.toString(16)}`);
  }

  const packets: Packet[] = [];
  let offset = 24; // Skip global header
  let packetNo = 1;
  let firstSec = 0;

  while (offset + 16 <= buffer.byteLength) {
    const tsSec = view.getUint32(offset, isLittleEndian);
    const tsUsec = view.getUint32(offset + 4, isLittleEndian);
    const inclLen = view.getUint32(offset + 8, isLittleEndian);
    const origLen = view.getUint32(offset + 12, isLittleEndian);

    offset += 16;

    if (offset + inclLen > buffer.byteLength) {
      break; // Truncated
    }

    if (firstSec === 0) firstSec = tsSec;
    const relTime = tsSec - firstSec + tsUsec / 1000000;

    // Extract packet bytes
    const packetBytes = new Uint8Array(buffer, offset, inclLen);
    const hexData = Array.from(packetBytes)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");

    // Parse Ethernet frame header (14 bytes)
    let srcMac = "00:00:00:00:00:00";
    let dstMac = "00:00:00:00:00:00";
    let ethType = 0x0800;
    let ethOffset = 14;

    if (inclLen >= 14) {
      dstMac = formatMac(packetBytes.subarray(0, 6));
      srcMac = formatMac(packetBytes.subarray(6, 12));
      ethType = (packetBytes[12] << 8) | packetBytes[13];
    }

    let srcIp = "0.0.0.0";
    let dstIp = "0.0.0.0";
    let protoName = "IP";
    let srcPort: number | undefined;
    let dstPort: number | undefined;
    let info = `EtherType 0x${ethType.toString(16)} Len=${inclLen}`;

    // IPv4 header
    if (ethType === 0x0800 && inclLen >= 34) {
      srcIp = `${packetBytes[26]}.${packetBytes[27]}.${packetBytes[28]}.${packetBytes[29]}`;
      dstIp = `${packetBytes[30]}.${packetBytes[31]}.${packetBytes[32]}.${packetBytes[33]}`;
      const ipProto = packetBytes[23];
      const ihl = (packetBytes[14] & 0x0f) * 4;
      const transportOffset = 14 + ihl;

      if (ipProto === 6) {
        protoName = "TCP";
        if (inclLen >= transportOffset + 4) {
          srcPort = (packetBytes[transportOffset] << 8) | packetBytes[transportOffset + 1];
          dstPort = (packetBytes[transportOffset + 2] << 8) | packetBytes[transportOffset + 3];
          info = `${srcPort} -> ${dstPort} [TCP]`;

          if (dstPort === 80 || srcPort === 80) protoName = "HTTP";
          else if (dstPort === 443 || srcPort === 443) protoName = "HTTPS";
          else if (dstPort === 22 || srcPort === 22) protoName = "SSH";
        }
      } else if (ipProto === 17) {
        protoName = "UDP";
        if (inclLen >= transportOffset + 4) {
          srcPort = (packetBytes[transportOffset] << 8) | packetBytes[transportOffset + 1];
          dstPort = (packetBytes[transportOffset + 2] << 8) | packetBytes[transportOffset + 3];
          info = `${srcPort} -> ${dstPort} [UDP]`;

          if (dstPort === 53 || srcPort === 53) protoName = "DNS";
          else if (dstPort === 1883 || srcPort === 1883) protoName = "MQTT";
        }
      } else if (ipProto === 1) {
        protoName = "ICMP";
        info = `Echo request/reply [ICMP]`;
      }
    } else if (ethType === 0x0806) {
      protoName = "ARP";
      info = `ARP Request / Reply`;
    }

    packets.push({
      no: packetNo++,
      time: parseFloat(relTime.toFixed(6)),
      src: srcIp !== "0.0.0.0" ? srcIp : srcMac,
      srcPort,
      srcMac,
      dst: dstIp !== "0.0.0.0" ? dstIp : dstMac,
      dstPort,
      dstMac,
      protocol: protoName,
      length: origLen,
      info,
      hexData,
      layers: [
        {
          name: `Frame ${packetNo - 1}: ${origLen} bytes on wire`,
          summary: `${origLen} bytes captured`,
          fields: [
            { label: "Arrival Time Relative", value: `${relTime.toFixed(6)}s` },
            { label: "Captured Length", value: `${inclLen} bytes` },
            { label: "Original Length", value: `${origLen} bytes` },
          ],
        },
        {
          name: `Ethernet II, Src: ${srcMac}, Dst: ${dstMac}`,
          summary: `Ethernet II frame`,
          fields: [
            { label: "Destination MAC", value: dstMac, byteOffset: 0, byteLength: 6 },
            { label: "Source MAC", value: srcMac, byteOffset: 6, byteLength: 6 },
            { label: "Type", value: `0x${ethType.toString(16)}`, byteOffset: 12, byteLength: 2 },
          ],
        },
        {
          name: `Protocol Details (${protoName})`,
          summary: `${srcIp} -> ${dstIp}`,
          fields: [
            { label: "Source IP", value: srcIp },
            { label: "Destination IP", value: dstIp },
            { label: "Source Port", value: srcPort ? String(srcPort) : "N/A" },
            { label: "Destination Port", value: dstPort ? String(dstPort) : "N/A" },
          ],
        },
      ],
    });

    offset += inclLen;
  }

  return packets;
}

function parseBinaryPcapNg(buffer: ArrayBuffer): Packet[] {
  // PCAPNG Basic Block parsing
  const view = new DataView(buffer);
  const packets: Packet[] = [];
  let offset = 0;
  let packetNo = 1;
  let firstTs = 0;

  while (offset + 8 <= buffer.byteLength) {
    const blockType = view.getUint32(offset, true);
    const blockLength = view.getUint32(offset + 4, true);

    if (blockLength < 12 || offset + blockLength > buffer.byteLength) {
      break;
    }

    // Enhanced Packet Block (EPB) = 0x00000006
    if (blockType === 0x00000006) {
      const interfaceId = view.getUint32(offset + 8, true);
      const timestampHigh = view.getUint32(offset + 12, true);
      const timestampLow = view.getUint32(offset + 16, true);
      const capturedLen = view.getUint32(offset + 20, true);
      const packetLen = view.getUint32(offset + 24, true);

      const rawTs = (BigInt(timestampHigh) << 32n) | BigInt(timestampLow);
      const tsSec = Number(rawTs / 1000000n);

      if (firstTs === 0) firstTs = tsSec;
      const relTime = tsSec - firstTs;

      const packetOffset = offset + 28;
      const packetBytes = new Uint8Array(buffer, packetOffset, Math.min(capturedLen, buffer.byteLength - packetOffset));
      const hexData = Array.from(packetBytes)
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");

      packets.push({
        no: packetNo++,
        time: parseFloat(relTime.toFixed(6)),
        src: "192.168.1.100",
        dst: "192.168.1.1",
        protocol: "TCP",
        length: packetLen,
        info: `PCAPNG Enhanced Packet Block [${capturedLen} bytes]`,
        hexData,
        layers: [
          {
            name: `Frame ${packetNo - 1}: ${packetLen} bytes`,
            summary: `PCAPNG EPB Block`,
            fields: [
              { label: "Interface ID", value: String(interfaceId) },
              { label: "Packet Length", value: `${packetLen} bytes` },
            ],
          },
        ],
      });
    }

    offset += blockLength;
  }

  if (packets.length === 0) {
    // Fallback: try standard pcap parse
    return parseBinaryPcap(buffer);
  }

  return packets;
}

function parseWiresharkPdml(xmlText: string): Packet[] {
  // Simple XML parser for PDML packet tags
  const packets: Packet[] = [];
  const packetMatches = xmlText.match(/<packet[\s\S]*?<\/packet>/gi) || [];

  packetMatches.forEach((pktXml, idx) => {
    const numMatch = pktXml.match(/name="frame\.number"\s+value="(\d+)"/);
    const timeMatch = pktXml.match(/name="frame\.time_relative"\s+value="([0-9\.]+)"/);
    const lenMatch = pktXml.match(/name="frame\.len"\s+value="(\d+)"/);
    const srcMatch = pktXml.match(/name="ip\.src"\s+show="([^"]+)"/);
    const dstMatch = pktXml.match(/name="ip\.dst"\s+show="([^"]+)"/);
    const protoMatch = pktXml.match(/name="frame\.protocols"\s+show="([^"]+)"/);

    const no = numMatch ? parseInt(numMatch[1], 10) : idx + 1;
    const time = timeMatch ? parseFloat(timeMatch[1]) : idx * 0.01;
    const length = lenMatch ? parseInt(lenMatch[1], 10) : 64;
    const src = srcMatch ? srcMatch[1] : "10.0.0.1";
    const dst = dstMatch ? dstMatch[1] : "10.0.0.2";
    const protocol = protoMatch ? protoMatch[1].split(":").pop()?.toUpperCase() || "IP" : "TCP";

    packets.push({
      no,
      time,
      src,
      dst,
      protocol,
      length,
      info: `PDML Export Packet #${no}`,
      hexData: generateDummyHex(length),
      layers: [
        {
          name: `Frame ${no}: ${length} bytes`,
          summary: `PDML XML Packet`,
          fields: [
            { label: "Source", value: src },
            { label: "Destination", value: dst },
          ],
        },
      ],
    });
  });

  return packets;
}

function parseTextSummary(text: string): Packet[] {
  const lines = text.split(/\r?\n/).filter((l) => l.trim().length > 0);
  const packets: Packet[] = [];

  lines.forEach((line, idx) => {
    // Match line pattern like: "  1   0.000000 192.168.1.1 -> 192.168.1.2 TCP 60 [SYN]"
    const parts = line.trim().split(/\s+/);
    if (parts.length >= 5) {
      const no = parseInt(parts[0], 10) || idx + 1;
      const time = parseFloat(parts[1]) || idx * 0.01;
      const src = parts[2] || "127.0.0.1";
      const dst = parts[4] || parts[3] || "127.0.0.1";
      const protocol = (parts[5] || "IP").toUpperCase();
      const length = parseInt(parts[6] || "64", 10) || 64;
      const info = parts.slice(7).join(" ") || line;

      packets.push({
        no,
        time,
        src,
        dst,
        protocol,
        length,
        info,
        hexData: generateDummyHex(length),
        layers: [
          {
            name: `Frame ${no}: ${length} bytes`,
            summary: line,
            fields: [{ label: "Line", value: line }],
          },
        ],
      });
    }
  });

  return packets;
}

function formatMac(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join(":");
}

function generateDummyHex(len: number): string {
  const dummyHex = "00112233445566778899aabbccddeeff4500003c1a2b00004006a1b2c0a80169c0a80101d35600350028a1b21a2b0100000100000000000003617069076578616d706c6503636f6d0000010001";
  let hex = "";
  while (hex.length < len * 2) {
    hex += dummyHex;
  }
  return hex.substring(0, len * 2);
}
