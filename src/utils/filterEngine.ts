import { Packet } from "../types";

export interface FilterResult {
  isValid: boolean;
  errorMessage?: string;
}

export function validateFilterSyntax(filterText: string): FilterResult {
  const trimmed = filterText.trim();
  if (!trimmed) return { isValid: true };

  // Basic syntax check for balanced quotes and parenthetical expressions
  let quoteCount = 0;
  for (let i = 0; i < trimmed.length; i++) {
    if (trimmed[i] === '"' || trimmed[i] === "'") quoteCount++;
  }
  if (quoteCount % 2 !== 0) {
    return { isValid: false, errorMessage: "Unmatched quotation mark in filter expression." };
  }

  return { isValid: true };
}

export function filterPackets(packets: Packet[], filterText: string): Packet[] {
  const trimmed = filterText.trim().toLowerCase();
  if (!trimmed) return packets;

  // Split by OR operators first
  const orClauses = trimmed.split(/\s+(?:or|\|\|)\s+/);

  return packets.filter((packet) => {
    // Packet matches if ANY OR clause is satisfied
    return orClauses.some((orClause) => {
      // Each OR clause requires ALL AND tokens to be true
      const andTokens = orClause.split(/\s+(?:and|\&\&)\s+/);

      return andTokens.every((token) => {
        return evaluateToken(packet, token.trim());
      });
    });
  });
}

function evaluateToken(packet: Packet, token: string): boolean {
  if (!token) return true;

  // Check for 'not' or '!'
  if (token.startsWith("not ") || token.startsWith("!")) {
    const subToken = token.replace(/^(not\s+|!)/, "").trim();
    return !evaluateToken(packet, subToken);
  }

  // Single word protocol filter e.g., "dns", "http", "tcp", "udp", "icmp", "tls", "arp", "ssh", "mqtt", "quic"
  if (/^[a-z0-9_]+$/.test(token)) {
    const proto = packet.protocol.toLowerCase();
    if (token === "error" || token === "errors") return !!packet.error;
    if (token === "retransmission" || token === "retransmissions") return !!packet.retransmission;
    if (token === "suspicious" || token === "threat") return !!packet.suspicious || packet.riskLevel === "high";

    if (proto === token) return true;
    if (token === "ip" && (packet.src.includes(".") || packet.dst.includes("."))) return true;
    if (token === "ipv6" && (packet.src.includes(":") || packet.dst.includes(":"))) return true;
    if (token === "tcp" && (proto === "tcp" || proto === "http" || proto === "https" || proto === "tls" || proto === "ssh")) return true;
    if (token === "udp" && (proto === "udp" || proto === "dns" || proto === "quic" || proto === "dhcp" || proto === "ntp")) return true;

    // Check layer names
    return packet.layers.some((layer) => layer.name.toLowerCase().includes(token));
  }

  // Comparison operator evaluation e.g. "ip.addr == 192.168.1.1", "tcp.port == 443", "frame.len > 100"
  const match = token.match(/^([a-z0-9_\.]+)\s*(==|!=|>=|<=|>|<|contains|matches)\s*(.+)$/);
  if (!match) {
    // Fallback search in info, src, dst or protocol
    const cleanSearch = token.replace(/["']/g, "");
    return (
      packet.info.toLowerCase().includes(cleanSearch) ||
      packet.src.toLowerCase().includes(cleanSearch) ||
      packet.dst.toLowerCase().includes(cleanSearch) ||
      packet.protocol.toLowerCase().includes(cleanSearch)
    );
  }

  const [, field, op, rawVal] = match;
  const val = rawVal.replace(/["']/g, "").trim();
  const numVal = parseFloat(val);

  switch (field) {
    case "ip.addr":
    case "ip.host":
      return compareString(packet.src, val, op) || compareString(packet.dst, val, op);

    case "ip.src":
    case "ip.src_host":
      return compareString(packet.src, val, op);

    case "ip.dst":
    case "ip.dst_host":
      return compareString(packet.dst, val, op);

    case "ip.proto":
    case "protocol":
      return compareString(packet.protocol, val, op);

    case "tcp.port":
    case "udp.port":
      return (
        compareNum(packet.srcPort || 0, numVal, op) ||
        compareNum(packet.dstPort || 0, numVal, op)
      );

    case "tcp.srcport":
    case "udp.srcport":
      return compareNum(packet.srcPort || 0, numVal, op);

    case "tcp.dstport":
    case "udp.dstport":
      return compareNum(packet.dstPort || 0, numVal, op);

    case "frame.len":
    case "frame.length":
    case "length":
      return compareNum(packet.length, numVal, op);

    case "frame.number":
    case "frame.no":
    case "no":
      return compareNum(packet.no, numVal, op);

    case "frame.time_relative":
    case "time":
      return compareNum(packet.time, numVal, op);

    case "tcp.flags.syn":
      return compareNum(packet.flags?.syn ? 1 : 0, numVal, op);

    case "tcp.flags.ack":
      return compareNum(packet.flags?.ack ? 1 : 0, numVal, op);

    case "tcp.flags.fin":
      return compareNum(packet.flags?.fin ? 1 : 0, numVal, op);

    case "tcp.flags.rst":
      return compareNum(packet.flags?.rst ? 1 : 0, numVal, op);

    case "http.request":
      return packet.protocol === "HTTP" && packet.info.includes("GET") || packet.info.includes("POST");

    case "info":
    case "frame.info":
      return compareString(packet.info, val, op);

    default:
      // Search in all layers
      return packet.layers.some((layer) =>
        layer.fields.some(
          (f) =>
            f.label.toLowerCase().includes(field) &&
            compareString(f.value, val, op)
        )
      );
  }
}

function compareString(actual: string, target: string, op: string): boolean {
  const act = actual.toLowerCase();
  const tgt = target.toLowerCase();

  switch (op) {
    case "==":
      return act === tgt;
    case "!=":
      return act !== tgt;
    case "contains":
    case "matches":
      return act.includes(tgt);
    default:
      return act === tgt;
  }
}

function compareNum(actual: number, target: number, op: string): boolean {
  if (isNaN(actual) || isNaN(target)) return false;

  switch (op) {
    case "==":
      return actual === target;
    case "!=":
      return actual !== target;
    case ">":
      return actual > target;
    case "<":
      return actual < target;
    case ">=":
      return actual >= target;
    case "<=":
      return actual <= target;
    default:
      return actual === target;
  }
}
