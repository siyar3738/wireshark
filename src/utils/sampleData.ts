import { SampleDataset, Packet, SecurityAlert } from "../types";

export const SAMPLE_DATASETS: SampleDataset[] = [
  {
    id: "web-https",
    name: "Web Browsing & HTTPS Traffic",
    category: "General Traffic",
    description: "DNS resolution, TLS 1.3 Client/Server Handshakes, HTTP GET requests, and TCP connection establishment.",
    packetCount: 18,
    duration: "4.2s",
    alerts: [
      {
        id: "alert-1",
        timestamp: "0.852s",
        type: "Cleartext Password",
        severity: "medium",
        sourceIp: "192.168.1.105",
        destinationIp: "104.21.55.12",
        protocol: "HTTP",
        message: "Unencrypted HTTP POST detected submitting credentials to /login.php",
        packetNo: 8,
      }
    ],
    packets: generateWebHttpsPackets()
  },
  {
    id: "security-incident",
    name: "Security Incident (Port Scan & SYN Flood)",
    category: "Cybersecurity",
    description: "Reconnaissance port scan from untrusted IP, TCP SYN Flood attempt, and unencrypted auth leak.",
    packetCount: 26,
    duration: "1.8s",
    alerts: [
      {
        id: "sec-1",
        timestamp: "0.012s",
        type: "Port Scan",
        severity: "high",
        sourceIp: "10.0.0.105",
        destinationIp: "192.168.1.1",
        protocol: "TCP",
        message: "Rapid sequential TCP SYN packets detected across ports 21, 22, 80, 443, 8080, 3306",
        packetNo: 3,
      },
      {
        id: "sec-2",
        timestamp: "0.450s",
        type: "SYN Flood",
        severity: "critical",
        sourceIp: "10.0.0.105",
        destinationIp: "192.168.1.1",
        protocol: "TCP",
        message: "High velocity SYN packet burst without corresponding ACK responses (Potential DoS)",
        packetNo: 15,
      }
    ],
    packets: generateSecurityIncidentPackets()
  },
  {
    id: "iot-smart-home",
    name: "IoT & Smart Home Network",
    category: "IoT / Embedded",
    description: "MQTT telemetry updates, CoAP light switch controls, DNS queries, and NTP clock sync.",
    packetCount: 16,
    duration: "12.5s",
    packets: generateIoTPackets()
  },
  {
    id: "enterprise-mixed",
    name: "Enterprise Core Network",
    category: "Enterprise",
    description: "DHCP lease renewals, DNS queries, SSH admin sessions, ICMP diagnostics, and TCP retransmissions.",
    packetCount: 22,
    duration: "8.1s",
    alerts: [
      {
        id: "ent-1",
        timestamp: "3.412s",
        type: "High Retransmissions",
        severity: "medium",
        sourceIp: "192.168.1.45",
        destinationIp: "172.16.0.10",
        protocol: "TCP",
        message: "Repeated TCP retransmissions detected indicating network congestion or bad cabling",
        packetNo: 14,
      }
    ],
    packets: generateEnterprisePackets()
  }
];

function generateWebHttpsPackets(): Packet[] {
  return [
    {
      no: 1,
      time: 0.000000,
      src: "192.168.1.105",
      srcPort: 54102,
      srcMac: "00:1A:2B:3C:4D:5E",
      dst: "192.168.1.1",
      dstPort: 53,
      dstMac: "00:11:22:33:44:55",
      protocol: "DNS",
      length: 74,
      info: "Standard query 0x1a2b A api.example.com",
      hexData: "001122334455001a2b3c4d5e08004500003c1a2b00004011a1b2c0a80169c0a80101d35600350028a1b21a2b0100000100000000000003617069076578616d706c6503636f6d0000010001",
      layers: [
        {
          name: "Frame 1: 74 bytes on wire",
          summary: "74 bytes captured (592 bits)",
          fields: [
            { label: "Arrival Time", value: "2026-08-03 21:10:00.000000000" },
            { label: "Frame Length", value: "74 bytes (592 bits)" },
            { label: "Capture Length", value: "74 bytes (592 bits)" }
          ]
        },
        {
          name: "Ethernet II, Src: 00:1a:2b:3c:4d:5e, Dst: 00:11:22:33:44:55",
          summary: "Destination: 00:11:22:33:44:55, Source: 00:1a:2b:3c:4d:5e",
          fields: [
            { label: "Destination", value: "00:11:22:33:44:55", byteOffset: 0, byteLength: 6 },
            { label: "Source", value: "00:1a:2b:3c:4d:5e", byteOffset: 6, byteLength: 6 },
            { label: "Type", value: "IPv4 (0x0800)", byteOffset: 12, byteLength: 2 }
          ]
        },
        {
          name: "Internet Protocol Version 4, Src: 192.168.1.105, Dst: 192.168.1.1",
          summary: "IPv4 header length 20 bytes, TTL 64, Protocol UDP (17)",
          fields: [
            { label: "Version", value: "4", byteOffset: 14, byteLength: 1 },
            { label: "Header Length", value: "20 bytes (5)", byteOffset: 14, byteLength: 1 },
            { label: "Total Length", value: "60", byteOffset: 16, byteLength: 2 },
            { label: "Protocol", value: "UDP (17)", byteOffset: 23, byteLength: 1 },
            { label: "Source Address", value: "192.168.1.105", byteOffset: 26, byteLength: 4 },
            { label: "Destination Address", value: "192.168.1.1", byteOffset: 30, byteLength: 4 }
          ]
        },
        {
          name: "User Datagram Protocol, Src Port: 54102, Dst Port: 53",
          summary: "Source Port: 54102, Destination Port: 53, Length: 40",
          fields: [
            { label: "Source Port", value: "54102", byteOffset: 34, byteLength: 2 },
            { label: "Destination Port", value: "53 (DNS)", byteOffset: 36, byteLength: 2 },
            { label: "Length", value: "40", byteOffset: 38, byteLength: 2 }
          ]
        },
        {
          name: "Domain Name System (query)",
          summary: "Transaction ID: 0x1a2b, Query: api.example.com (A record)",
          fields: [
            { label: "Transaction ID", value: "0x1a2b", byteOffset: 42, byteLength: 2 },
            { label: "Flags", value: "0x0100 (Standard query)", byteOffset: 44, byteLength: 2 },
            { label: "Questions", value: "1", byteOffset: 46, byteLength: 2 },
            { label: "Query Name", value: "api.example.com", byteOffset: 54, byteLength: 17 }
          ]
        }
      ]
    },
    {
      no: 2,
      time: 0.018240,
      src: "192.168.1.1",
      srcPort: 53,
      dst: "192.168.1.105",
      dstPort: 54102,
      protocol: "DNS",
      length: 90,
      info: "Standard query response 0x1a2b A api.example.com A 104.21.55.12",
      hexData: "001a2b3c4d5e00112233445508004500004c1a2c00004011a1b1c0a80101c0a801690035d3560038a1b11a2b8180000100010000000003617069076578616d706c6503636f6d0000010001c00c000100010000012c00046815370c",
      layers: [
        {
          name: "Frame 2: 90 bytes on wire",
          summary: "90 bytes captured",
          fields: [
            { label: "Arrival Time", value: "2026-08-03 21:10:00.018240000" },
            { label: "Frame Length", value: "90 bytes" }
          ]
        },
        {
          name: "Internet Protocol Version 4, Src: 192.168.1.1, Dst: 192.168.1.105",
          summary: "IPv4 header, Src 192.168.1.1, Dst 192.168.1.105",
          fields: [
            { label: "Source Address", value: "192.168.1.1" },
            { label: "Destination Address", value: "192.168.1.105" }
          ]
        },
        {
          name: "Domain Name System (response)",
          summary: "Answers: api.example.com -> 104.21.55.12 (TTL 300)",
          fields: [
            { label: "Query Name", value: "api.example.com" },
            { label: "Address", value: "104.21.55.12" },
            { label: "Time to live", value: "300 seconds" }
          ]
        }
      ]
    },
    {
      no: 3,
      time: 0.024110,
      src: "192.168.1.105",
      srcPort: 49812,
      dst: "104.21.55.12",
      dstPort: 443,
      protocol: "TCP",
      length: 66,
      flags: { syn: true },
      info: "49812 → 443 [SYN] Seq=0 Win=64240 Len=0 MSS=1460 SACK_PERM=1 WS=128",
      hexData: "001122334455001a2b3c4d5e0800450000344a100000400671a1c0a801696815370cc29401bb00000000000000008002faf01a2b0000020405b40103030701010402",
      layers: [
        {
          name: "Transmission Control Protocol, Src Port: 49812, Dst Port: 443, Seq: 0, Flags: SYN",
          summary: "Header length: 32 bytes, Flags: SYN (Synchronization)",
          fields: [
            { label: "Source Port", value: "49812", byteOffset: 34, byteLength: 2 },
            { label: "Destination Port", value: "443 (HTTPS/TLS)", byteOffset: 36, byteLength: 2 },
            { label: "Sequence Number", value: "0 (relative sequence number)", byteOffset: 38, byteLength: 4 },
            { label: "Header Length", value: "32 bytes (8)", byteOffset: 46, byteLength: 1 },
            { label: "SYN Flag", value: "Set (1)", byteOffset: 47, byteLength: 1 },
            { label: "Window Size", value: "64240", byteOffset: 48, byteLength: 2 },
            { label: "Maximum Segment Size (MSS)", value: "1460 bytes", byteOffset: 54, byteLength: 4 }
          ]
        }
      ]
    },
    {
      no: 4,
      time: 0.045120,
      src: "104.21.55.12",
      srcPort: 443,
      dst: "192.168.1.105",
      dstPort: 49812,
      protocol: "TCP",
      length: 66,
      flags: { syn: true, ack: true },
      info: "443 → 49812 [SYN, ACK] Seq=0 Ack=1 Win=65535 Len=0 MSS=1460 SACK_PERM=1 WS=256",
      hexData: "001a2b3c4d5e001122334455080045000034000040003406bb116815370cc0a8016901bbc2943a410000000000018012ffff2a1b0000020405b40101040201030308",
      layers: [
        {
          name: "Transmission Control Protocol, Src Port: 443, Dst Port: 49812, Flags: SYN, ACK",
          summary: "Header length: 32 bytes, Flags: SYN, ACK",
          fields: [
            { label: "Source Port", value: "443" },
            { label: "Destination Port", value: "49812" },
            { label: "SYN Flag", value: "Set (1)" },
            { label: "ACK Flag", value: "Set (1)" },
            { label: "Acknowledgment Number", value: "1 (relative)" }
          ]
        }
      ]
    },
    {
      no: 5,
      time: 0.045210,
      src: "192.168.1.105",
      srcPort: 49812,
      dst: "104.21.55.12",
      dstPort: 443,
      protocol: "TCP",
      length: 54,
      flags: { ack: true },
      info: "49812 → 443 [ACK] Seq=1 Ack=1 Win=64240 Len=0",
      hexData: "001122334455001a2b3c4d5e0800450000284a110000400671ab0a801696815370cc29401bb000000013a4100015010faf011220000",
      layers: [
        {
          name: "Transmission Control Protocol, Src Port: 49812, Dst Port: 443, Flags: ACK",
          summary: "TCP 3-Way Handshake Completed",
          fields: [
            { label: "ACK Flag", value: "Set (1)" },
            { label: "Sequence Number", value: "1" },
            { label: "Acknowledgment Number", value: "1" }
          ]
        }
      ]
    },
    {
      no: 6,
      time: 0.051020,
      src: "192.168.1.105",
      srcPort: 49812,
      dst: "104.21.55.12",
      dstPort: 443,
      protocol: "TLS",
      length: 517,
      info: "Client Hello, TLS 1.3, Sni: api.example.com",
      hexData: "16030101ca010001c60303a1b2c3d4e5f600112233445566778899aabbccddeeff001122334455667788992000000010020000000000000000000000000000000000000000000000000000000130100130200130301000000",
      layers: [
        {
          name: "Transport Layer Security, TLS v1.3 Record Layer: Handshake Protocol: Client Hello",
          summary: "TLS 1.3 Client Hello (SNI: api.example.com)",
          fields: [
            { label: "Record Type", value: "Handshake (22)" },
            { label: "Version", value: "TLS 1.2 (0x0303)" },
            { label: "Handshake Type", value: "Client Hello (1)" },
            { label: "Server Name Indication", value: "api.example.com" },
            { label: "Supported Versions", value: "TLS 1.3, TLS 1.2" },
            { label: "Cipher Suites", value: "TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256" }
          ]
        }
      ]
    },
    {
      no: 7,
      time: 0.082100,
      src: "104.21.55.12",
      srcPort: 443,
      dst: "192.168.1.105",
      dstPort: 49812,
      protocol: "TLS",
      length: 1240,
      info: "Server Hello, Change Cipher Spec, Application Data",
      hexData: "160303007a02000076030311223344556677889900112233445566778899aabbccddeeff0011223344556600130100004e00330024001d00201122334455667788990011223344556677889900112233445566778899001122",
      layers: [
        {
          name: "Transport Layer Security, TLS v1.3 Record Layer: Server Hello",
          summary: "TLS 1.3 Handshake completed & encrypted channel established",
          fields: [
            { label: "Handshake Type", value: "Server Hello (2)" },
            { label: "Cipher Suite", value: "TLS_AES_256_GCM_SHA384 (0x1301)" },
            { label: "Key Exchange", value: "X25519" }
          ]
        }
      ]
    },
    {
      no: 8,
      time: 0.852100,
      src: "192.168.1.105",
      srcPort: 52100,
      dst: "104.21.55.12",
      dstPort: 80,
      protocol: "HTTP",
      length: 312,
      error: true,
      suspicious: true,
      riskLevel: "medium",
      riskReason: "Cleartext credentials submitted over insecure HTTP",
      info: "POST /login.php HTTP/1.1 (application/x-www-form-urlencoded)",
      hexData: "504f5354202f6c6f67696e2e70687020485454502f312e310d0a486f73743a206578616d706c652e636f6d0d0a436f6e74656e742d547970653a206170706c69636174696f6e2f782d7777772d666f726d2d75726c656e636f6465640d0a0d0a757365723d61646d696e26706173733d53656372657431323321",
      layers: [
        {
          name: "Hypertext Transfer Protocol",
          summary: "Unencrypted HTTP POST containing credentials!",
          fields: [
            { label: "Request Method", value: "POST" },
            { label: "Request URI", value: "/login.php" },
            { label: "Request Version", value: "HTTP/1.1" },
            { label: "Host", value: "example.com" },
            { label: "Form Body Data", value: "user=admin&pass=Secret123!" }
          ]
        }
      ]
    },
    {
      no: 9,
      time: 0.910200,
      src: "104.21.55.12",
      srcPort: 80,
      dst: "192.168.1.105",
      dstPort: 52100,
      protocol: "HTTP",
      length: 245,
      info: "HTTP/1.1 200 OK (text/html)",
      hexData: "485454502f312e3120323030204f4b0d0a436f6e74656e742d547970653a20746578742f68746d6c0d0a0d0a3c68313e4c6f67696e205375636365737366756c3c2f68313e",
      layers: [
        {
          name: "Hypertext Transfer Protocol (Response)",
          summary: "HTTP/1.1 200 OK",
          fields: [
            { label: "Status Code", value: "200" },
            { label: "Response Phrase", value: "OK" },
            { label: "Content-Type", value: "text/html" }
          ]
        }
      ]
    }
  ];
}

function generateSecurityIncidentPackets(): Packet[] {
  const packets: Packet[] = [];
  const ports = [21, 22, 23, 25, 80, 110, 139, 443, 445, 1433, 3306, 5432, 8080];

  let time = 0.000;
  let pNo = 1;

  // Reconnaissance Port Scan
  ports.forEach((port) => {
    packets.push({
      no: pNo++,
      time: parseFloat(time.toFixed(4)),
      src: "10.0.0.105",
      srcPort: 45000 + pNo,
      dst: "192.168.1.1",
      dstPort: port,
      protocol: "TCP",
      length: 60,
      flags: { syn: true },
      suspicious: true,
      riskLevel: "medium",
      riskReason: `Port Scan Probe on target port ${port}`,
      info: `4500${pNo} → ${port} [SYN] Seq=0 Win=1024 Len=0`,
      hexData: "00112233445500aa3344556608004500002812340000400688990a000069c0a80101afc8005000000000000000005002040012340000",
      layers: [
        {
          name: `TCP Port Scan Probe to Port ${port}`,
          summary: `Port Scan from untrusted host 10.0.0.105`,
          fields: [
            { label: "Target Port", value: `${port}` },
            { label: "Flag", value: "SYN" }
          ]
        }
      ]
    });

    time += 0.002;

    // Reset from closed ports
    if (port !== 80 && port !== 443) {
      packets.push({
        no: pNo++,
        time: parseFloat(time.toFixed(4)),
        src: "192.168.1.1",
        srcPort: port,
        dst: "10.0.0.105",
        dstPort: 45000 + pNo - 1,
        protocol: "TCP",
        length: 54,
        flags: { rst: true, ack: true },
        error: true,
        info: `${port} → 4500${pNo - 1} [RST, ACK] Seq=1 Ack=1 Win=0`,
        hexData: "00aa334455660011223344550800450000280000000040069900c0a801010a0000690050afc800000001000000015014000000000000",
        layers: [
          {
            name: "TCP Reset / Connection Refused",
            summary: "Port closed, RST sent",
            fields: [
              { label: "Flags", value: "RST, ACK" }
            ]
          }
        ]
      });
      time += 0.001;
    }
  });

  // SYN Flood Burst
  for (let i = 0; i < 6; i++) {
    time += 0.001;
    packets.push({
      no: pNo++,
      time: parseFloat(time.toFixed(4)),
      src: `10.0.0.${100 + i}`,
      srcPort: 32000 + i * 11,
      dst: "192.168.1.1",
      dstPort: 80,
      protocol: "TCP",
      length: 60,
      flags: { syn: true },
      suspicious: true,
      riskLevel: "high",
      riskReason: "SYN Flood DoS attack packet without ACK response",
      info: `${32000 + i * 11} → 80 [SYN] Seq=${i * 1000} Win=512 Len=0`,
      hexData: "00112233445500aa3344556608004500002812340000400688990a000069c0a80101afc8005000000000000000005002020012340000",
      layers: [
        {
          name: "TCP SYN Flood Attack Packet",
          summary: "Spoofed IP source burst targeting HTTP service",
          fields: [
            { label: "Source IP", value: `10.0.0.${100 + i}` },
            { label: "Target Port", value: "80" }
          ]
        }
      ]
    });
  }

  return packets;
}

function generateIoTPackets(): Packet[] {
  return [
    {
      no: 1,
      time: 0.000000,
      src: "192.168.1.140",
      srcPort: 1883,
      dst: "192.168.1.10",
      dstPort: 1883,
      protocol: "MQTT",
      length: 82,
      info: "Publish Message [home/sensor/livingroom/temp] QOS: 0, Payload: 21.5C",
      hexData: "301c001e686f6d652f73656e736f722f6c6976696e67726f6f6d2f74656d7032312e3543",
      layers: [
        {
          name: "MQ Telemetry Transport Protocol (MQTT)",
          summary: "Publish Message to topic home/sensor/livingroom/temp",
          fields: [
            { label: "Header Flags", value: "0x30 (Publish Message)" },
            { label: "Topic", value: "home/sensor/livingroom/temp" },
            { label: "QoS Level", value: "At most once (0)" },
            { label: "Payload", value: "21.5C" }
          ]
        }
      ]
    },
    {
      no: 2,
      time: 1.250000,
      src: "192.168.1.141",
      srcPort: 5683,
      dst: "192.168.1.10",
      dstPort: 5683,
      protocol: "UDP",
      length: 64,
      info: "CoAP CON POST /light/kitchen payload: state=ON",
      hexData: "40021234b56c69676874076b69746368656eff73746174653d4f4e",
      layers: [
        {
          name: "Constrained Application Protocol (CoAP)",
          summary: "Confirmable POST /light/kitchen state=ON",
          fields: [
            { label: "Code", value: "0.02 (POST)" },
            { label: "Uri-Path", value: "light/kitchen" },
            { label: "Payload", value: "state=ON" }
          ]
        }
      ]
    },
    {
      no: 3,
      time: 5.012000,
      src: "192.168.1.140",
      srcPort: 123,
      dst: "216.239.35.0",
      dstPort: 123,
      protocol: "NTP",
      length: 90,
      info: "NTP Version 4, Client, Kiss-o'-death",
      hexData: "23000000000000000000000000000000000000000000000000000000000000000000000000000000e123456789abcdef",
      layers: [
        {
          name: "Network Time Protocol (NTP)",
          summary: "NTP Client Time Synchronization Query",
          fields: [
            { label: "Mode", value: "Client (3)" },
            { label: "Version", value: "NTPv4" }
          ]
        }
      ]
    }
  ];
}

function generateEnterprisePackets(): Packet[] {
  return [
    {
      no: 1,
      time: 0.000000,
      src: "0.0.0.0",
      srcPort: 68,
      dst: "255.255.255.255",
      dstPort: 67,
      protocol: "DHCP",
      length: 342,
      info: "DHCP Request - Transaction ID 0x39a3f12c",
      hexData: "0101060039a3f12c0000800000000000000000000000000000000000001a2b3c4d5e0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000063825363",
      layers: [
        {
          name: "Dynamic Host Configuration Protocol (DHCP Request)",
          summary: "DHCP Request for IP address assignment",
          fields: [
            { label: "Message Type", value: "Boot Request (1)" },
            { label: "Client MAC", value: "00:1a:2b:3c:4d:5e" },
            { label: "Requested IP", value: "192.168.1.45" }
          ]
        }
      ]
    },
    {
      no: 2,
      time: 0.021000,
      src: "192.168.1.1",
      srcPort: 67,
      dst: "192.168.1.45",
      dstPort: 68,
      protocol: "DHCP",
      length: 342,
      info: "DHCP ACK - IP: 192.168.1.45, Lease: 86400s",
      hexData: "0201060039a3f12c0000000000000000c0a8012d0000000000000000001a2b3c4d5e0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000063825363",
      layers: [
        {
          name: "Dynamic Host Configuration Protocol (DHCP ACK)",
          summary: "Assigned IP 192.168.1.45, Subnet 255.255.255.0, Gateway 192.168.1.1",
          fields: [
            { label: "Your (client) IP", value: "192.168.1.45" },
            { label: "Subnet Mask", value: "255.255.255.0" },
            { label: "Lease Time", value: "86400 seconds (1 day)" }
          ]
        }
      ]
    },
    {
      no: 3,
      time: 1.100000,
      src: "192.168.1.45",
      srcPort: 58210,
      dst: "10.0.0.5",
      dstPort: 22,
      protocol: "SSH",
      length: 114,
      info: "SSH-2.0-OpenSSH_9.3p1 Client Key Exchange",
      hexData: "5353482d322e302d4f70656e5353485f392e3370310d0a",
      layers: [
        {
          name: "Secure Shell Protocol (SSH-2.0)",
          summary: "SSH Key Exchange and Cipher Negotiation",
          fields: [
            { label: "Protocol Version", value: "SSH-2.0" },
            { label: "Software Version", value: "OpenSSH_9.3p1" }
          ]
        }
      ]
    },
    {
      no: 4,
      time: 3.412000,
      src: "192.168.1.45",
      srcPort: 48922,
      dst: "172.16.0.10",
      dstPort: 443,
      protocol: "TCP",
      length: 1514,
      retransmission: true,
      error: true,
      info: "[TCP Retransmission] 48922 → 443 [ACK] Seq=1461 Ack=1 Win=64240 Len=1460",
      hexData: "001122334455001a2b3c4d5e0800450005dc12340000400671abc0a8012dac10000ac30201bb000005b5000000015010faf011220000",
      layers: [
        {
          name: "TCP Retransmission Detected",
          summary: "Packet lost on link; retransmitted frame #14",
          fields: [
            { label: "Status", value: "Retransmission" },
            { label: "Original Segment", value: "Frame #14" }
          ]
        }
      ]
    }
  ];
}
