import express from "express";
import path from "path";
import dotenv from "dotenv";
import { createServer as createViteServer } from "vite";
import { GoogleGenAI } from "@google/genai";

dotenv.config();

const PORT = 3000;

let aiClient: GoogleGenAI | null = null;

function getAIClient(): GoogleGenAI {
  if (!aiClient) {
    const apiKey = process.env.GEMINI_API_KEY;
    if (!apiKey) {
      throw new Error("GEMINI_API_KEY environment variable is not configured.");
    }
    aiClient = new GoogleGenAI({
      apiKey,
      httpOptions: {
        headers: {
          "User-Agent": "aistudio-build",
        },
      },
    });
  }
  return aiClient;
}

async function startServer() {
  const app = express();
  app.use(express.json({ limit: "20mb" }));

  // API Routes
  app.get("/api/health", (req, res) => {
    res.json({ status: "ok", timestamp: new Date().toISOString() });
  });

  // AI Packet Analysis Endpoint
  app.post("/api/analyze-packet", async (req, res) => {
    try {
      const { packet } = req.body;
      if (!packet) {
        return res.status(400).json({ error: "Packet payload is required." });
      }

      const ai = getAIClient();
      const prompt = `You are an expert Network Protocol Security Specialist and Wireshark Analyst.
Analyze the following packet detail and provide a concise, high-value breakdown:

Packet Info:
- Packet No: ${packet.no}
- Timestamp / Time: ${packet.time}
- Source: ${packet.src} (MAC: ${packet.srcMac || "N/A"})
- Destination: ${packet.dst} (MAC: ${packet.dstMac || "N/A"})
- Protocol: ${packet.protocol}
- Length: ${packet.length} bytes
- Flags / Info: ${packet.info}
- Payload Preview / Hex: ${packet.hexPreview || packet.payload || "N/A"}

Please provide a JSON response with the following structure:
{
  "summary": "Brief 1-2 sentence overview of what this packet represents.",
  "protocolDetails": "Key technical explanation of the protocol exchange (e.g. TCP Handshake, DNS Query, TLS Client Hello, HTTP GET).",
  "securityAssessment": "Security status (e.g. 'Normal Traffic', 'Potential Port Scan', 'Cleartext Password Exposure', 'Malformed Header', 'Suspicious Burst').",
  "riskLevel": "'low' | 'medium' | 'high' | 'critical'",
  "recommendations": ["Actionable recommendation 1", "Actionable recommendation 2"]
}`;

      const response = await ai.models.generateContent({
        model: "gemini-3.6-flash",
        contents: prompt,
        config: {
          responseMimeType: "application/json",
          temperature: 0.3,
        },
      });

      const responseText = response.text || "{}";
      const analysis = JSON.parse(responseText);
      res.json({ success: true, analysis });
    } catch (err: any) {
      console.error("Error analyzing packet with Gemini:", err);
      res.status(500).json({
        error: err.message || "Failed to analyze packet.",
      });
    }
  });

  // AI Network Traffic Audit Endpoint
  app.post("/api/analyze-traffic", async (req, res) => {
    try {
      const { trafficStats, suspiciousPackets } = req.body;
      if (!trafficStats) {
        return res.status(400).json({ error: "Traffic statistics are required." });
      }

      const ai = getAIClient();
      const prompt = `You are a Principal Network Architect and Threat Hunter. Analyze the following capture traffic summary statistics and suspicious activity samples:

Total Packets: ${trafficStats.totalPackets}
Total Bytes: ${trafficStats.totalBytes}
Duration: ${trafficStats.durationSeconds}s
Avg Bandwidth: ${trafficStats.avgBandwidthKbps} Kbps
Protocol Counts: ${JSON.stringify(trafficStats.protocolCounts)}
Top Source IPs: ${JSON.stringify(trafficStats.topSources)}
Top Destination IPs: ${JSON.stringify(trafficStats.topDestinations)}
Error/Retransmission Packets: ${trafficStats.errorCount}
Suspicious Packets Sample: ${JSON.stringify(suspiciousPackets || []).slice(0, 1000)}

Generate an executive Wireshark Network Audit Report in JSON format:
{
  "executiveSummary": "Concise high-level summary of the network traffic behavior and overall health.",
  "healthScore": 85, // 0 to 100
  "threatFindings": [
    {
      "severity": "'High' | 'Medium' | 'Low' | 'Info'",
      "title": "Short title of the finding",
      "description": "Detailed explanation of what was detected",
      "impact": "Potential network or security impact",
      "affectedHosts": ["192.168.1.50"]
    }
  ],
  "performanceInsights": [
    "Observation regarding throughput, TCP retransmissions, latency or protocol efficiency"
  ],
  "actionItems": [
    "Recommended remediation step 1",
    "Recommended remediation step 2"
  ]
}`;

      const response = await ai.models.generateContent({
        model: "gemini-3.6-flash",
        contents: prompt,
        config: {
          responseMimeType: "application/json",
          temperature: 0.2,
        },
      });

      const responseText = response.text || "{}";
      const report = JSON.parse(responseText);
      res.json({ success: true, report });
    } catch (err: any) {
      console.error("Error analyzing traffic with Gemini:", err);
      res.status(500).json({
        error: err.message || "Failed to generate traffic audit report.",
      });
    }
  });

  // Vite middleware in dev or static files in prod
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), "dist");
    app.use(express.static(distPath));
    app.get("*", (req, res) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server listening on http://0.0.0.0:${PORT}`);
  });
}

startServer();
