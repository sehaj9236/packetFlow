"use client";

import { useEffect, useState } from "react";
import axios from "axios";
import {
  Activity,
  ShieldCheck,
  AlertTriangle,
  Network,
  LayoutDashboard,
  Radio,
  BarChart3,
  Bell,
  Settings,
} from "lucide-react";
import {
  PieChart,
  Pie,
  Cell,
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  Legend,
} from "recharts";

const API = "http://127.0.0.1:8000";

function getPacketKey(packet) {
  return `${packet.timestamp}-${packet.src_ip}-${packet.dst_ip}-${packet.src_port}-${packet.dst_port}`;
}

function formatBytes(bytes) {
  if (!bytes) return "0 B";

  const units = ["B", "KB", "MB", "GB", "TB"];
  const k = 1024;
  const i = Math.floor(Math.log(bytes) / Math.log(k));

  return `${(bytes / Math.pow(k, i)).toFixed(2)} ${units[i]}`;
}

export default function Dashboard() {
  const [summary, setSummary] = useState(null);
  const [health, setHealth] = useState(null);
  const [packets, setPackets] = useState([]);
  const [services, setServices] = useState([]);
  const [selectedPacket, setSelectedPacket] = useState(null);
  const [threatScore, setThreatScore] = useState(null);
  const [loading, setLoading] = useState(true);

  async function startCapture() {
    try {
      await axios.post(`${API}/capture/start`);
    } catch {
      console.log("Capture already running or backend unavailable");
    }
  }

  async function fetchPackets() {
    try {
      const packetsRes = await axios.get(`${API}/packets`);
      const latestPackets = packetsRes.data.slice(-25).reverse();

      setPackets(latestPackets);

      const cached = localStorage.getItem("packetflow-dashboard-cache");
      if (cached) {
        const parsed = JSON.parse(cached);
        localStorage.setItem(
          "packetflow-dashboard-cache",
          JSON.stringify({
            ...parsed,
            packets: latestPackets,
          })
        );
      }
    } catch (err) {
      console.log("Error fetching packets", err);
    }
  }

  async function fetchDashboardData() {
    try {
      const [summaryRes, healthRes, servicesRes] = await Promise.all([
        axios.get(`${API}/analytics/summary`),
        axios.get(`${API}/analytics/network-health`),
        axios.get(`${API}/analytics/top-services`),
      ]);

      const latestServices = servicesRes.data.top_services.map(
        ([name, value]) => ({
          name,
          value,
        })
      );

      setSummary(summaryRes.data);
      setHealth(healthRes.data);
      setServices(latestServices);

      const cached = localStorage.getItem("packetflow-dashboard-cache");
      const parsed = cached ? JSON.parse(cached) : {};

      localStorage.setItem(
        "packetflow-dashboard-cache",
        JSON.stringify({
          ...parsed,
          summary: summaryRes.data,
          health: healthRes.data,
          services: latestServices,
        })
      );

      setLoading(false);
    } catch (err) {
      console.log("Error fetching dashboard data", err);
    }
  }

  async function fetchThreatScore() {
    try {
      const res = await axios.get(`${API}/ml/traffic-anomaly-score`);

      setThreatScore(res.data);

      const cached = localStorage.getItem("packetflow-dashboard-cache");
      const parsed = cached ? JSON.parse(cached) : {};

      localStorage.setItem(
        "packetflow-dashboard-cache",
        JSON.stringify({
          ...parsed,
          threatScore: res.data,
        })
      );
    } catch (err) {
      console.log("Error fetching threat score", err);
    }
  }

  useEffect(() => {
    const cached = localStorage.getItem("packetflow-dashboard-cache");

    if (cached) {
      const parsed = JSON.parse(cached);

      setSummary(parsed.summary || null);
      setHealth(parsed.health || null);
      setPackets(parsed.packets || []);
      setServices(parsed.services || []);
      setThreatScore(parsed.threatScore || null);

      setLoading(false);
    }

    startCapture();

    fetchDashboardData();
    fetchPackets();
    fetchThreatScore();

    const dataInterval = setInterval(fetchDashboardData, 3000);
    const packetInterval = setInterval(fetchPackets, 700);
    const threatInterval = setInterval(fetchThreatScore, 5000);

    return () => {
      clearInterval(dataInterval);
      clearInterval(packetInterval);
      clearInterval(threatInterval);
    };
  }, []);

  const protocolData = summary
    ? Object.entries(summary.protocol_distribution).map(([name, value]) => ({
        name,
        value,
      }))
    : [];

  const topService = services.length > 0 ? services[0] : null;

  const healthColor =
    health?.health === "GOOD"
      ? "text-green-400"
      : health?.health === "MODERATE"
      ? "text-yellow-400"
      : "text-red-400";

  const COLORS = {
    TCP: "#3B82F6",
    UDP: "#22C55E",
    ICMP: "#F59E0B",
  };

  const anomalyKeys = new Set();

  if (loading) {
    return (
      <main className="min-h-screen bg-[#07111f] text-white flex">
       
        <div className="flex-1">
          <DashboardSkeleton />
        </div>
      </main>
    );
  }

  return (
    <main className="min-h-screen bg-[#07111f] text-white flex">
      

      <div className="flex-1 p-6">
        <div className="mb-8">
          <h1 className="text-3xl font-bold">PacketFlow Analytics</h1>
          <p className="text-slate-400 mt-1">
            Real-time network traffic analytics dashboard
          </p>
        </div>

        <section className="rounded-3xl bg-[#0d1b2f] border border-slate-800 p-8 mb-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-slate-400 mb-2">Network Health Score</p>
              <h2 className={`text-6xl font-bold ${healthColor}`}>
                {health ? health.score : "--"}
              </h2>

              <p className="mt-3 text-xl">
                Status:{" "}
                <span className={`font-semibold ${healthColor}`}>
                  {health ? health.health : "Loading..."}
                </span>
              </p>

              {health?.load && (
                <p className="mt-2 text-slate-400">
                  Network Load:{" "}
                  <span className="text-blue-300 font-semibold">
                    {health.load}
                  </span>
                </p>
              )}
            </div>

            <div className="h-32 w-32 rounded-full border-8 border-blue-500 flex items-center justify-center">
              <ShieldCheck size={52} className={healthColor} />
            </div>
          </div>

          <div className="mt-6 flex flex-wrap gap-3">
            {health?.reasons?.map((reason, index) => (
              <span
                key={index}
                className="px-4 py-2 bg-slate-900 border border-slate-700 rounded-full text-sm text-slate-300"
              >
                {reason}
              </span>
            ))}
          </div>
        </section>

        <section className="grid grid-cols-1 md:grid-cols-5 gap-5 mb-6">
          <Card
            title="Total Packets"
            value={summary?.total_packets ?? "--"}
            icon={<Network />}
          />

          <Card
            title="Packets/sec"
            value={`${health?.metrics?.packets_per_second ?? "--"} pps`}
            icon={<Activity />}
          />

          <Card
            title="Throughput"
            value={`${health?.metrics?.throughput_mbps ?? "--"} Mbps`}
            icon={<Activity />}
          />

<Card
  title="Threat Score"
  value={
    threatScore ? (
      <ThreatIndicator
        score={threatScore.traffic_anomaly_score}
        status={threatScore.status}
      />
    ) : (
      "--"
    )
  }
  icon={<AlertTriangle />}
/>

          <Card
            title="Top Service"
            value={topService ? `${topService.name} (${topService.value})` : "--"}
            icon={<Network />}
          />
        </section>

        <section className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
          <div className="rounded-3xl bg-[#0d1b2f] border border-slate-800 p-6">
            <h2 className="text-xl font-semibold mb-4">
              Protocol Distribution
            </h2>

            <ResponsiveContainer width="100%" height={260}>
              <PieChart>
                <Pie
                  data={protocolData}
                  dataKey="value"
                  nameKey="name"
                  innerRadius={70}
                  outerRadius={100}
                  paddingAngle={4}
                >
                  {protocolData.map((entry, index) => (
                    <Cell
                      key={index}
                      fill={COLORS[entry.name] || "#94A3B8"}
                    />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{
                    backgroundColor: "rgba(15, 23, 42, 0.75)",
                    border: "1px solid #334155",
                    borderRadius: "12px",
                    color: "#fff",
                    backdropFilter: "blur(8px)",
                  }}
                  labelStyle={{ color: "#94a3b8" }}
                  itemStyle={{ color: "#3b82f6" }}
                />
                <Legend />
              </PieChart>
            </ResponsiveContainer>
          </div>

          <div className="rounded-3xl bg-[#0d1b2f] border border-slate-800 p-6">
            <h2 className="text-xl font-semibold mb-4">Top Services</h2>

            <ResponsiveContainer width="100%" height={260}>
              <BarChart data={services}>
                <XAxis dataKey="name" />
                <YAxis />
                <Tooltip
                  contentStyle={{
                    backgroundColor: "rgba(15, 23, 42, 0.75)",
                    border: "1px solid #334155",
                    borderRadius: "12px",
                    color: "#fff",
                    backdropFilter: "blur(8px)",
                  }}
                  labelStyle={{ color: "#94a3b8" }}
                  itemStyle={{ color: "#3b82f6" }}
                />
                <Bar dataKey="value" fill="#3B82F6" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </section>

        <section className="rounded-3xl bg-[#0d1b2f] border border-slate-800 p-6">
          <h2 className="text-xl font-semibold mb-4">Live Packet Stream</h2>

          <div className="overflow-x-auto max-h-[520px] overflow-y-auto">
            <table className="w-full text-sm">
              <thead className="sticky top-0 bg-[#0d1b2f] z-10">
                <tr className="text-slate-400 border-b border-slate-800">
                  <th className="text-left py-3">Time</th>
                  <th className="text-left py-3">Source</th>
                  <th className="text-left py-3">Destination</th>
                  <th className="text-left py-3">Protocol</th>
                  <th className="text-left py-3">Application</th>
                  <th className="text-left py-3">Service</th>
                  <th className="text-left py-3">Size</th>
                </tr>
              </thead>

              <tbody>
                {packets.map((packet, index) => {
                  const isAnomaly = anomalyKeys.has(getPacketKey(packet));

                  return (
                    <tr
                      key={`${packet.timestamp}-${index}`}
                      onClick={() => setSelectedPacket(packet)}
                      className={`border-b transition-colors cursor-pointer ${
                        isAnomaly
                          ? "bg-red-500/15 border-red-500/30 hover:bg-red-500/25"
                          : "border-slate-900 hover:bg-slate-800/40"
                      }`}
                    >
                      <td className="py-3 text-slate-300">
                        {new Date(packet.timestamp).toLocaleTimeString()}
                      </td>

                      <td className="py-3">{packet.src_ip}</td>

                      <td className="py-3">{packet.dst_ip}</td>

                      <td className="py-3">
                        <span
                          className={`px-3 py-1 rounded-full ${
                            isAnomaly
                              ? "bg-red-500/20 text-red-300"
                              : packet.protocol === "TCP"
                              ? "bg-blue-500/20 text-blue-300"
                              : packet.protocol === "UDP"
                              ? "bg-green-500/20 text-green-300"
                              : "bg-yellow-500/20 text-yellow-300"
                          }`}
                        >
                          {packet.protocol}
                        </span>
                      </td>

                      <td className="py-3">{packet.application}</td>

                      <td className="py-3">{packet.detected_service}</td>

                      <td className="py-3">{packet.packet_size} B</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </section>

        {selectedPacket && (
          <PacketDrawer
            packet={selectedPacket}
            onClose={() => setSelectedPacket(null)}
          />
        )}
      </div>
    </main>
  );
}



function Card({ title, value, icon }) {
  return (
    <div className="rounded-3xl bg-[#0d1b2f] border border-slate-800 p-5 transition-all duration-300 hover:scale-[1.02] hover:border-blue-500/50">
      <div className="flex items-center justify-between text-slate-400">
        <p>{title}</p>
        {icon}
      </div>
      <h3 className="text-2xl font-bold mt-4 break-words">{value}</h3>
    </div>
  );
}
function ThreatIndicator({ score, status }) {

  const color =
    status === "NORMAL"
      ? "text-green-400 border-green-400"
      : status === "MODERATE"
      ? "text-yellow-400 border-yellow-400"
      : "text-red-400 border-red-400";

  return (
    <div className="flex items-center gap-4 mt-2">

      <div
        className={`h-14 w-14 rounded-full border-4 flex items-center justify-center ${color}`}
      >
        <span className="text-sm font-bold">
          {Math.round(score)}
        </span>
      </div>

      <div>
        <p className={`font-semibold ${color}`}>
          {status}
        </p>

        <p className="text-sm text-slate-400">
          Traffic Risk
        </p>
      </div>

    </div>
  );
}
function PacketDrawer({ packet, onClose }) {
  return (
    <div className="fixed inset-0 bg-black/50 flex justify-end z-50">
      <div className="w-full max-w-xl h-full bg-[#0d1b2f] border-l border-slate-700 p-6 overflow-y-auto">
        <div className="flex items-center justify-between mb-6">
          <h2 className="text-2xl font-bold">Packet Details</h2>

          <button
            onClick={onClose}
            className="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700"
          >
            Close
          </button>
        </div>

        <Detail title="Timestamp" value={packet.timestamp} />
        <Detail title="Source IP" value={packet.src_ip} />
        <Detail title="Destination IP" value={packet.dst_ip} />
        <Detail title="Protocol" value={packet.protocol} />
        <Detail title="Source Port" value={packet.src_port ?? "N/A"} />
        <Detail title="Destination Port" value={packet.dst_port ?? "N/A"} />
        <Detail title="Application" value={packet.application} />
        <Detail title="Detected Service" value={packet.detected_service} />
        <Detail title="Packet Size" value={`${packet.packet_size} B`} />

        <div className="mt-8">
          <h3 className="text-lg font-semibold mb-3">Decoded Information</h3>

          <pre className="bg-slate-950 border border-slate-800 rounded-2xl p-4 text-sm overflow-x-auto text-slate-300">
            {JSON.stringify(packet.decoded, null, 2)}
          </pre>
        </div>
      </div>
    </div>
  );
}

function Detail({ title, value }) {
  return (
    <div className="flex justify-between gap-4 py-3 border-b border-slate-800">
      <span className="text-slate-400">{title}</span>
      <span className="text-right">{value}</span>
    </div>
  );
}

function DashboardSkeleton() {
  return (
    <div className="min-h-screen bg-[#07111f] text-white p-6">
      <div className="mb-8">
        <Skeleton className="h-9 w-72 mb-3" />
        <Skeleton className="h-5 w-96" />
      </div>

      <section className="rounded-3xl bg-[#0d1b2f] border border-slate-800 p-8 mb-6">
        <div className="flex items-center justify-between">
          <div>
            <Skeleton className="h-5 w-48 mb-5" />
            <Skeleton className="h-16 w-32 mb-4" />
            <Skeleton className="h-6 w-56" />
          </div>

          <Skeleton className="h-32 w-32 rounded-full" />
        </div>
      </section>

      <section className="grid grid-cols-1 md:grid-cols-5 gap-5 mb-6">
        <SkeletonCard />
        <SkeletonCard />
        <SkeletonCard />
        <SkeletonCard />
        <SkeletonCard />
      </section>

      <section className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
        <Skeleton className="h-80 rounded-3xl" />
        <Skeleton className="h-80 rounded-3xl" />
      </section>

      <section className="rounded-3xl bg-[#0d1b2f] border border-slate-800 p-6">
        <Skeleton className="h-7 w-56 mb-6" />

        <div className="space-y-4">
          {Array.from({ length: 8 }).map((_, index) => (
            <Skeleton key={index} className="h-10 w-full" />
          ))}
        </div>
      </section>
    </div>
  );
}

function SkeletonCard() {
  return (
    <div className="rounded-3xl bg-[#0d1b2f] border border-slate-800 p-5">
      <Skeleton className="h-5 w-32 mb-6" />
      <Skeleton className="h-8 w-28" />
    </div>
  );
}

function Skeleton({ className = "" }) {
  return <div className={`animate-pulse bg-slate-700/60 ${className}`} />;
}