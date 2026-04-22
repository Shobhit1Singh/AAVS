import { useEffect, useMemo, useState } from "react"
import {
  LineChart,
  Line,
  BarChart,
  Bar,
  PieChart,
  Pie,
  AreaChart,
  Area,
  Cell,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
  ResponsiveContainer,
  Legend,
} from "recharts"

export default function Dashboard() {
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)

  async function runScan() {
    try {
      setLoading(true)
      const res = await fetch("http://127.0.0.1:8000/scan")
      const data = await res.json()
      setResult(data)
    } catch (err) {
      console.log(err)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    runScan()
  }, [])

  const stats = {
    scans: 1562,
    vulns: 342,
    users: 281,
    retention: "78%",
    uptime: "99.97%",
    apis: 64,
  }

  const scanTrend = [
    { day: "Mon", scans: 42, vulns: 9 },
    { day: "Tue", scans: 58, vulns: 12 },
    { day: "Wed", scans: 73, vulns: 15 },
    { day: "Thu", scans: 49, vulns: 8 },
    { day: "Fri", scans: 88, vulns: 19 },
    { day: "Sat", scans: 64, vulns: 10 },
    { day: "Sun", scans: 79, vulns: 14 },
  ]

  const traffic = [
    { hour: "00", requests: 210 },
    { hour: "04", requests: 340 },
    { hour: "08", requests: 710 },
    { hour: "12", requests: 980 },
    { hour: "16", requests: 860 },
    { hour: "20", requests: 620 },
  ]

  const severity = [
    { name: "Critical", value: 18 },
    { name: "High", value: 41 },
    { name: "Medium", value: 89 },
    { name: "Low", value: 56 },
  ]

  const users = [
    { month: "Jan", users: 120 },
    { month: "Feb", users: 145 },
    { month: "Mar", users: 164 },
    { month: "Apr", users: 193 },
    { month: "May", users: 232 },
    { month: "Jun", users: 281 },
  ]

  const colors = ["#ef4444", "#f97316", "#eab308", "#22c55e"]

  const recentFindings = useMemo(
    () => [
      { id: 1, issue: "Broken Auth", sev: "Critical", target: "/login" },
      { id: 2, issue: "Rate Limit Missing", sev: "High", target: "/otp/send" },
      { id: 3, issue: "CORS Misconfig", sev: "Medium", target: "/profile" },
      { id: 4, issue: "Verbose Errors", sev: "Low", target: "/search" },
    ],
    []
  )

  return (
    <div className="min-h-screen bg-black text-white p-6">
      {/* Header */}
      <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
        <div>
          <h1 className="text-4xl font-bold">AAVS Dashboard</h1>
          <p className="text-gray-400 mt-2">
            Automated API Vulnerability Scanner. Watching bad decisions in real time.
          </p>
        </div>

        <div className="flex gap-3">
          <button
            onClick={runScan}
            className="px-5 py-2 rounded-xl bg-blue-600 hover:bg-blue-700"
          >
            {loading ? "Scanning..." : "Run Scan"}
          </button>

          <button className="px-5 py-2 rounded-xl bg-gray-800 hover:bg-gray-700">
            Export Report
          </button>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 lg:grid-cols-6 gap-4 mt-8">
        <Card title="Total Scans" value={stats.scans} />
        <Card title="Vulnerabilities" value={stats.vulns} />
        <Card title="Users" value={stats.users} />
        <Card title="Retention" value={stats.retention} />
        <Card title="Uptime" value={stats.uptime} />
        <Card title="Tracked APIs" value={stats.apis} />
      </div>

      {/* Main Grid */}
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6 mt-8">
        {/* Left */}
        <div className="xl:col-span-2 space-y-6">
          {/* Scan Trend */}
          <Panel title="Weekly Scan Trend">
            <ResponsiveContainer width="100%" height={300}>
              <LineChart data={scanTrend}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="day" stroke="#aaa" />
                <YAxis stroke="#aaa" />
                <Tooltip />
                <Legend />
                <Line dataKey="scans" stroke="#3b82f6" strokeWidth={3} />
                <Line dataKey="vulns" stroke="#ef4444" strokeWidth={3} />
              </LineChart>
            </ResponsiveContainer>
          </Panel>

          {/* Traffic */}
          <Panel title="API Traffic Heat">
            <ResponsiveContainer width="100%" height={300}>
              <AreaChart data={traffic}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="hour" stroke="#aaa" />
                <YAxis stroke="#aaa" />
                <Tooltip />
                <Area
                  type="monotone"
                  dataKey="requests"
                  stroke="#22c55e"
                  fill="#14532d"
                />
              </AreaChart>
            </ResponsiveContainer>
          </Panel>

          {/* Result */}
          {result && (
            <Panel title="Latest Scan Payload">
              <pre className="text-sm overflow-auto max-h-72 text-gray-300">
                {JSON.stringify(result, null, 2)}
              </pre>
            </Panel>
          )}
        </div>

        {/* Right */}
        <div className="space-y-6">
          {/* Severity */}
          <Panel title="Severity Split">
            <ResponsiveContainer width="100%" height={260}>
              <PieChart>
                <Pie data={severity} dataKey="value" outerRadius={95} label>
                  {severity.map((item, i) => (
                    <Cell key={i} fill={colors[i % colors.length]} />
                  ))}
                </Pie>
                <Tooltip />
              </PieChart>
            </ResponsiveContainer>
          </Panel>

          {/* User Growth */}
          <Panel title="User Growth">
            <ResponsiveContainer width="100%" height={260}>
              <BarChart data={users}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="month" stroke="#aaa" />
                <YAxis stroke="#aaa" />
                <Tooltip />
                <Bar dataKey="users" fill="#8b5cf6" radius={[6, 6, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </Panel>

          {/* Findings */}
          <Panel title="Recent Findings">
            <div className="space-y-3">
              {recentFindings.map((item) => (
                <div
                  key={item.id}
                  className="p-3 rounded-xl bg-gray-800 border border-gray-700"
                >
                  <div className="flex justify-between">
                    <span className="font-semibold">{item.issue}</span>
                    <span className="text-sm text-red-400">{item.sev}</span>
                  </div>
                  <p className="text-sm text-gray-400 mt-1">{item.target}</p>
                </div>
              ))}
            </div>
          </Panel>

          {/* Status */}
          <Panel title="System Status">
            <div className="space-y-2 text-sm text-gray-300">
              <Row label="Scanner Engine" value="Online" />
              <Row label="Database" value="Healthy" />
              <Row label="Queue Workers" value="4 Active" />
              <Row label="Last Backup" value="2 hrs ago" />
              <Row label="Latency" value="143ms" />
            </div>
          </Panel>
        </div>
      </div>
    </div>
  )
}

function Card({ title, value }) {
  return (
    <div className="bg-gray-900 rounded-2xl p-4 border border-gray-800">
      <p className="text-sm text-gray-400">{title}</p>
      <h3 className="text-2xl font-bold mt-2">{value}</h3>
    </div>
  )
}

function Panel({ title, children }) {
  return (
    <div className="bg-gray-900 rounded-2xl p-5 border border-gray-800">
      <h3 className="text-lg font-semibold mb-4">{title}</h3>
      {children}
    </div>
  )
}

function Row({ label, value }) {
  return (
    <div className="flex justify-between border-b border-gray-800 pb-2">
      <span>{label}</span>
      <span>{value}</span>
    </div>
  )
}