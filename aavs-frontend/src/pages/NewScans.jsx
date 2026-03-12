import { useState } from "react"

export default function NewScan() {

  const [targetUrl, setTargetUrl] = useState("")
  const [scanMode, setScanMode] = useState("active")
  const [authToken, setAuthToken] = useState("")
  const [status, setStatus] = useState("")

  const startScan = async (e) => {
    e.preventDefault()

    setStatus("Starting scan...")

    try {

      const response = await fetch("http://localhost:8000/start-scan", {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          url: targetUrl,
          mode: scanMode,
          token: authToken
        })
      })

      const data = await response.json()

      if (response.ok) {
        setStatus("Scan started successfully")
      } else {
        setStatus("Scan failed: " + data.detail)
      }

    } catch (error) {
      setStatus("Backend not reachable")
    }
  }

  return (
    <div className="max-w-xl">

      <h2 className="text-2xl font-bold mb-6">Start New Scan</h2>

      <form onSubmit={startScan} className="space-y-5">

        <div>
          <label className="block mb-1 text-sm text-gray-300">
            API Target URL
          </label>
          <input
            type="text"
            value={targetUrl}
            onChange={(e) => setTargetUrl(e.target.value)}
            placeholder="https://api.example.com"
            className="w-full p-2 rounded bg-slate-800 border border-slate-700"
            required
          />
        </div>

        <div>
          <label className="block mb-1 text-sm text-gray-300">
            Scan Mode
          </label>
          <select
            value={scanMode}
            onChange={(e) => setScanMode(e.target.value)}
            className="w-full p-2 rounded bg-slate-800 border border-slate-700"
          >
            <option value="active">Active Scan</option>
            <option value="passive">Passive Scan</option>
          </select>
        </div>

        <div>
          <label className="block mb-1 text-sm text-gray-300">
            Auth Token (optional)
          </label>
          <input
            type="text"
            value={authToken}
            onChange={(e) => setAuthToken(e.target.value)}
            placeholder="Bearer token..."
            className="w-full p-2 rounded bg-slate-800 border border-slate-700"
          />
        </div>

        <button
          type="submit"
          className="px-4 py-2 bg-blue-600 rounded hover:bg-blue-700"
        >
          Start Scan
        </button>

      </form>

      {status && (
        <div className="mt-4 text-sm text-gray-400">
          {status}
        </div>
      )}

    </div>
  )
}