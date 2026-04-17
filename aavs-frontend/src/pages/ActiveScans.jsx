import { useEffect, useState } from "react"

export default function ActiveScans() {
  const [url, setUrl] = useState("")
  const [loading, setLoading] = useState(false)
  const [status, setStatus] = useState("")
  const [scans, setScans] = useState({})

  useEffect(() => {
    fetchActiveScans()

    const interval = setInterval(fetchActiveScans, 3000)

    return () => clearInterval(interval)
  }, [])

  const fetchActiveScans = async () => {
    try {
      const response = await fetch("http://127.0.0.1:8000/active-scans")
      const data = await response.json()

      console.log("Fetched scans:", data)

      if (data && typeof data === "object") {
        setScans(data)
      } else {
        setScans({})
      }

    } catch (error) {
      console.error("Fetch failed:", error)
      setScans({})
    }
  }

  const startScan = async () => {
    if (!url.trim()) {
      setStatus("Enter valid URL.")
      return
    }

    setLoading(true)
    setStatus("Starting scan...")

    try {
      const response = await fetch("http://127.0.0.1:8000/scan/url", {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          url: url.trim(),
          base_url: url.trim()
        })
      })

      const data = await response.json()

      if (response.ok) {
        setStatus("Scan started")
        setUrl("")
        fetchActiveScans()
      } else {
        setStatus(data.error || "Failed")
      }

    } catch (error) {
      console.error(error)
      setStatus("Backend unreachable")
    }

    setLoading(false)
  }

  const scanEntries = Object.entries(scans || {})

  return (
    <div className="p-6 text-white">
      <h2 className="text-2xl font-bold mb-6">Active Scans</h2>

      <div className="flex gap-2 mb-4">
        <input
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          placeholder="http://127.0.0.1:8000"
          className="p-2 w-full bg-slate-800 border rounded"
        />

        <button
          onClick={startScan}
          className="px-4 py-2 bg-blue-600 rounded"
        >
          {loading ? "Starting..." : "Start Scan"}
        </button>
      </div>

      {status && <p className="mb-4 text-yellow-400">{status}</p>}

      <table className="w-full border">
        <thead>
          <tr className="bg-slate-700">
            <th className="p-2">Scan ID</th>
            <th className="p-2">Status</th>
            <th className="p-2">Error</th>
          </tr>
        </thead>

        <tbody>
          {scanEntries.length === 0 ? (
            <tr>
              <td colSpan="3" className="p-4 text-center">
                No scans found.
              </td>
            </tr>
          ) : (
            scanEntries.map(([id, scan]) => (
              <tr key={id} className="border-t">
                <td className="p-2 break-all">{id}</td>
                <td className="p-2">{scan?.status || "-"}</td>
                <td className="p-2 text-red-400">{scan?.error || "-"}</td>
              </tr>
            ))
          )}
        </tbody>
      </table>
    </div>
  )
}