import { useEffect, useState } from "react"
import { useParams } from "react-router-dom"

export default function Results() {
  const { scanId } = useParams()

  const [inputId, setInputId] = useState(scanId || "")
  const [activeScanId, setActiveScanId] = useState(scanId || "")
  const [vulns, setVulns] = useState([])
  const [status, setStatus] = useState("")

  useEffect(() => {
    if (scanId) {
      setInputId(scanId)
      setActiveScanId(scanId)
    }
  }, [scanId])

  useEffect(() => {
    if (activeScanId) {
      fetchResults(activeScanId)
    } else {
      setStatus("Enter Scan ID to view results")
    }
  }, [activeScanId])

  const fetchResults = async (id) => {
    try {
      setStatus("Loading...")

      const response = await fetch(`http://localhost:8000/scan/${id}`)
      const data = await response.json()

      if (data.status === "running") {
        setStatus("Scan still running...")
        setTimeout(() => fetchResults(id), 3000)
        return
      }

      if (data.status === "failed") {
        setStatus("Scan failed")
        setVulns([])
        return
      }

      if (data.status === "not_found") {
        setStatus("Invalid Scan ID")
        setVulns([])
        return
      }

      if (data.status === "completed") {
        setVulns(data.result || [])
        setStatus("")
      }

    } catch (error) {
      setStatus("Failed to fetch results")
    }
  }

  const handleSearch = () => {
    if (!inputId.trim()) {
      setStatus("Please enter Scan ID")
      return
    }

    setVulns([])
    setActiveScanId(inputId.trim())
  }

  const severityColor = (severity) => {
    if (severity === "CRITICAL") return "text-red-500"
    if (severity === "HIGH") return "text-orange-400"
    if (severity === "MEDIUM") return "text-yellow-400"
    if (severity === "LOW") return "text-green-400"
    return "text-green-400"
  }

  return (
    <div>
      <h2 className="text-2xl font-bold mb-6">
        Scan Results
      </h2>

      {/* Scan ID Search */}
      <div className="flex gap-3 mb-6">
        <input
          type="text"
          placeholder="Enter Scan ID"
          value={inputId}
          onChange={(e) => setInputId(e.target.value)}
          className="flex-1 p-3 rounded bg-slate-800 border border-slate-700 text-white"
        />

        <button
          onClick={handleSearch}
          className="px-5 py-3 bg-blue-600 rounded hover:bg-blue-700"
        >
          View Result
        </button>
      </div>

      {activeScanId && (
        <p className="text-sm text-gray-400 mb-4">
          Scan ID: {activeScanId}
        </p>
      )}

      {status && (
        <p className="text-yellow-400 mb-4">{status}</p>
      )}

      <div className="bg-slate-800 rounded border border-slate-700 overflow-hidden">
        <table className="w-full">
          <thead className="bg-slate-700 text-left">
            <tr>
              <th className="p-3">Endpoint</th>
              <th className="p-3">Reason</th>
              <th className="p-3">Severity</th>
              <th className="p-3">Method</th>
            </tr>
          </thead>

          <tbody>
            {vulns.length === 0 && !status && (
              <tr>
                <td className="p-4 text-gray-400" colSpan="4">
                  No vulnerabilities found
                </td>
              </tr>
            )}

            {vulns.map((v, index) => (
              <tr
                key={index}
                className="border-t border-slate-700"
              >
                <td className="p-3">{v.endpoint}</td>

                <td className="p-3">{v.reason}</td>

                <td className={`p-3 font-semibold ${severityColor(v.severity)}`}>
                  {v.severity}
                </td>

                <td className="p-3">{v.method}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}