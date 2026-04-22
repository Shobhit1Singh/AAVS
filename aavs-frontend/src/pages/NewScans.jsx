import { useState } from "react"
import { useNavigate } from "react-router-dom"

export default function NewScan() {
  const navigate = useNavigate()

  // Autofilled because typing localhost repeatedly is a tax on human life
  const [targetUrl, setTargetUrl] = useState("http://localhost:3000")
  const [scanMode, setScanMode] = useState("active")
  const [authToken, setAuthToken] = useState("")
  const [file, setFile] = useState(null)

  const [status, setStatus] = useState("")
  const [scanId, setScanId] = useState(null)
  const [loading, setLoading] = useState(false)

  const startScan = async (e) => {
    e.preventDefault()

    const cleanUrl = targetUrl.trim()

    if (!cleanUrl) {
      setStatus("Enter API Target URL. Clairvoyance is still unavailable.")
      return
    }

    if (!file) {
      setStatus("Upload your OpenAPI / Swagger file.")
      return
    }

    setLoading(true)
    setStatus("Starting scan...")
    setScanId(null)

    try {
      const formData = new FormData()

      formData.append("file", file)
      formData.append("base_url", cleanUrl)
      formData.append("scan_mode", scanMode)

      if (authToken.trim()) {
        formData.append("auth_token", authToken.trim())
      }

      const response = await fetch("http://localhost:8000/scan/file", {
        method: "POST",
        body: formData,
      })

      const data = await response.json()

      if (!response.ok) {
        setStatus("Scan failed: " + (data.error || "Unknown error"))
        setLoading(false)
        return
      }

      setScanId(data.scan_id)
      setStatus("Scan started successfully")

    } catch (error) {
      setStatus("Backend not reachable")
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="max-w-xl">
      <h2 className="text-2xl font-bold mb-6">
        Start New Scan
      </h2>

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
            className="w-full p-3 rounded bg-slate-800 border border-slate-700 text-white"
          />
        </div>

        <div>
          <label className="block mb-1 text-sm text-gray-300">
            Upload API File
          </label>

          <input
            type="file"
            accept=".json,.yaml,.yml"
            onChange={(e) => setFile(e.target.files[0])}
            className="w-full p-3 rounded bg-slate-800 border border-slate-700 text-white"
          />
        </div>

        <div>
          <label className="block mb-1 text-sm text-gray-300">
            Scan Mode
          </label>

          <select
            value={scanMode}
            onChange={(e) => setScanMode(e.target.value)}
            className="w-full p-3 rounded bg-slate-800 border border-slate-700 text-white"
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
            className="w-full p-3 rounded bg-slate-800 border border-slate-700 text-white"
          />
        </div>

        <button
          type="submit"
          disabled={loading}
          className="px-5 py-3 bg-blue-600 rounded hover:bg-blue-700 disabled:opacity-50"
        >
          {loading ? "Starting..." : "Start Scan"}
        </button>
      </form>

      {status && (
        <div className="mt-4 text-sm text-yellow-400">
          {status}
        </div>
      )}

      {scanId && (
        <div className="mt-3 text-sm text-green-400 break-all">
          Scan ID: {scanId}
        </div>
      )}
    </div>
  )
}