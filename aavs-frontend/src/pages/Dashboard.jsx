import { useState } from "react"

export default function Dashboard() {
  const [result, setResult] = useState(null)

  async function runScan() {
    const res = await fetch("http://127.0.0.1:8000/scan")
    const data = await res.json()
    console.log(data)
    setResult(data)
  }

  return (
    <div>
      <h2 className="text-2xl font-bold">Dashboard</h2>
      <p className="mt-2 text-gray-400">
        Automated API Vulnerability Scanner running.
      </p>

      <button
        onClick={runScan}
        className="mt-4 px-4 py-2 bg-blue-600 text-white rounded"
      >
        Run Scan
      </button>

      {result && (
        <pre className="mt-4 text-sm bg-gray-900 p-3 rounded">
          {JSON.stringify(result, null, 2)}
        </pre>
      )}
    </div>
  )
}