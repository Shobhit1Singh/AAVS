import { useEffect, useState } from "react"

export default function Results() {

  const [vulns, setVulns] = useState([])

  useEffect(() => {
    fetchResults()
  }, [])

  const fetchResults = async () => {
    try {

      const response = await fetch("http://localhost:8000/results")
      const data = await response.json()

      setVulns(data)

    } catch (error) {
      console.log("Failed to fetch results")
    }
  }

  const severityColor = (severity) => {
    if (severity === "critical") return "text-red-500"
    if (severity === "high") return "text-orange-400"
    if (severity === "medium") return "text-yellow-400"
    return "text-green-400"
  }

  return (
    <div>

      <h2 className="text-2xl font-bold mb-6">
        Scan Results
      </h2>

      <div className="bg-slate-800 rounded border border-slate-700 overflow-hidden">

        <table className="w-full">

          <thead className="bg-slate-700 text-left">
            <tr>
              <th className="p-3">Endpoint</th>
              <th className="p-3">Vulnerability</th>
              <th className="p-3">Severity</th>
              <th className="p-3">Method</th>
            </tr>
          </thead>

          <tbody>

            {vulns.length === 0 && (
              <tr>
                <td className="p-4 text-gray-400" colSpan="4">
                  No vulnerabilities found yet
                </td>
              </tr>
            )}

            {vulns.map((v, index) => (
              <tr key={index} className="border-t border-slate-700">

                <td className="p-3">{v.endpoint}</td>

                <td className="p-3">
                  {v.vulnerability}
                </td>

                <td className={`p-3 font-semibold ${severityColor(v.severity)}`}>
                  {v.severity}
                </td>

                <td className="p-3">
                  {v.method}
                </td>

              </tr>
            ))}

          </tbody>

        </table>

      </div>

    </div>
  )
}