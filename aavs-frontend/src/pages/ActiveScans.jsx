import { useEffect, useState } from "react"

export default function ActiveScans() {

  const [scans, setScans] = useState([])

  useEffect(() => {
    fetchScans()
  }, [])

  const fetchScans = async () => {
    try {

      const response = await fetch("http://localhost:8000/active-scans")
      const data = await response.json()

      setScans(data)

    } catch (error) {
      console.log("Failed to fetch scans")
    }
  }

  return (
    <div>

      <h2 className="text-2xl font-bold mb-6">
        Active Scans
      </h2>

      <div className="bg-slate-800 rounded border border-slate-700">

        <table className="w-full">

          <thead className="bg-slate-700 text-left">
            <tr>
              <th className="p-3">Scan ID</th>
              <th className="p-3">Target</th>
              <th className="p-3">Status</th>
              <th className="p-3">Started</th>
            </tr>
          </thead>

          <tbody>

            {scans.length === 0 && (
              <tr>
                <td className="p-4 text-gray-400" colSpan="4">
                  No active scans
                </td>
              </tr>
            )}

            {scans.map((scan) => (
              <tr key={scan.id} className="border-t border-slate-700">

                <td className="p-3">{scan.id}</td>
                <td className="p-3">{scan.target}</td>
                <td className="p-3">{scan.status}</td>
                <td className="p-3">{scan.started}</td>

              </tr>
            ))}

          </tbody>

        </table>

      </div>

    </div>
  )
}