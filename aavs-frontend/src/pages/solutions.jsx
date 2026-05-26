import { useEffect, useState } from "react"
import { useParams } from "react-router-dom"

export default function AISolutionPage() {

  const { scanId } = useParams()

  const [inputId, setInputId] = useState(scanId || "")
  const [activeScanId, setActiveScanId] = useState(scanId || "")

  const [loading, setLoading] = useState(false)
  const [status, setStatus] = useState("Enter Scan ID")

  const [report, setReport] = useState("")
  const [findings, setFindings] = useState([])

  useEffect(() => {

    if (scanId) {
      setInputId(scanId)
      setActiveScanId(scanId)
    }

  }, [scanId])

  useEffect(() => {

    if (activeScanId) {
      fetchSolutions(activeScanId)
    }

  }, [activeScanId])

  const fetchSolutions = async (id) => {

    try {

      setLoading(true)

      setStatus("Generating AI remediation report...")

      const res = await fetch(
        `https://localhost:8000/scan/${id}`
      )

      const result = await res.json()

      console.log("AI SOLUTION RESULT")
      console.log(result)

      if (result.status === "running") {

        setStatus("Scan still running...")

        setTimeout(() => {
          fetchSolutions(id)
        }, 3000)

        return
      }

      if (result.status === "failed") {

        setStatus(
          "Scan failed: " +
          (result.error || "unknown error")
        )

        setLoading(false)

        return
      }

      if (result.status === "not_found") {

        setStatus("Invalid Scan ID")

        setLoading(false)

        return
      }

      if (result.status === "completed") {

        setFindings(result.result || [])

        setReport(
          result.ai_report ||
          "No AI remediation report found"
        )

        setStatus("")

        setLoading(false)
      }

    } catch (err) {

      console.log(err)

      setStatus("Error loading AI report")

      setLoading(false)
    }
  }

  const handleSearch = () => {

    if (!inputId.trim()) {

      setStatus("Please enter Scan ID")

      return
    }

    setReport("")

    setFindings([])

    setActiveScanId(inputId.trim())
  }

  return (

    <div className="min-h-screen bg-slate-950 p-6">

      <div className="max-w-7xl mx-auto">

        <div className="mb-8">

          <h1 className="text-3xl font-bold text-white mb-2">
            AI API Security Solutions
          </h1>

          <p className="text-slate-400">
            AI-generated remediation guidance for scanned API vulnerabilities.
          </p>

        </div>

        <div className="flex gap-3 mb-6">

          <input
            type="text"
            placeholder="Enter Scan ID"
            value={inputId}
            onChange={(e) =>
              setInputId(e.target.value)
            }
            className="
              flex-1
              p-4
              rounded-xl
              bg-slate-900
              border
              border-slate-700
              text-white
              outline-none
              focus:border-indigo-500
            "
          />

          <button
            onClick={handleSearch}
            className="
              px-6
              py-4
              rounded-xl
              text-white
              font-semibold
              bg-gradient-to-r
              from-indigo-600
              to-purple-600
              hover:from-indigo-500
              hover:to-purple-500
              transition-all
            "
          >
            Generate Solutions
          </button>

        </div>

        {activeScanId && (

          <div className="mb-6">

            <div className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-slate-900 border border-slate-700">

              <span className="text-slate-400 text-sm">
                Active Scan:
              </span>

              <span className="text-indigo-400 text-sm font-mono">
                {activeScanId}
              </span>

            </div>

          </div>

        )}

        {status && (

          <div className="
            mb-6
            bg-yellow-500/10
            border
            border-yellow-500/20
            rounded-xl
            p-4
          ">

            <p className="text-yellow-300">
              {status}
            </p>

          </div>

        )}

        {loading && (

          <div className="
            bg-slate-900
            border
            border-slate-700
            rounded-2xl
            p-8
            animate-pulse
            mb-6
          ">

            <div className="h-6 w-64 bg-slate-700 rounded mb-4"></div>

            <div className="space-y-3">
              <div className="h-4 bg-slate-800 rounded"></div>
              <div className="h-4 bg-slate-800 rounded"></div>
              <div className="h-4 bg-slate-800 rounded w-3/4"></div>
            </div>

          </div>

        )}

        {!loading && findings.length > 0 && (

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-6">

            <div className="bg-slate-900 border border-slate-700 rounded-2xl p-5">
              <h3 className="text-slate-400 text-sm mb-2">
                Total Findings
              </h3>
              <p className="text-3xl font-bold text-white">
                {findings.length}
              </p>
            </div>

            <div className="bg-slate-900 border border-slate-700 rounded-2xl p-5">
              <h3 className="text-slate-400 text-sm mb-2">
                Critical + High
              </h3>
              <p className="text-3xl font-bold text-red-400">
                {
                  findings.filter(
                    f =>
                      f.severity === "CRITICAL" ||
                      f.severity === "HIGH"
                  ).length
                }
              </p>
            </div>

            <div className="bg-slate-900 border border-slate-700 rounded-2xl p-5">
              <h3 className="text-slate-400 text-sm mb-2">
                AI Status
              </h3>
              <p className="text-3xl font-bold text-green-400">
                Ready
              </p>
            </div>

          </div>

        )}

        {!loading && report && (

          <div className="
            bg-slate-900
            border
            border-indigo-500/20
            rounded-2xl
            p-8
            shadow-2xl
          ">

            <div className="flex items-center justify-between mb-6">

              <div>

                <h2 className="text-2xl font-bold text-white mb-1">
                  AI Remediation Report
                </h2>

                <p className="text-slate-400 text-sm">
                  Generated security remediation guidance for scanned APIs.
                </p>

              </div>

              <div className="px-3 py-1 rounded-full bg-indigo-500/10 border border-indigo-500/20 text-indigo-400 text-xs uppercase tracking-widest">
                LLM Powered
              </div>

            </div>

            <div className="
              whitespace-pre-wrap
              text-slate-300
              leading-8
              text-sm
              overflow-auto
            ">
              {report}
            </div>

          </div>

        )}

      </div>

    </div>
  )
}
