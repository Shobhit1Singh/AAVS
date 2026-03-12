import { Link } from "react-router-dom"

export default function MainLayout({ children }) {
  return (
    <div className="flex h-screen bg-slate-900 text-gray-200">

      <aside className="w-64 bg-slate-800 border-r border-slate-700">
        <div className="p-4 text-xl font-semibold border-b border-slate-700">
          AAVS
        </div>

        <nav className="p-4 space-y-2">
          <Link to="/" className="block px-3 py-2 rounded hover:bg-slate-700">
            Dashboard
          </Link>

          <Link to="/scan" className="block px-3 py-2 rounded hover:bg-slate-700">
            New Scan
          </Link>

          <Link to="/active" className="block px-3 py-2 rounded hover:bg-slate-700">
            Active Scans
          </Link>

          <Link to="/results" className="block px-3 py-2 rounded hover:bg-slate-700">
            Results
          </Link>

          <Link to="/reports" className="block px-3 py-2 rounded hover:bg-slate-700">
            Reports
          </Link>

          <Link to="/settings" className="block px-3 py-2 rounded hover:bg-slate-700">
            Settings
          </Link>
        </nav>
      </aside>

      <div className="flex-1 flex flex-col">

        <header className="h-14 bg-slate-800 border-b border-slate-700 flex items-center px-6">
          <h1 className="text-lg font-medium">AAVS Security Scanner</h1>
        </header>

        <main className="flex-1 overflow-y-auto p-6">
          {children}
        </main>

      </div>

    </div>
  )
}