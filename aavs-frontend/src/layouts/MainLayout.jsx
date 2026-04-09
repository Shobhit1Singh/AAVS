import { Link } from "react-router-dom"
import { 
  LayoutDashboard, 
  PlayCircle, 
  Activity, 
  FileText, 
  BarChart3, 
  Settings, 
  LogIn 
} from "lucide-react"

export default function MainLayout({ children }) {
  return (
    <div className="flex h-screen bg-slate-900 text-gray-200">

      {/* Sidebar */}
      <aside className="w-64 bg-slate-800 border-r border-slate-700 flex flex-col">

        {/* Title - NO extra margin pushing it down */}
        <div className="px-4 py-4 text-lg font-semibold border-b border-slate-700">
          AAVS
        </div>

        {/* Nav - FULL HEIGHT DISTRIBUTION */}
        <nav className="flex-1 flex flex-col justify-between p-4">

          {/* Top Links */}
          <div className="flex flex-col gap-4">

            <Link to="/" className="flex items-center gap-3 px-3 py-3 rounded hover:bg-slate-700 transition">
              <LayoutDashboard size={18} />
              Dashboard
            </Link>

            <Link to="/scan" className="flex items-center gap-3 px-3 py-3 rounded hover:bg-slate-700 transition">
              <PlayCircle size={18} />
              New Scan
            </Link>

            <Link to="/active" className="flex items-center gap-3 px-3 py-3 rounded hover:bg-slate-700 transition">
              <Activity size={18} />
              Active Scans
            </Link>

            <Link to="/results" className="flex items-center gap-3 px-3 py-3 rounded hover:bg-slate-700 transition">
              <BarChart3 size={18} />
              Results
            </Link>

            <Link to="/reports" className="flex items-center gap-3 px-3 py-3 rounded hover:bg-slate-700 transition">
              <FileText size={18} />
              Reports
            </Link>

            <Link to="/settings" className="flex items-center gap-3 px-3 py-3 rounded hover:bg-slate-700 transition">
              <Settings size={18} />
              Settings
            </Link>

          </div>

          {/* Bottom Login */}
          <div>
            <Link 
              to="/login" 
              className="flex items-center justify-center gap-2 px-3 py-3 rounded bg-slate-700 hover:bg-slate-600 transition"
            >
              <LogIn size={18} />
              Login
            </Link>
          </div>

        </nav>

      </aside>

      {/* Main Content */}
      <div className="flex-1 flex flex-col">

        {/* Header - flush to top */}
        <header className="h-14 bg-slate-800 border-b border-slate-700 flex items-center px-6">
          <h1 className="text-lg font-medium">
            Automated API Vulnerability Scanner
          </h1>
        </header>

        <main className="flex-1 overflow-y-auto p-6">
          <div className="max-w-7xl mx-auto">
            {children}
          </div>
        </main>

      </div>

    </div>
  )
}