import { Link, useLocation } from "react-router-dom"
import {
  LayoutDashboard,
  PlayCircle,
  Activity,
  FileText,
  BarChart3,
  Settings,
  LogIn,
} from "lucide-react"

export default function MainLayout({ children }) {
  const location = useLocation()

  const links = [
    { to: "/", icon: LayoutDashboard, label: "Dashboard" },
    { to: "/scan", icon: PlayCircle, label: "New Scan" },
    { to: "/activescan", icon: Activity, label: "Active Scans" },
    { to: "/results", icon: BarChart3, label: "Results" },
    { to: "/details", icon: FileText, label: "Details" },
    { to: "/settings", icon: Settings, label: "Settings" },
  ]

  return (
    <div className="flex h-screen w-screen overflow-hidden bg-gradient-to-br from-slate-950 via-indigo-950 to-purple-950 text-gray-200">

      {/* Sidebar */}
      <aside className="w-64 shrink-0 bg-slate-900/80 backdrop-blur border-r border-purple-800/40 flex flex-col">

        {/* Title */}
        <div className="h-14 flex items-center px-5 border-b border-purple-800/40">
          <span className="text-lg font-semibold text-purple-400 tracking-wide">
            AAVS
          </span>
        </div>

        {/* Nav */}
        <nav className="flex-1 flex flex-col justify-between py-4">

          {/* Top Links */}
          <div className="flex flex-col px-3 space-y-1">
            {links.map(({ to, icon: Icon, label }) => {
              const active = location.pathname === to

              return (
                <Link
                  key={to}
                  to={to}
                  className={`flex items-center gap-3 px-3 py-2.5 rounded-lg transition-all duration-200
                  ${
                    active
                      ? "bg-gradient-to-r from-indigo-600/40 to-purple-600/40 text-white shadow-inner"
                      : "hover:bg-gradient-to-r hover:from-indigo-600/20 hover:to-purple-600/20"
                  }`}
                >
                  <Icon
                    size={18}
                    className={active ? "text-purple-300" : "text-indigo-400"}
                  />
                  <span className="text-sm font-medium">{label}</span>
                </Link>
              )
            })}
          </div>

          {/* Bottom Login */}
          <div className="px-3 pt-4 border-t border-purple-800/30">
            <Link
              to="/login"
              className="flex items-center justify-center gap-2 px-3 py-2.5 rounded-lg bg-gradient-to-r from-indigo-600 to-purple-600 hover:from-indigo-500 hover:to-purple-500 transition"
            >
              <LogIn size={18} />
              <span className="text-sm font-medium">Login</span>
            </Link>
          </div>

        </nav>
      </aside>

      {/* Main Content */}
      <div className="flex-1 flex flex-col min-w-0">

        {/* Header */}
        <header className="h-14 flex items-center px-6 border-b border-purple-800/40 bg-slate-900/60 backdrop-blur">
          <h1 className="text-base font-semibold text-indigo-300 tracking-wide">
            Automated API Vulnerability Scanner
          </h1>
        </header>

        {/* Content */}
        <main className="flex-1 overflow-y-auto px-6 py-5 w-full">
          <div className="w-full">
            {children}
          </div>
        </main>

      </div>
    </div>
  )
}