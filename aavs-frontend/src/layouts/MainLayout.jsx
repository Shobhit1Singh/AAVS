import { Link, useLocation } from "react-router-dom"
import {
  LayoutDashboard,
  PlayCircle,
  Activity,
  FileText,
  BarChart3,
  Settings,
  LogIn,
  Bell,
  Search,
  Shield,
  ChevronRight,
  UserCircle2,
  Server,
} from "lucide-react"

export default function MainLayout({ children }) {
  const location = useLocation()

  const links = [
    { to: "/", icon: LayoutDashboard, label: "Dashboard" },
    { to: "/scan", icon: PlayCircle, label: "New Scan" },
    { to: "/activescan", icon: Activity, label: "Active Scans" },
    { to: "/results", icon: BarChart3, label: "Results" },
    { to: "/details", icon: FileText, label: "Details" },
    { to: "/setting", icon: Settings, label: "Settings" },
  ]

  const currentPage =
    links.find((item) => item.to === location.pathname)?.label || "Dashboard"

  return (
    <div className="flex h-screen w-screen overflow-hidden bg-gradient-to-br from-slate-950 via-indigo-950 to-purple-950 text-gray-200">
      {/* Sidebar */}
      <aside className="w-72 shrink-0 bg-slate-900/80 backdrop-blur-xl border-r border-purple-800/30 flex flex-col">
        {/* Logo */}
        <div className="h-16 px-5 border-b border-purple-800/30 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="h-10 w-10 rounded-xl bg-gradient-to-br from-indigo-500 to-purple-600 flex items-center justify-center shadow-lg">
              <Shield size={20} />
            </div>

            <div>
              <h2 className="font-semibold tracking-wide text-purple-300">
                AAVS
              </h2>
              <p className="text-xs text-gray-400">Security Console</p>
            </div>
          </div>

          <span className="text-[10px] px-2 py-1 rounded-full bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
            LIVE
          </span>
        </div>

        {/* Workspace */}
        <div className="px-4 py-4 border-b border-purple-800/20">
          <div className="rounded-xl bg-slate-800/70 p-3">
            <p className="text-xs text-gray-400">Workspace</p>
            <div className="mt-2 flex items-center justify-between">
              <span className="font-medium">Production APIs</span>
              <Server size={15} className="text-indigo-400" />
            </div>
            <p className="text-xs text-emerald-300 mt-1">
              64 endpoints monitored
            </p>
          </div>
        </div>

        {/* Nav */}
        <nav className="flex-1 px-3 py-4 space-y-1 overflow-y-auto">
          {links.map(({ to, icon: Icon, label }) => {
            const active = location.pathname === to

            return (
              <Link
                key={to}
                to={to}
                className={`group flex items-center justify-between px-3 py-3 rounded-xl transition-all duration-200
                ${
                  active
                    ? "bg-gradient-to-r from-indigo-600/40 to-purple-600/40 border border-purple-500/20 shadow-lg"
                    : "hover:bg-white/5"
                }`}
              >
                <div className="flex items-center gap-3">
                  <Icon
                    size={18}
                    className={
                      active
                        ? "text-purple-200"
                        : "text-indigo-400 group-hover:text-indigo-300"
                    }
                  />
                  <span className="text-sm font-medium">{label}</span>
                </div>

                <ChevronRight
                  size={15}
                  className={`transition ${
                    active
                      ? "text-purple-300"
                      : "text-gray-600 group-hover:text-gray-400"
                  }`}
                />
              </Link>
            )
          })}
        </nav>

        {/* Bottom User Card */}
        <div className="p-4 border-t border-purple-800/20">
          <div className="rounded-xl bg-slate-800/70 p-3 mb-3 flex items-center gap-3">
            <UserCircle2 size={34} className="text-indigo-400" />
            <div className="min-w-0">
              <p className="text-sm font-medium truncate">Admin User</p>
              <p className="text-xs text-gray-400 truncate">
                Root of questionable decisions
              </p>
            </div>
          </div>

          <Link
            to="/login"
            className="flex items-center justify-center gap-2 px-3 py-2.5 rounded-xl bg-gradient-to-r from-indigo-600 to-purple-600 hover:from-indigo-500 hover:to-purple-500 transition"
          >
            <LogIn size={18} />
            <span className="text-sm font-medium">Login</span>
          </Link>
        </div>
      </aside>

      {/* Main */}
      <div className="flex-1 min-w-0 flex flex-col">
        {/* Header */}
        <header className="h-16 px-6 border-b border-purple-800/30 bg-slate-900/60 backdrop-blur-xl flex items-center justify-between">
          {/* Left */}
          <div>
            <h1 className="text-lg font-semibold text-indigo-200">
              {currentPage}
            </h1>
            <p className="text-xs text-gray-400">
              Automated API Vulnerability Scanner
            </p>
          </div>

          {/* Right */}
          <div className="flex items-center gap-3">
            {/* Search */}
            <div className="hidden md:flex items-center gap-2 px-3 h-10 rounded-xl bg-slate-800/70 border border-slate-700">
              <Search size={16} className="text-gray-400" />
              <input
                placeholder="Search..."
                className="bg-transparent outline-none text-sm w-40 placeholder:text-gray-500"
              />
            </div>

            {/* Alerts */}
            <button className="h-10 w-10 rounded-xl bg-slate-800/70 border border-slate-700 flex items-center justify-center hover:bg-slate-700/70 transition relative">
              <Bell size={17} />
              <span className="absolute top-2 right-2 h-2 w-2 rounded-full bg-red-500"></span>
            </button>

            {/* Status */}
            <div className="hidden sm:flex px-3 h-10 items-center rounded-xl bg-emerald-500/10 border border-emerald-500/20 text-emerald-300 text-sm">
              All Systems Operational
            </div>
          </div>
        </header>

        {/* Content */}
        <main className="flex-1 overflow-y-auto p-6">
          <div className="rounded-2xl border border-white/5 bg-white/[0.02] min-h-full p-5">
            {children}
          </div>
        </main>
      </div>
    </div>
  )
}