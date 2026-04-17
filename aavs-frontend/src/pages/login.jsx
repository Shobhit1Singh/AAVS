import { useState } from "react"

export default function Login() {
  const [email, setEmail] = useState("")
  const [password, setPassword] = useState("")

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-slate-950 via-indigo-950 to-purple-950 text-gray-200">

      <div className="w-full max-w-md bg-slate-900/80 backdrop-blur border border-purple-800/40 rounded-xl shadow-lg p-8">

        <h2 className="text-2xl font-semibold text-purple-400 text-center mb-6 tracking-wide">
          AAVS Login
        </h2>

        <form className="space-y-5">

          <div>
            <label className="text-sm text-indigo-300 block mb-1">
              Email
            </label>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="w-full px-3 py-2 rounded-lg bg-slate-800 border border-purple-800/40 focus:outline-none focus:ring-2 focus:ring-indigo-500 text-sm"
              placeholder="you@example.com"
            />
          </div>

          <div>
            <label className="text-sm text-indigo-300 block mb-1">
              Password
            </label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full px-3 py-2 rounded-lg bg-slate-800 border border-purple-800/40 focus:outline-none focus:ring-2 focus:ring-purple-500 text-sm"
              placeholder="••••••••"
            />
          </div>

          <button
            type="submit"
            className="w-full py-2.5 rounded-lg bg-gradient-to-r from-indigo-600 to-purple-600 hover:from-indigo-500 hover:to-purple-500 transition text-sm font-medium"
          >
            Login
          </button>

        </form>

        <p className="text-xs text-gray-400 text-center mt-6">
          Secure access to your scan dashboard
        </p>

      </div>

    </div>
  )
}