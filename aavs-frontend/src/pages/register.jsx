import { useState } from "react";
import { Eye, EyeOff, Mail, Lock, ShieldCheck, User, Phone, ArrowRight, CheckCircle2 } from "lucide-react";
import { motion } from "framer-motion";

export default function Register() {
  const [form, setForm] = useState({
    name: "",
    email: "",
    phone: "",
    password: "",
    confirmPassword: "",
    agree: false
  });

  const [showPassword, setShowPassword] = useState(false);
  const [showConfirm, setShowConfirm] = useState(false);
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");

  const update = (key, value) =>
    setForm((prev) => ({ ...prev, [key]: value }));

  const strength = [
    form.password.length > 5,
    /[A-Z]/.test(form.password),
    /\d/.test(form.password)
  ].filter(Boolean).length;

  const handleSubmit = async (e) => {
    e.preventDefault();

    setMessage("");
    setError("");

    if (!form.agree) {
      setError("You must agree to the terms.");
      return;
    }

    if (form.password !== form.confirmPassword) {
      setError("Passwords do not match.");
      return;
    }

    try {
      setLoading(true);

      const res = await fetch("http://127.0.0.1:5000/register", {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          full_name: form.name,
          email: form.email,
          phone: form.phone,
          password: form.password
        })
      });

      const data = await res.json();

      if (!res.ok) {
        throw new Error(data.message || "Registration failed");
      }

      setMessage("Account created successfully");

      setForm({
        name: "",
        email: "",
        phone: "",
        password: "",
        confirmPassword: "",
        agree: false
      });

    } catch (err) {
      setError(err.message || "Something went wrong");
    } finally {
      setLoading(false);
    }
  };

  const inputClass =
    "w-full pl-10 pr-4 py-3 rounded-xl bg-slate-900/70 border border-white/10 focus:outline-none focus:ring-2 text-sm transition";

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-slate-950 via-indigo-950 to-purple-950 px-4 py-10 relative overflow-hidden text-white">
      <div className="absolute top-8 left-8 w-44 h-44 bg-purple-700/20 blur-3xl rounded-full" />
      <div className="absolute bottom-8 right-8 w-56 h-56 bg-indigo-700/20 blur-3xl rounded-full" />

      <motion.div
        initial={{ opacity: 0, y: 30 }}
        animate={{ opacity: 1, y: 0 }}
        className="relative w-full max-w-lg bg-white/10 backdrop-blur-2xl border border-white/10 rounded-3xl shadow-2xl p-8"
      >
        <div className="text-center mb-8">
          <div className="w-16 h-16 mx-auto rounded-2xl bg-gradient-to-r from-indigo-500 to-purple-600 flex items-center justify-center shadow-lg mb-4">
            <ShieldCheck size={28} />
          </div>
          <h1 className="text-3xl font-bold">Create Account</h1>
          <p className="text-sm text-gray-300 mt-2">Another form for the humans.</p>
        </div>

        <form onSubmit={handleSubmit} className="space-y-5">

          {message && (
            <div className="p-3 rounded-lg bg-green-500/20 text-green-300 text-sm">
              {message}
            </div>
          )}

          {error && (
            <div className="p-3 rounded-lg bg-red-500/20 text-red-300 text-sm">
              {error}
            </div>
          )}

          <div className="grid sm:grid-cols-2 gap-4">
            <div className="relative">
              <User size={18} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400" />
              <input
                className={inputClass}
                placeholder="Full Name"
                value={form.name}
                onChange={(e) => update("name", e.target.value)}
              />
            </div>
            <div className="relative">
              <Phone size={18} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400" />
              <input
                className={inputClass}
                placeholder="Phone Number"
                value={form.phone}
                onChange={(e) => update("phone", e.target.value)}
              />
            </div>
          </div>

          <div className="relative">
            <Mail size={18} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400" />
            <input
              type="email"
              className={inputClass}
              placeholder="you@example.com"
              value={form.email}
              onChange={(e) => update("email", e.target.value)}
            />
          </div>

          <div className="grid sm:grid-cols-2 gap-4">
            <div className="relative">
              <Lock size={18} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400" />
              <input
                type={showPassword ? "text" : "password"}
                className={inputClass}
                placeholder="Password"
                value={form.password}
                onChange={(e) => update("password", e.target.value)}
              />
              <button type="button" className="absolute right-3 top-1/2 -translate-y-1/2" onClick={() => setShowPassword(!showPassword)}>
                {showPassword ? <EyeOff size={18} /> : <Eye size={18} />}
              </button>
            </div>

            <div className="relative">
              <Lock size={18} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400" />
              <input
                type={showConfirm ? "text" : "password"}
                className={inputClass}
                placeholder="Confirm Password"
                value={form.confirmPassword}
                onChange={(e) => update("confirmPassword", e.target.value)}
              />
              <button type="button" className="absolute right-3 top-1/2 -translate-y-1/2" onClick={() => setShowConfirm(!showConfirm)}>
                {showConfirm ? <EyeOff size={18} /> : <Eye size={18} />}
              </button>
            </div>
          </div>

          <div className="h-2 rounded-full bg-white/10 overflow-hidden">
            <div
              className="h-full bg-gradient-to-r from-indigo-500 to-purple-500"
              style={{ width: `${(strength / 3) * 100}%` }}
            />
          </div>

          <label className="flex gap-2 text-sm text-gray-300">
            <input
              type="checkbox"
              checked={form.agree}
              onChange={(e) => update("agree", e.target.checked)}
            />
            I agree to the Terms.
          </label>

          <button
            disabled={loading}
            className="w-full py-3 rounded-xl bg-gradient-to-r from-indigo-600 to-purple-600 font-semibold flex items-center justify-center gap-2"
          >
            {loading ? "Creating..." : <>Create Account <ArrowRight size={18} /></>}
          </button>
        </form>

        <div className="mt-6 p-4 rounded-2xl bg-white/5 border border-white/10 text-sm text-gray-300 flex gap-3">
          <CheckCircle2 size={18} className="text-green-400" />
          Secure enough to calm nervous users.
        </div>
      </motion.div>
    </div>
  );
}