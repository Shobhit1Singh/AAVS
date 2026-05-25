import { BrowserRouter, Routes, Route } from "react-router-dom"
import MainLayout from "./layouts/MainLayout"
import Dashboard from "./pages/Dashboard"
import NewScan from "./pages/NewScans"
import ActiveScans from "./pages/ActiveScans"
import Results from "./pages/Results"
import VulnerabilityDetails from "./pages/VulnerabilityDetails"
import AISolutionPage from "./pages/solutions"
import Login from "./pages/login"
import SettingsPage from "./pages/settings"
import Register from "./pages/register"
export default function App(){
  return (
    <BrowserRouter>
      <MainLayout>
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/scan" element={<NewScan />} />
          <Route path="/activescan" element={<ActiveScans />} />
          <Route path="/results" element={<Results />} />
          <Route path="/details" element={<VulnerabilityDetails />} />
          <Route path="/solutions" element={<AISolutionPage />} />
          <Route path="/login" element={<Login />} />
          <Route path="/setting" element={<SettingsPage />} />
          <Route path="/register" element={<Register />} />
        </Routes>
      </MainLayout>
    </BrowserRouter>
  )
}