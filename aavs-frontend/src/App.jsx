import { BrowserRouter, Routes, Route } from "react-router-dom"
import MainLayout from "./layouts/MainLayout"
import Dashboard from "./pages/Dashboard"
import NewScan from "./pages/NewScans"
import ActiveScans from "./pages/ActiveScans"
import Results from "./pages/Results"
export default function App(){
  return (
    <BrowserRouter>
      <MainLayout>
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/scan" element={<NewScan />} />
          <Route path="/activescan" element={<ActiveScans />} />
          <Route path="/results" element={<Results />} />

        </Routes>
      </MainLayout>
    </BrowserRouter>
  )
}