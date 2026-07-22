import { NavLink, Navigate, Route, Routes } from "react-router-dom";
import Dashboard from "./pages/Dashboard";
import Devices from "./pages/Devices";
import DeviceDetail from "./pages/DeviceDetail";
import Scans from "./pages/Scans";
import Alerts from "./pages/Alerts";
import SettingsPage from "./pages/Settings";

const navItems = [
  { to: "/", label: "Devices", end: true },
  { to: "/dashboard", label: "Dashboard" },
  { to: "/scans", label: "Scans" },
  { to: "/alerts", label: "Alerts" },
  { to: "/settings", label: "Settings" },
];

export default function App() {
  return (
    <div className="min-h-screen">
      <header className="border-b border-slate-200 bg-white">
        <div className="mx-auto flex max-w-6xl items-center justify-between px-6 py-3">
          <div className="flex items-center gap-2">
            <span className="inline-block h-6 w-6 rounded bg-brand-600" />
            <span className="text-lg font-semibold">Lighthouse</span>
            <span className="ml-2 text-xs text-slate-500">local network visibility</span>
          </div>
          <nav className="flex gap-1">
            {navItems.map((n) => (
              <NavLink
                key={n.to}
                to={n.to}
                end={n.end}
                className={({ isActive }) =>
                  `rounded-md px-3 py-1.5 text-sm font-medium ${
                    isActive ? "bg-brand-50 text-brand-700" : "text-slate-600 hover:bg-slate-100"
                  }`
                }
              >
                {n.label}
              </NavLink>
            ))}
          </nav>
        </div>
      </header>
      <main className="mx-auto max-w-6xl px-6 py-6">
        <Routes>
          <Route path="/" element={<Devices />} />
          <Route path="/dashboard" element={<Dashboard />} />
          <Route path="/devices" element={<Navigate to="/" replace />} />
          <Route path="/devices/:id" element={<DeviceDetail />} />
          <Route path="/scans" element={<Scans />} />
          <Route path="/alerts" element={<Alerts />} />
          <Route path="/settings" element={<SettingsPage />} />
        </Routes>
      </main>
    </div>
  );
}
