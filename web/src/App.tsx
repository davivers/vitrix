import { useQuery } from "@tanstack/react-query";
import clsx from "clsx";
import {
  Activity,
  FileBarChart,
  FlaskConical,
  Gauge,
  Grid3x3,
  Library,

  Plug,
  Regex,
  Settings,
  ShieldCheck,
  SquarePen,
  Undo2,
  type LucideIcon,
} from "lucide-react";
import { NavLink, Navigate, Route, Routes } from "react-router-dom";
import { Logo, LogoMark } from "./components/Logo";
import ConnectionsPage from "./pages/Connections";
import CoveragePage from "./pages/Coverage";
import DashboardPage from "./pages/Dashboard";
import EditorPage from "./pages/Editor";
import ExecutivePage from "./pages/Executive";
import QualityGatePage from "./pages/QualityGate";
import RegexLabPage from "./pages/RegexLab";
import ReplayPage from "./pages/Replay";
import ReportsPage from "./pages/Reports";
import RulesPage from "./pages/Rules";
import SettingsPage from "./pages/Settings";
import TestSuitesPage from "./pages/TestSuites";

interface NavItem {
  to: string;
  label: string;
  Icon: LucideIcon;
}

// Agrupado pelo fluxo: escrever → validar/testar/replay/analisar → gate → acompanhar.
const NAV: { title: string; items: NavItem[] }[] = [
  {
    title: "Visão",
    items: [
      { to: "/dashboard", label: "Operacional", Icon: Activity },
      { to: "/executive", label: "Executivo", Icon: Gauge },
    ],
  },
  {
    title: "Detecções",
    items: [
      { to: "/rules", label: "Regras", Icon: Library },
      { to: "/editor", label: "Editor", Icon: SquarePen },
      { to: "/regex", label: "Regex Workbench", Icon: Regex },
    ],
  },
  {
    title: "Validação",
    items: [
      { to: "/tests", label: "Test Suites", Icon: FlaskConical },
      { to: "/replay", label: "Log Replay", Icon: Undo2 },
      { to: "/coverage", label: "MITRE Coverage", Icon: Grid3x3 },
      { to: "/gate", label: "Quality Gate", Icon: ShieldCheck },
      { to: "/reports", label: "Reports", Icon: FileBarChart },
    ],
  },
  {
    title: "Sistema",
    items: [
      { to: "/connections", label: "Conexões", Icon: Plug },
      { to: "/settings", label: "Configurações", Icon: Settings },
    ],
  },
];

/** Barra lateral: com rótulos a partir de lg, só ícones abaixo disso (rótulo vira title/aria-label). */
function Sidebar() {
  const health = useQuery({ queryKey: ["health"], queryFn: () => fetch("/api/health").then((r) => r.json() as Promise<{ version: string }>) });
  return (
    <aside className="flex w-16 shrink-0 flex-col border-r border-line bg-white/[0.02] px-2.5 py-5 text-muted lg:w-58 lg:px-3.5">
      <div className="flex justify-center pb-6 lg:justify-start lg:px-2">
        <span className="lg:hidden">
          <LogoMark size={30} />
        </span>
        <span className="hidden lg:block">
          <Logo />
        </span>
      </div>
      <nav className="flex flex-1 flex-col gap-4 overflow-y-auto" aria-label="Principal">
        {NAV.map((group) => (
          <div key={group.title} className="flex flex-col gap-1">
            <span className="hidden px-3 pb-0.5 text-[10.5px] font-semibold uppercase tracking-wider text-subtle lg:block">{group.title}</span>
            {group.items.map(({ to, label, Icon }) => (
              <NavLink
                key={to}
                to={to}
                title={label}
                className={({ isActive }) =>
                  clsx(
                    "flex items-center justify-center gap-3 rounded-[10px] px-3 py-2 text-[13.5px] font-medium transition-colors lg:justify-start",
                    isActive ? "bg-accent-soft text-strong ring-1 ring-accent/30" : "hover:bg-surface hover:text-text",
                  )
                }
              >
                <Icon size={18} className="shrink-0" aria-hidden />
                <span className="sr-only lg:not-sr-only">{label}</span>
              </NavLink>
            ))}
          </div>
        ))}
      </nav>
      <p className="hidden px-2 text-xs text-subtle lg:block">{health.data ? `v${health.data.version} · local` : "local"}</p>
    </aside>
  );
}

export default function App() {
  return (
    <div className="flex h-full">
      <Sidebar />
      <main className="min-w-0 flex-1 overflow-auto">
        <Routes>
          <Route path="/" element={<Navigate to="/dashboard" replace />} />
          <Route path="/dashboard" element={<DashboardPage />} />
          <Route path="/executive" element={<ExecutivePage />} />
          <Route path="/rules" element={<RulesPage />} />
          <Route path="/editor" element={<EditorPage />} />
          <Route path="/editor/*" element={<EditorPage />} />
          <Route path="/regex" element={<RegexLabPage />} />
          <Route path="/tests" element={<TestSuitesPage />} />
          <Route path="/replay" element={<ReplayPage />} />
          <Route path="/coverage" element={<CoveragePage />} />
          <Route path="/gate" element={<QualityGatePage />} />
          <Route path="/reports" element={<ReportsPage />} />
          <Route path="/connections" element={<ConnectionsPage />} />
          <Route path="/settings" element={<SettingsPage />} />
          <Route path="*" element={<Navigate to="/dashboard" replace />} />
        </Routes>
      </main>
    </div>
  );
}
