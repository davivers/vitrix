import { useQuery } from "@tanstack/react-query";
import { useEffect, useRef } from "react";
import clsx from "clsx";
import {
  Activity,
  FlaskConical,
  Gauge,
  Grid3x3,
  Info,
  Library,
  PackageOpen,
  Plug,
  Regex,
  Settings,
  SquarePen,
  UserCheck,
  Users,
  type LucideIcon,
} from "lucide-react";
import { NavLink, Navigate, Route, Routes } from "react-router-dom";
import { DEMO, api } from "./api";
import { useMe } from "./components/auth";
import { Logo, LogoMark } from "./components/Logo";
import { SyncChip } from "./components/SyncChip";
import { Toaster, toast } from "./components/Toast";
import { UserMenu } from "./components/UserMenu";
import ConnectionsPage from "./pages/Connections";
import CoveragePage from "./pages/Coverage";
import DashboardPage from "./pages/Dashboard";
import EditorPage from "./pages/Editor";
import PacksPage from "./pages/Packs";
import ReviewsPage from "./pages/Reviews";
import ReviewPage from "./pages/ReviewPage";
import ExecutivePage from "./pages/Executive";
import RegexLabPage from "./pages/RegexLab";
import RulesPage from "./pages/Rules";
import SettingsPage from "./pages/Settings";
import TeamPage from "./pages/Team";
import TestSuitesPage from "./pages/TestSuites";
import { t } from "./i18n";

const REVIEWS = "/reviews";

interface NavItem {
  to: string;
  label: string;
  Icon: LucideIcon;
}

// Agrupado pelo fluxo: escrever → validar/testar/replay/analisar → gate → acompanhar.
const NAV: { title: string; items: NavItem[] }[] = [
  {
    title: t("l_overview"),
    items: [
      { to: "/dashboard", label: t("l_operational"), Icon: Activity },
      { to: "/executive", label: t("l_executive"), Icon: Gauge },
    ],
  },
  {
    title: t("l_detections"),
    items: [
      { to: "/rules", label: t("l_rules"), Icon: Library },
      { to: "/editor", label: t("l_editor"), Icon: SquarePen },
      { to: "/reviews", label: t("rv_my_reviews"), Icon: UserCheck },
      { to: "/packs", label: t("pk_title"), Icon: PackageOpen },
      { to: "/regex", label: t("l_regex_workbench"), Icon: Regex },
    ],
  },
  {
    title: t("l_validation_group"),
    items: [
      { to: "/tests", label: t("l_test_suites"), Icon: FlaskConical },
      { to: "/coverage", label: t("l_mitre_coverage"), Icon: Grid3x3 },
    ],
  },
  {
    title: t("l_system"),
    items: [
      { to: "/team", label: t("l_team"), Icon: Users },
      { to: "/connections", label: t("l_connections"), Icon: Plug },
      { to: "/settings", label: t("l_settings"), Icon: Settings },
    ],
  },
];

/** Sidebar: labels from lg up, icons only below (the label stays as title/screen-reader text). */
function Sidebar() {
  const me = useMe();
  const health = useQuery({ queryKey: ["health"], queryFn: api.health });
  // Reviews need accounts: no item (and no polling) otherwise; the badge is the number waiting for me.
  const counts = useQuery({
    queryKey: ["review-counts"],
    queryFn: api.reviewCounts,
    enabled: me.enabled && !DEMO,
    // 30 s while the tab is visible (immediately on focus via refetchOnWindowFocus), paused when hidden.
    refetchInterval: () => (document.visibilityState === "visible" ? 30_000 : false),
    refetchOnWindowFocus: true,
    retry: false,
  });
  const toReview = counts.data?.enabled ? (counts.data.unread ?? counts.data.to_review) : 0;
  const lastUnread = useRef<number | null>(null);
  useEffect(() => {
    if (!counts.data?.enabled) return;
    const n = counts.data.unread ?? counts.data.to_review;
    if (lastUnread.current !== null && n > lastUnread.current) {
      const first = counts.data.latest?.[0];
      toast(n - lastUnread.current === 1 && first ? t("rv_toast_one", { title: first.title, who: first.requester ?? "" }) : t("rv_toast_many", { n: n - lastUnread.current }), { to: first && n - lastUnread.current === 1 ? `/reviews/${first.id}` : "/reviews", label: t("rv_toast_view") });
    }
    lastUnread.current = n;
  }, [counts.data]);
  return (
    <aside className="flex w-16 shrink-0 flex-col border-r border-line bg-surface-2 px-2.5 py-5 text-muted lg:w-58 lg:px-3.5">
      <div className="flex justify-center pb-6 lg:justify-start lg:px-2">
        <span className="lg:hidden">
          <LogoMark size={30} />
        </span>
        <span className="hidden lg:block">
          <Logo />
        </span>
      </div>
      <nav className="flex flex-1 flex-col gap-4 overflow-y-auto" aria-label={t("main")}>
        {NAV.map((group) => (
          <div key={group.title} className="flex flex-col gap-1">
            <span className="hidden px-3 pb-0.5 text-[10.5px] font-semibold uppercase tracking-wider text-subtle lg:block">{group.title}</span>
            {group.items.filter(({ to }) => !DEMO || (to !== REVIEWS && to !== "/packs")).map(({ to, label, Icon }) => (
              <NavLink
                key={to}
                to={to}
                title={label}
                className={({ isActive }) =>
                  clsx(
                    "flex items-center justify-center gap-3 rounded-[10px] px-3 py-2 text-[13.5px] font-medium transition-colors lg:justify-start",
                    isActive ? "border-l-2 border-accent bg-accent-soft font-semibold text-accent" : "border-l-2 border-transparent hover:bg-surface-3 hover:text-text",
                  )
                }
              >
                <Icon size={18} className="shrink-0" aria-hidden />
                <span className="sr-only lg:not-sr-only">{label}</span>
                {to === REVIEWS && toReview > 0 && (
                  <span className="ml-auto rounded-full bg-accent px-1.5 text-[11px] font-semibold tabular-nums text-on-brand" aria-label={t("rv_badge", { n: toReview })}>
                    {toReview}
                  </span>
                )}
              </NavLink>
            ))}
          </div>
        ))}
      </nav>
      <SyncChip />
      <UserMenu />
      <p className="mt-2 hidden px-2 text-[11px] text-subtle lg:block">{health.data ? `Vitrix v${health.data.version}` : "Vitrix"}</p>
    </aside>
  );
}

/** Static demo (ADR 0003): says up front that nothing here is saved. */
function DemoBanner() {
  return (
    <div role="status" className="sticky top-0 z-20 flex flex-wrap items-center gap-x-2 border-b border-line bg-accent-soft px-4 py-2 text-[13px] text-strong">
      <Info size={15} className="shrink-0 text-accent" aria-hidden />
      <span>{t("demo_banner")}</span>
      <a href="https://github.com/davivers/vitrix#quickstart" target="_blank" rel="noreferrer" className="font-semibold text-accent hover:underline">
        {t("demo_banner_link")}
      </a>
    </div>
  );
}

/** Print always uses the light theme (exports spec), whatever the screen theme is. */
function usePrintLight() {
  useEffect(() => {
    let prev: string | null = null;
    const before = () => {
      prev = document.documentElement.getAttribute("data-theme");
      document.documentElement.setAttribute("data-theme", "light");
    };
    const after = () => prev !== null && document.documentElement.setAttribute("data-theme", prev);
    window.addEventListener("beforeprint", before);
    window.addEventListener("afterprint", after);
    return () => {
      window.removeEventListener("beforeprint", before);
      window.removeEventListener("afterprint", after);
    };
  }, []);
}

export default function App() {
  usePrintLight();
  return (
    <div className="flex h-full">
      <Toaster />
      <Sidebar />
      <main className="min-w-0 flex-1 overflow-auto">
        {DEMO && <DemoBanner />}
        <Routes>
          <Route path="/" element={<Navigate to="/dashboard" replace />} />
          <Route path="/dashboard" element={<DashboardPage />} />
          <Route path="/executive" element={<ExecutivePage />} />
          <Route path="/rules" element={<RulesPage />} />
          <Route path="/editor" element={<EditorPage />} />
          <Route path="/editor/*" element={<EditorPage />} />
          <Route path="/reviews" element={<ReviewsPage />} />
          <Route path="/reviews/:id" element={<ReviewPage />} />
          <Route path="/packs" element={<PacksPage />} />
          <Route path="/regex" element={<RegexLabPage />} />
          <Route path="/tests" element={<TestSuitesPage />} />
          <Route path="/replay" element={<Navigate to="/editor" replace />} />
          <Route path="/coverage" element={<CoveragePage />} />
          <Route path="/gate" element={<Navigate to="/rules?view=gate" replace />} />
          <Route path="/reports" element={<Navigate to="/executive" replace />} />
          <Route path="/connections" element={<ConnectionsPage />} />
          <Route path="/settings" element={<SettingsPage />} />
          <Route path="/team" element={<TeamPage />} />
          <Route path="*" element={<Navigate to="/dashboard" replace />} />
        </Routes>
      </main>
    </div>
  );
}
