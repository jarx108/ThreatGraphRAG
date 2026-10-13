import { useEffect, useState, type CSSProperties } from "react";
import { api } from "./api";
import { Backdrop } from "./components/Backdrop";
import { LogoMark } from "./components/Icons";
import { AnalyticsPage } from "./pages/AnalyticsPage";
import { ExtractionNedPage } from "./pages/ExtractionNedPage";
import { GraphRagPage } from "./pages/GraphRagPage";
import { IngestionPage } from "./pages/IngestionPage";
import { OverviewPage } from "./pages/OverviewPage";
import { href, usePage } from "./router";
import { TABS } from "./tabs";
import type { Overview } from "./types";



export function App() {
  const page = usePage();
  const [overview, setOverview] = useState<Overview | null>(null);
  const [offline, setOffline] = useState(false);
  const [motion, setMotion] = useState(() => {
    try { return localStorage.getItem("threatgraph.motion") !== "off"; } catch { return true; }
  });

  useEffect(() => {
    api.overview().then(setOverview).catch(() => setOffline(true));
  }, []);

  function toggleMotion() {
    const next = !motion;
    setMotion(next);
    try { localStorage.setItem("threatgraph.motion", next ? "on" : "off"); } catch { /* storage unavailable */ }
  }

  const tab = TABS.find((t) => t.page === page)!;
  return (
    <div className="app" style={{ "--tab": tab.color } as CSSProperties}>
      <Backdrop paused={!motion} />
      <header className="topbar">
        <div className="brand">
          <div className="brand-mark"><LogoMark /></div>
          <div>
            <div className="brand-name">ThreatGraph</div>
            <div className="brand-sub">Knowledge graph + LLM for cyber threat intelligence</div>
          </div>
        </div>
        <div className="top-status">
          <span><span className={`dot ${overview ? "ok" : "off"}`} />{overview ? "Neo4j connected" : offline ? "API offline" : "…"}</span>
          {overview && <span className="chip">{overview.llm.provider} · {overview.llm.model}</span>}
          <button className={`mini-switch${motion ? " on" : ""}`} onClick={toggleMotion}
            title="Pause the animated background (useful for screenshots)" aria-pressed={motion}><span /></button>
        </div>
      </header>

      <nav className="tabs">
        {TABS.map((t, i) => (
          <a key={t.page} href={href(t.page)} className={t.page === page ? "active" : ""}
            style={{ "--c": t.color } as CSSProperties}>
            <span className="tab-ico">{t.icon}</span>
            <span className="tab-label"><span className="tab-num">{i}</span>{t.label}</span>
            <span className="tab-short">{t.short}</span>
          </a>
        ))}
      </nav>

      <main className="page">
        {offline && (
          <div className="notice bad" style={{ marginBottom: 20 }}>
            Cannot reach the ThreatGraph API. Start it with <code>make app</code>.
          </div>
        )}
        {page === "overview" && <OverviewPage data={overview} />}
        {page === "ingestion" && <IngestionPage />}
        {page === "analytics" && <AnalyticsPage />}
        {page === "extraction" && <ExtractionNedPage />}
        {page === "graphrag" && <GraphRagPage />}
      </main>
    </div>
  );
}
