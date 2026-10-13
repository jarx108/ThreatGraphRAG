import type { ReactNode } from "react";
import { DatabaseIcon, ExtractionIcon, GraphIcon, HomeIcon, SparkIcon } from "./components/Icons";
import type { Page } from "./router";

// The five tabs: an introduction plus one per rubric pillar.
export const TABS: { page: Page; label: string; short: string; icon: ReactNode; color: string }[] = [
  { page: "overview", label: "Introduction", short: "Intro", icon: <HomeIcon size={16} />, color: "#2fd7c3" },
  { page: "ingestion", label: "Schema & Ingestion", short: "Ingestion", icon: <DatabaseIcon size={16} />, color: "#60a5fa" },
  { page: "analytics", label: "Graph Analytics", short: "Analytics", icon: <GraphIcon size={16} />, color: "#a78bfa" },
  { page: "extraction", label: "Extraction & NED", short: "Extraction", icon: <ExtractionIcon size={16} />, color: "#fbbf24" },
  { page: "graphrag", label: "GraphRAG", short: "GraphRAG", icon: <SparkIcon size={16} />, color: "#f472b6" },
];
