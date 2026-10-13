import { useEffect, useState } from "react";

export type Page = "overview" | "ingestion" | "analytics" | "extraction" | "graphrag";
export const PAGES: Page[] = ["overview", "ingestion", "analytics", "extraction", "graphrag"];

function parse(): Page {
  const path = window.location.hash.replace(/^#\/?/, "").split("?")[0];
  return (PAGES as string[]).includes(path) ? (path as Page) : "overview";
}

/** Hash routing, so the open tab survives a refresh. */
export function usePage(): Page {
  const [page, setPage] = useState(parse);
  useEffect(() => {
    const onChange = () => setPage(parse());
    window.addEventListener("hashchange", onChange);
    return () => window.removeEventListener("hashchange", onChange);
  }, []);
  return page;
}

export const href = (page: Page) => `#/${page}`;
