import { useEffect, useMemo, useRef, useState } from "react";
import { CATEGORY_LABEL } from "../format";
import type { BenchmarkQuestion } from "../types";

const norm = (s: string) => s.trim().toLowerCase().replace(/[?.!\s]+$/, "");

/** The question box: free text, with benchmark questions (each has a verified
 *  reference answer) suggested underneath while typing or on focus. */
export function QuestionInput({ questions, value, onChange, onSubmit, placeholder }: {
  questions: BenchmarkQuestion[];
  value: string;
  onChange: (q: string) => void;
  onSubmit: () => void;
  placeholder?: string;
}) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const close = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", close);
    return () => document.removeEventListener("mousedown", close);
  }, []);

  const filtered = useMemo(() => {
    const q = norm(value);
    if (questions.some((x) => norm(x.question) === q)) return [];   // already a benchmark question
    const words = q.split(/\s+/).filter(Boolean);
    return questions.filter((x) => {
      const hay = `${x.id} ${x.question}`.toLowerCase();
      return words.every((w) => hay.includes(w));
    });
  }, [questions, value]);

  return (
    <div className="combo" ref={ref}>
      <textarea
        value={value}
        onFocus={() => setOpen(true)}
        onChange={(e) => { onChange(e.target.value); setOpen(true); }}
        onKeyDown={(e) => {
          if (e.key === "Escape") setOpen(false);
          if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) { setOpen(false); onSubmit(); }
        }}
        placeholder={placeholder}
      />
      {open && filtered.length > 0 && (
        <div className="combo-list">
          <div className="muted" style={{ padding: "8px 10px 4px", fontSize: 12 }}>
            Benchmark questions with verified answers ({filtered.length})
          </div>
          {filtered.map((q) => (
            <div key={q.id} className="combo-item" onMouseDown={(e) => e.preventDefault()}
              onClick={() => { onChange(q.question); setOpen(false); }}>
              <span className="chip">{q.id}</span>
              <div>
                <div className="q">{q.question}</div>
                <div className="muted">{q.required_hops}-hop · {CATEGORY_LABEL[q.category ?? ""] ?? q.category}</div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
