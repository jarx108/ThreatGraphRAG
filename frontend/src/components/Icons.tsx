type P = { size?: number };

const base = (size = 18) => ({
  width: size, height: size, viewBox: "0 0 24 24", fill: "none", stroke: "currentColor",
  strokeWidth: 1.8, strokeLinecap: "round" as const, strokeLinejoin: "round" as const,
});

export const LogoMark = ({ size = 22 }: P) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none">
    <path d="M6 7l6-3 6 3M6 7v6l6 4 6-4V7M6 7l6 4 6-4M12 11v6" stroke="#2fd7c3" strokeWidth="1.6" strokeLinejoin="round" />
    <circle cx="12" cy="4" r="1.8" fill="#2fd7c3" />
    <circle cx="6" cy="7" r="1.8" fill="#8f9dff" />
    <circle cx="18" cy="7" r="1.8" fill="#8f9dff" />
    <circle cx="12" cy="11" r="1.8" fill="#e8ecf4" />
    <circle cx="12" cy="17" r="1.8" fill="#2fd7c3" />
  </svg>
);

export const AskIcon = ({ size }: P) => (
  <svg {...base(size)}><path d="M21 12a8 8 0 0 1-11.8 7L4 20l1.1-4.6A8 8 0 1 1 21 12z" /><path d="M9.5 9.5a2.5 2.5 0 0 1 4.9.7c0 1.7-2.4 2-2.4 3.3M12 16.5h.01" /></svg>
);
export const BenchmarkIcon = ({ size }: P) => (
  <svg {...base(size)}><path d="M4 20V10M10 20V4M16 20v-7M22 20H2" /></svg>
);
export const ExtractionIcon = ({ size }: P) => (
  <svg {...base(size)}><circle cx="5" cy="6" r="2" /><circle cx="19" cy="6" r="2" /><circle cx="12" cy="18" r="2" /><path d="M7 6h10M6 8l5 8.3M18 8l-5 8.3" /></svg>
);
export const HistoryIcon = ({ size }: P) => (
  <svg {...base(size)}><path d="M3 12a9 9 0 1 0 3-6.7L3 8" /><path d="M3 3v5h5M12 7v5l3 2" /></svg>
);
export const SparkIcon = ({ size }: P) => (
  <svg {...base(size)}><path d="M12 3l1.9 5.1L19 10l-5.1 1.9L12 17l-1.9-5.1L5 10l5.1-1.9z" /></svg>
);
export const PlayIcon = ({ size }: P) => (
  <svg {...base(size)}><path d="M7 4.5v15l12-7.5z" fill="currentColor" stroke="none" /></svg>
);
export const ArrowIcon = ({ size = 14 }: P) => (
  <svg {...base(size)}><path d="M5 12h14M13 6l6 6-6 6" /></svg>
);
export const CheckIcon = ({ size = 14 }: P) => (
  <svg {...base(size)}><path d="M5 12.5l4.5 4.5L19 7.5" /></svg>
);
export const HomeIcon = ({ size }: P) => (
  <svg {...base(size)}><path d="M3 11l9-7 9 7" /><path d="M5 10v10h14V10" /><path d="M10 20v-6h4v6" /></svg>
);
export const DatabaseIcon = ({ size }: P) => (
  <svg {...base(size)}><ellipse cx="12" cy="5" rx="8" ry="3" /><path d="M4 5v6c0 1.7 3.6 3 8 3s8-1.3 8-3V5" /><path d="M4 11v6c0 1.7 3.6 3 8 3s8-1.3 8-3v-6" /></svg>
);
export const GraphIcon = ({ size }: P) => (
  <svg {...base(size)}><circle cx="6" cy="6" r="2.2" /><circle cx="18" cy="7" r="2.2" /><circle cx="8" cy="18" r="2.2" /><circle cx="17" cy="17" r="2.2" /><path d="M8 7l8 0.5M7 8l1 8M10 18h5M17.5 9.2l-.3 5.6M7.6 7.6l7.8 7.8" /></svg>
);
export const LinkIcon = ({ size }: P) => (
  <svg {...base(size)}><path d="M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1" /><path d="M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1" /></svg>
);
