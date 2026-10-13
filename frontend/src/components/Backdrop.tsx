import { useEffect, useRef } from "react";

// Animated page background: slow aurora glows plus a drifting "threat graph"
// (nodes linked when close, with packets travelling along some links).
// Purely decorative; `paused` freezes it (e.g. for paper screenshots) and
// prefers-reduced-motion always renders a single still frame.

const COLORS = ["#2fd7c3", "#a78bfa", "#60a5fa", "#f472b6", "#fbbf24", "#8f9dff"];
const LINK_DIST = 150;

interface Node { x: number; y: number; vx: number; vy: number; r: number; c: string; phase: number }
interface Packet { a: number; b: number; t: number; speed: number }

export function Backdrop({ paused }: { paused: boolean }) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const pausedRef = useRef(paused);
  pausedRef.current = paused;

  useEffect(() => {
    const canvas = canvasRef.current;
    const ctx = canvas?.getContext("2d");
    if (!canvas || !ctx) return;

    const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    let w = 0, h = 0, raf = 0;
    let nodes: Node[] = [];
    let packets: Packet[] = [];
    const mouse = { x: -1e4, y: -1e4 };

    function seed() {
      w = window.innerWidth; h = window.innerHeight;
      canvas!.width = w * dpr; canvas!.height = h * dpr;
      canvas!.style.width = `${w}px`; canvas!.style.height = `${h}px`;
      ctx!.setTransform(dpr, 0, 0, dpr, 0, 0);
      const count = Math.round(Math.min(110, Math.max(40, (w * h) / 16000)));
      nodes = Array.from({ length: count }, () => ({
        x: Math.random() * w, y: Math.random() * h,
        vx: (Math.random() - 0.5) * 0.25, vy: (Math.random() - 0.5) * 0.25,
        r: 1.2 + Math.random() * 2.2,
        c: COLORS[Math.floor(Math.random() * COLORS.length)],
        phase: Math.random() * Math.PI * 2,
      }));
      packets = [];
    }

    function frame(time: number) {
      const moving = !pausedRef.current && !reduced;
      ctx!.clearRect(0, 0, w, h);

      if (moving) {
        for (const n of nodes) {
          n.x += n.vx; n.y += n.vy;
          if (n.x < -20) n.x = w + 20; else if (n.x > w + 20) n.x = -20;
          if (n.y < -20) n.y = h + 20; else if (n.y > h + 20) n.y = -20;
          // Gentle pull towards the cursor.
          const dx = mouse.x - n.x, dy = mouse.y - n.y, d2 = dx * dx + dy * dy;
          if (d2 < 220 * 220 && d2 > 1) { n.x += dx * 0.0025; n.y += dy * 0.0025; }
        }
      }

      // Links.
      const links: [number, number][] = [];
      for (let i = 0; i < nodes.length; i++) {
        for (let j = i + 1; j < nodes.length; j++) {
          const a = nodes[i], b = nodes[j];
          const dx = a.x - b.x, dy = a.y - b.y, d = Math.hypot(dx, dy);
          if (d > LINK_DIST) continue;
          links.push([i, j]);
          const alpha = (1 - d / LINK_DIST) * 0.28;
          const g = ctx!.createLinearGradient(a.x, a.y, b.x, b.y);
          g.addColorStop(0, hexA(a.c, alpha)); g.addColorStop(1, hexA(b.c, alpha));
          ctx!.strokeStyle = g; ctx!.lineWidth = 0.8;
          ctx!.beginPath(); ctx!.moveTo(a.x, a.y); ctx!.lineTo(b.x, b.y); ctx!.stroke();
        }
      }
      // Cursor links.
      for (const n of nodes) {
        const d = Math.hypot(mouse.x - n.x, mouse.y - n.y);
        if (d < 180) {
          ctx!.strokeStyle = hexA(n.c, (1 - d / 180) * 0.45); ctx!.lineWidth = 1;
          ctx!.beginPath(); ctx!.moveTo(n.x, n.y); ctx!.lineTo(mouse.x, mouse.y); ctx!.stroke();
        }
      }

      // Packets: bright dots travelling along existing links (multi-hop vibes).
      if (moving && links.length && packets.length < 14 && Math.random() < 0.06) {
        const [a, b] = links[Math.floor(Math.random() * links.length)];
        packets.push({ a, b, t: 0, speed: 0.008 + Math.random() * 0.012 });
      }
      packets = packets.filter((p) => {
        const a = nodes[p.a], b = nodes[p.b];
        if (!a || !b || Math.hypot(a.x - b.x, a.y - b.y) > LINK_DIST * 1.2) return false;
        if (moving) p.t += p.speed;
        if (p.t >= 1) return false;
        const x = a.x + (b.x - a.x) * p.t, y = a.y + (b.y - a.y) * p.t;
        glow(x, y, 2.2, b.c, 0.95);
        return true;
      });

      // Nodes with a soft twinkle.
      for (const n of nodes) {
        const tw = moving ? 0.55 + 0.45 * Math.sin(time / 900 + n.phase) : 0.8;
        glow(n.x, n.y, n.r, n.c, tw);
      }

      if (moving) raf = requestAnimationFrame(frame);
    }

    function glow(x: number, y: number, r: number, c: string, a: number) {
      const g = ctx!.createRadialGradient(x, y, 0, x, y, r * 5);
      g.addColorStop(0, hexA(c, 0.5 * a)); g.addColorStop(1, hexA(c, 0));
      ctx!.fillStyle = g; ctx!.beginPath(); ctx!.arc(x, y, r * 5, 0, Math.PI * 2); ctx!.fill();
      ctx!.fillStyle = hexA(c, Math.min(1, a + 0.15)); ctx!.beginPath(); ctx!.arc(x, y, r, 0, Math.PI * 2); ctx!.fill();
    }

    const start = () => { cancelAnimationFrame(raf); raf = requestAnimationFrame(frame); };
    const onResize = () => { seed(); start(); };
    const onMove = (e: PointerEvent) => { mouse.x = e.clientX; mouse.y = e.clientY; };
    const onLeave = () => { mouse.x = -1e4; mouse.y = -1e4; };
    const onVisibility = () => { if (document.hidden) cancelAnimationFrame(raf); else start(); };

    seed(); start();
    window.addEventListener("resize", onResize);
    window.addEventListener("pointermove", onMove);
    document.addEventListener("pointerleave", onLeave);
    document.addEventListener("visibilitychange", onVisibility);
    // Restart the loop whenever the pause toggle flips.
    const unpause = () => start();
    window.addEventListener("threatgraph:motion", unpause);

    return () => {
      cancelAnimationFrame(raf);
      window.removeEventListener("resize", onResize);
      window.removeEventListener("pointermove", onMove);
      document.removeEventListener("pointerleave", onLeave);
      document.removeEventListener("visibilitychange", onVisibility);
      window.removeEventListener("threatgraph:motion", unpause);
    };
  }, []);

  useEffect(() => { window.dispatchEvent(new Event("threatgraph:motion")); }, [paused]);

  return (
    <div className={`backdrop${paused ? " paused" : ""}`} aria-hidden="true">
      <div className="aurora a1" />
      <div className="aurora a2" />
      <div className="aurora a3" />
      <div className="grid-floor" />
      <canvas ref={canvasRef} />
      <div className="vignette" />
    </div>
  );
}

function hexA(hex: string, a: number): string {
  const n = parseInt(hex.slice(1), 16);
  return `rgba(${(n >> 16) & 255}, ${(n >> 8) & 255}, ${n & 255}, ${Math.max(0, Math.min(1, a))})`;
}
